import Foundation
import CoreGraphics
import SwiftUI
import UniformTypeIdentifiers
import UIKit

func coordinatedFileRead<T>(at url: URL, _ operation: (URL) throws -> T) throws -> T {
    var coordinationError: NSError?
    var result: Result<T, Error>?
    NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { source in
        result = Result { try operation(source) }
    }
    if let error = coordinationError { throw error }
    guard let result = result else { throw CocoaError(.fileReadUnknown) }
    return try result.get()
}

struct LibraryFolder: Codable, Identifiable {
    var id: String
    var bookmark: Data
    var path: String?
}

struct LibraryEntry: Codable, Identifiable {
    var id: String
    var name: String
    var path: String?
    var folder: String?
    var imported: Bool
    var model: String?
    var display: String?
    var chipset: String?
    var sha256: String?
    var size: Int64
    var lastBooted: Date?
    var thumbnail: String?
    var available: Bool

    var displayName: String { display ?? name }
}

private struct LibraryGroup: Identifiable {
    let id: String
    var files: [LibraryEntry]
    var latest: LibraryEntry {
        files.max { ($0.lastBooted ?? .distantPast) < ($1.lastBooted ?? .distantPast) } ?? files[0]
    }
    var sizes: String { files.map { String(format: "%.1f MiB", Double($0.size) / 1048576) }.joined(separator: " / ") }
}

private struct LibraryIndex: Codable {
    var folders: [LibraryFolder] = []
    var entries: [LibraryEntry] = []
    var excluded: [String] = []
}

final class FirmwareLibraryStore: ObservableObject {
    @Published private(set) var entries: [LibraryEntry] = []
    @Published private(set) var scanning = false
    @Published private(set) var importing = false
    @Published private(set) var failedSources: [String] = []
    @Published var error: String?
    private var index = LibraryIndex()
    private var indexReadable = true
    private let scanner = DispatchQueue(label: "firmware.library.scan")
    private var generation = 0
    private let generationLock = NSLock()

    private func nextGeneration() -> Int {
        generationLock.lock()
        defer { generationLock.unlock() }
        generation += 1
        return generation
    }

    private func isCurrent(_ token: Int) -> Bool {
        generationLock.lock()
        defer { generationLock.unlock() }
        return token == generation
    }

    func pauseScanning() {
        _ = nextGeneration()
        scanning = false
    }
    private let support: URL
    private let indexURL: URL
    private let cacheURL: URL
    private let importsURL: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        support = base
        indexURL = base.appendingPathComponent("firmware-library.json")
        cacheURL = base.appendingPathComponent("firmware-library-cache.json")
        importsURL = base.appendingPathComponent("FirmwareLibrary", isDirectory: true)
        _ = loadIndex(allowMissing: true)
    }

    @discardableResult private func loadIndex(allowMissing: Bool = false) -> Bool {
        do {
            let loaded = try JSONDecoder().decode(LibraryIndex.self, from: Data(contentsOf: indexURL))
            index = loaded
            entries = loaded.entries
            indexReadable = true
            return true
        } catch {
            let failure = error as NSError
            if allowMissing && failure.domain == NSCocoaErrorDomain &&
                (failure.code == CocoaError.Code.fileReadNoSuchFile.rawValue || failure.code == CocoaError.Code.fileNoSuchFile.rawValue) {
                return true
            }
            indexReadable = false
            self.error = "Library index unreadable"
            return false
        }
    }

    @discardableResult private func save() -> Bool {
        guard indexReadable else { error = "Library index unreadable"; return false }
        do {
            try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
            try JSONEncoder().encode(index).write(to: indexURL, options: .atomic)
            return true
        } catch { self.error = "Library error"; return false }
    }

    var folders: [LibraryFolder] { index.folders }

    func removeFolder(_ id: String, engine: QEMUEngine) {
        guard indexReadable else { error = "Library index unreadable"; return }
        _ = nextGeneration()
        index.folders.removeAll { $0.id == id }
        index.entries.removeAll { !$0.imported && $0.folder == id }
        save()
        refresh(engine: engine)
    }

    func addFolder(_ url: URL, engine: QEMUEngine) {
        guard indexReadable else { error = "Library index unreadable"; return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let bookmark = try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
            if !index.folders.contains(where: { $0.bookmark == bookmark }) {
                index.folders.append(LibraryFolder(id: UUID().uuidString, bookmark: bookmark, path: url.path))
                save()
            }
            refresh(engine: engine)
        } catch { self.error = "Library error" }
    }

    private func resolveFolder(_ folder: LibraryFolder) throws -> (folder: LibraryFolder, url: URL) {
        var stale = false
        let url = try URL(resolvingBookmarkData: folder.bookmark, options: [], relativeTo: nil, bookmarkDataIsStale: &stale)
        var updated = folder
        if stale {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            updated.bookmark = try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
        }
        updated.path = url.path
        return (updated, url)
    }

    private func folderURL(_ id: String, index: LibraryIndex) -> URL? {
        guard let folder = index.folders.first(where: { $0.id == id }) else { return nil }
        return try? resolveFolder(folder).url
    }

    func sourceDescription(_ entry: LibraryEntry) -> String {
        if let path = entry.path { return path }
        if let id = entry.folder {
            if let folder = folderURL(id, index: index) {
                return folder.appendingPathComponent(entry.name).path
            }
            if let path = index.folders.first(where: { $0.id == id })?.path {
                return URL(fileURLWithPath: path).appendingPathComponent(entry.name).path
            }
        }
        return entry.name
    }

    @discardableResult func withSource(_ entry: LibraryEntry, _ action: (URL, @escaping () -> Void) -> Void) -> Bool {
        if let path = entry.path {
            guard FileManager.default.isReadableFile(atPath: path) else { return false }
            action(URL(fileURLWithPath: path), {})
            return true
        }
        if let id = entry.folder, let position = index.folders.firstIndex(where: { $0.id == id }),
           let resolved = try? resolveFolder(index.folders[position]) {
            if resolved.folder.bookmark != index.folders[position].bookmark || resolved.folder.path != index.folders[position].path {
                index.folders[position] = resolved.folder
                save()
            }
            let folder = resolved.url
            let scoped = folder.startAccessingSecurityScopedResource()
            let file = folder.appendingPathComponent(entry.name)
            action(file, { if scoped { folder.stopAccessingSecurityScopedResource() } })
            return true
        }
        return false
    }

    func importFile(_ url: URL, engine: QEMUEngine, completion: @escaping (Bool) -> Void = { _ in }) {
        guard indexReadable else { error = "Library index unreadable"; completion(false); return }
        guard !importing else { error = "Library import in progress"; completion(false); return }
        _ = nextGeneration()
        scanning = false
        importing = true
        let scoped = url.startAccessingSecurityScopedResource()
        scanner.async {
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let reply = try engine.libraryRequest(["limit_name": url.lastPathComponent])
                guard let limit = (reply["limit"] as? NSNumber)?.int64Value else {
                    throw NSError(domain: "FirmwareLibrary", code: 2)
                }
                let directory = self.importsURL.appendingPathComponent(UUID().uuidString, isDirectory: true)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                let target = directory.appendingPathComponent(url.lastPathComponent)
                do {
                    let byteCount = try coordinatedFileRead(at: url) { source -> Int64 in
                        let input = try FileHandle(forReadingFrom: source)
                        defer { try? input.close() }
                        guard FileManager.default.createFile(atPath: target.path, contents: nil) else {
                            throw CocoaError(.fileWriteUnknown)
                        }
                        let output = try FileHandle(forWritingTo: target)
                        defer { try? output.close() }
                        var total: Int64 = 0
                        while let data = try input.read(upToCount: 65536), !data.isEmpty {
                            total += Int64(data.count)
                            guard total <= limit else { throw NSError(domain: "FirmwareLibrary", code: 3) }
                            try output.write(contentsOf: data)
                        }
                        try output.close()
                        return total
                    }
                    let metadata = try engine.libraryRequest(["path": target.path, "cache": self.cacheURL.path, "name": url.lastPathComponent])
                    let sha = metadata["sha256"] as? String
                    DispatchQueue.main.async {
                        if let sha = sha, self.index.entries.contains(where: { $0.available && $0.sha256 == sha }) {
                            try? FileManager.default.removeItem(at: directory)
                        } else {
                            self.index.entries.append(LibraryEntry(id: UUID().uuidString, name: url.lastPathComponent,
                                path: target.path, folder: nil, imported: true,
                                model: metadata["model"] as? String, display: metadata["name"] as? String,
                                chipset: metadata["chipset"] as? String,
                                sha256: sha, size: byteCount, lastBooted: nil, thumbnail: nil, available: true))
                        }
                        let saved = self.save()
                        self.importing = false
                        completion(saved)
                        self.refresh(engine: engine)
                    }
                } catch {
                    try? FileManager.default.removeItem(at: directory)
                    throw error
                }
            } catch {
                DispatchQueue.main.async {
                    self.importing = false
                    self.error = "Library error"
                    completion(false)
                    self.refresh(engine: engine)
                }
            }
        }
    }

    func refresh(engine: QEMUEngine) {
        guard !importing else { return }
        if !indexReadable {
            guard loadIndex() else { return }
            error = nil
        }
        let token = nextGeneration()
        let original = index
        scanning = true
        scanner.async {
            var updated = original
            var oversized = Set<String>()
            var unreadable = Set<String>()
            for i in updated.entries.indices { updated.entries[i].available = false }
            var failures = Set<String>()
            for folderPosition in updated.folders.indices {
                if !self.isCurrent(token) { return }
                let folder = updated.folders[folderPosition]
                let url: URL
                do {
                    let resolved = try self.resolveFolder(folder)
                    updated.folders[folderPosition] = resolved.folder
                    url = resolved.url
                } catch {
                    failures.insert((folder.path as NSString?)?.lastPathComponent ?? folder.id)
                    continue
                }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                let files: [URL]
                do {
                    files = try coordinatedFileRead(at: url) { source in
                        try FileManager.default.contentsOfDirectory(at: source,
                            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey], options: [])
                    }
                } catch {
                    failures.insert(url.lastPathComponent)
                    continue
                }
                for file in files {
                    if !self.isCurrent(token) { return }
                    let name = file.lastPathComponent
                    let id = folder.id + ":" + name
                    if updated.excluded.contains(id) { continue }
                    do {
                        let metadata: [String: Any]? = try coordinatedFileRead(at: file) { source in
                            let values = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                            guard values.isRegularFile == true else { return nil }
                            let sizeLimit = try engine.libraryRequest(["limit_name": name])
                            guard let limit = (sizeLimit["limit"] as? NSNumber)?.int64Value else {
                                throw CocoaError(.fileReadUnknown)
                            }
                            if Int64(values.fileSize ?? 0) > limit { oversized.insert(id); return nil }
                            return try engine.libraryRequest(["path": source.path, "cache": self.cacheURL.path, "name": name])
                        }
                        guard let metadata = metadata else { continue }
                        if !updated.entries.contains(where: { $0.id == id }) {
                            updated.entries.append(LibraryEntry(id: id, name: name, path: nil, folder: folder.id,
                                imported: false, model: nil, display: nil, chipset: nil, sha256: nil,
                                size: 0, lastBooted: nil, thumbnail: nil, available: true))
                        }
                        guard let position = updated.entries.firstIndex(where: { $0.id == id }) else { continue }
                        updated.entries[position].model = metadata["model"] as? String
                        updated.entries[position].display = metadata["name"] as? String
                        updated.entries[position].chipset = metadata["chipset"] as? String
                        updated.entries[position].sha256 = metadata["sha256"] as? String
                        updated.entries[position].size = (metadata["size"] as? NSNumber)?.int64Value ?? 0
                        updated.entries[position].available = true
                        let pending = updated.entries
                        DispatchQueue.main.async {
                            if self.isCurrent(token) { self.entries = pending }
                        }
                    } catch {
                        unreadable.insert(id)
                        failures.insert(name)
                    }
                }
            }
            for position in updated.entries.indices where updated.entries[position].imported {
                if !self.isCurrent(token) { return }
                let entry = updated.entries[position]
                guard let path = entry.path else { failures.insert(entry.name); continue }
                do {
                    let metadata: [String: Any]? = try coordinatedFileRead(at: URL(fileURLWithPath: path)) { source in
                        let limits = try engine.libraryRequest(["limit_name": entry.name])
                        guard let limit = (limits["limit"] as? NSNumber)?.int64Value else {
                            throw CocoaError(.fileReadUnknown)
                        }
                        let attributes = try FileManager.default.attributesOfItem(atPath: source.path)
                        if let size = (attributes[.size] as? NSNumber)?.int64Value, size > limit {
                            oversized.insert(entry.id)
                            return nil
                        }
                        return try engine.libraryRequest(["path": source.path, "cache": self.cacheURL.path, "name": entry.name])
                    }
                    guard let metadata = metadata else { continue }
                    updated.entries[position].model = metadata["model"] as? String
                    updated.entries[position].display = metadata["name"] as? String
                    updated.entries[position].chipset = metadata["chipset"] as? String
                    updated.entries[position].sha256 = metadata["sha256"] as? String
                    updated.entries[position].size = (metadata["size"] as? NSNumber)?.int64Value ?? 0
                    updated.entries[position].available = true
                } catch {
                    failures.insert(entry.name)
                    if FileManager.default.fileExists(atPath: path) { unreadable.insert(entry.id) }
                }
            }
            let failedNames = failures.sorted()
            let scanned = updated
            let oversizedIDs = oversized
            let unreadableIDs = unreadable
            DispatchQueue.main.async {
                guard self.isCurrent(token) else { return }
                var updated = scanned
                for i in updated.entries.indices {
                    if let current = self.index.entries.first(where: { $0.id == updated.entries[i].id }) {
                        updated.entries[i].lastBooted = current.lastBooted
                        updated.entries[i].thumbnail = current.thumbnail
                    }
                }
                self.index = updated
                var hashes = Set<String>()
                let availableHashes = Set(updated.entries.filter { $0.available }.compactMap { $0.sha256 })
                self.entries = updated.entries.filter { entry in
                    if oversizedIDs.contains(entry.id) || unreadableIDs.contains(entry.id) { return false }
                    guard let sha = entry.sha256, !sha.isEmpty else { return true }
                    if !entry.available && availableHashes.contains(sha) { return false }
                    return hashes.insert(sha).inserted
                }
                self.scanning = false
                self.failedSources = failedNames
                self.save()
            }
        }
    }

    func removesImportedCopies(_ entry: LibraryEntry) -> Bool {
        index.entries.contains { candidate in
            candidate.imported && (candidate.id == entry.id ||
                (entry.sha256 != nil && !entry.sha256!.isEmpty && candidate.sha256 == entry.sha256))
        }
    }

    func remove(_ entry: LibraryEntry) {
        guard indexReadable else { error = "Library index unreadable"; return }
        _ = nextGeneration()
        scanning = false
        let matches = index.entries.filter { candidate in
            candidate.id == entry.id || (entry.sha256 != nil && !entry.sha256!.isEmpty && candidate.sha256 == entry.sha256)
        }
        let root = importsURL.standardizedFileURL.resolvingSymlinksInPath().path + "/"
        let previousIndex = index
        let previousEntries = entries
        let removed = Set(matches.map { $0.id })
        index.entries.removeAll { removed.contains($0.id) }
        for id in removed where !index.excluded.contains(id) { index.excluded.append(id) }
        entries.removeAll { removed.contains($0.id) }
        // shortcut: no crash journal, add one when process-loss recovery is required.
        guard save() else {
            index = previousIndex
            entries = previousEntries
            return
        }
        var deletedCopies = Set<String>()
        for item in matches where item.imported {
            guard let path = item.path else { continue }
            let target = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
            do {
                guard target.path.hasPrefix(root) else { throw CocoaError(.fileWriteNoPermission) }
                if FileManager.default.fileExists(atPath: target.path) { try FileManager.default.removeItem(at: target) }
                deletedCopies.insert(item.id)
            } catch {
                index = previousIndex
                entries = previousEntries
                for position in index.entries.indices where deletedCopies.contains(index.entries[position].id) {
                    index.entries[position].available = false
                }
                for position in entries.indices where deletedCopies.contains(entries[position].id) {
                    entries[position].available = false
                }
                save()
                self.error = "Library removal incomplete"
                return
            }
        }
    }

    func ensureEntry(_ entry: LibraryEntry) {
        if !index.entries.contains(where: { $0.id == entry.id }) {
            index.entries.append(entry)
            entries = index.entries
            save()
        }
    }

    func recordBoot(_ id: String?, sha: String) {
        guard let id = id, let position = index.entries.firstIndex(where: { $0.id == id }) else { return }
        if !sha.isEmpty { index.entries[position].sha256 = sha }
        index.entries[position].lastBooted = Date()
        entries = index.entries
        save()
    }

    func recordFrame(_ id: String?, image: CGImage?) {
        guard let id = id, let image = image,
              let position = index.entries.firstIndex(where: { $0.id == id }),
              let sha = index.entries[position].sha256, sha.count == 64,
              sha.allSatisfy({ $0.isHexDigit }) else { return }
        let directory = support.appendingPathComponent("library-thumbnails", isDirectory: true)
        let target = directory.appendingPathComponent(sha + ".png")
        scanner.async {
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                let ratio = min(1, 160 / CGFloat(max(image.width, image.height)))
                let size = CGSize(width: max(1, CGFloat(image.width) * ratio), height: max(1, CGFloat(image.height) * ratio))
                let format = UIGraphicsImageRendererFormat()
                format.scale = 1
                let renderer = UIGraphicsImageRenderer(size: size, format: format)
                let small = renderer.image { _ in UIImage(cgImage: image).draw(in: CGRect(origin: .zero, size: size)) }
                try small.pngData()?.write(to: target, options: .atomic)
                DispatchQueue.main.async {
                    guard let position = self.index.entries.firstIndex(where: { $0.id == id && $0.sha256 == sha }) else { return }
                    self.index.entries[position].thumbnail = target.path
                    self.entries = self.index.entries
                    self.save()
                }
            } catch { DispatchQueue.main.async { self.error = "Library error" } }
        }
    }
}

struct LibraryFolderPicker: UIViewControllerRepresentable {
    let selected: (URL) -> Void
    func makeCoordinator() -> Coordinator { Coordinator(selected: selected) }
    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.folder])
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = false
        return picker
    }
    func updateUIViewController(_ picker: UIDocumentPickerViewController, context: Context) {}
    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let selected: (URL) -> Void
        init(selected: @escaping (URL) -> Void) { self.selected = selected }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            if let url = urls.first { selected(url) }
        }
    }
}

struct FirmwareLibraryView: View {
    @ObservedObject var store: FirmwareLibraryStore
    @ObservedObject var engine: QEMUEngine
    let text: (String) -> String
    let canClose: Bool
    let preparing: Bool
    let close: () -> Void
    let boot: (LibraryEntry) -> Void
    @State private var folderPicker = false
    @State private var filePicker = false
    @State private var infoEntry: LibraryEntry?
    @State private var selectedGroup: LibraryGroup?
    @State private var choosingFiles = false
    @State private var showingSettings = false
    @AppStorage("ui_language") private var uiLanguage = "auto"
    @AppStorage("persistent_state") private var persistentState = true
    @AppStorage("virtual_network") private var virtualNetwork = false
    @AppStorage("network_host_time") private var networkHostTime = true
    @AppStorage("network_start_time_enabled") private var networkStartTimeEnabled = false
    @AppStorage("network_start_time") private var networkStartTime = 1037837100.0

    private var librarySettings: some View {
        NavigationView {
            Form {
                Section(header: Text(text("Library folders"))) {
                    if store.folders.isEmpty { Text(text("Library no folders")).foregroundColor(.secondary) }
                    ForEach(store.folders) { folder in
                        HStack {
                            Text((folder.path as NSString?)?.lastPathComponent ?? folder.id).lineLimit(1)
                            Spacer()
                            Button(text("Library remove folder"), role: .destructive) { store.removeFolder(folder.id, engine: engine) }
                        }
                    }
                    Button(text("Library add folder")) { showingSettings = false; folderPicker = true }
                    Button(text("Library import")) { showingSettings = false; filePicker = true }
                        .disabled(store.importing)
                }
                Section {
                    AppIconPicker(text: text)
                    Picker(text("UI language"), selection: $uiLanguage) {
                        Text(text("Auto (System)")).tag("auto")
                        Text(text("Korean")).tag("ko")
                        Text(text("English")).tag("en")
                    }
                }
                Section(header: Text(text("Library session settings"))) {
                    Toggle(text("Virtual network"), isOn: $virtualNetwork)
                    // One choice: device clock or a manual start time; only relevant with the virtual network.
                    Picker(text("Network time"), selection: Binding(
                        get: { networkStartTimeEnabled },
                        set: { manual in networkStartTimeEnabled = manual; networkHostTime = !manual })) {
                        Text(text("Device clock")).tag(false)
                        Text(text("Set manually")).tag(true)
                    }
                    .disabled(!virtualNetwork)
                    if virtualNetwork && networkStartTimeEnabled {
                        DatePicker(text("Start time"), selection: Binding(
                            get: { Date(timeIntervalSince1970: networkStartTime) },
                            set: { networkStartTime = $0.timeIntervalSince1970 }),
                            in: Date(timeIntervalSince1970: 315964800)...Date(timeIntervalSince1970: 5813520000),
                            displayedComponents: [.date, .hourAndMinute])
                    }
                    Toggle(text("Persistent device state"), isOn: $persistentState)
                }
            }
            .navigationTitle(text("Settings"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { Button(text("Done")) { showingSettings = false } }
        }
    }

    private var groups: [LibraryGroup] {
        var result: [LibraryGroup] = []
        var positions: [String: Int] = [:]
        for entry in store.entries {
            let model = entry.model?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let key = model.isEmpty ? "file:" + entry.id : "model:" + model.lowercased()
            if let position = positions[key] {
                if let hash = entry.sha256, !hash.isEmpty,
                   let duplicate = result[position].files.firstIndex(where: { $0.sha256 == hash }) {
                    let old = result[position].files[duplicate]
                    if (entry.available && !old.available) ||
                       (entry.available == old.available && (entry.lastBooted ?? .distantPast) > (old.lastBooted ?? .distantPast)) {
                        result[position].files[duplicate] = entry
                    }
                } else { result[position].files.append(entry) }
            } else { positions[key] = result.count; result.append(LibraryGroup(id: key, files: [entry])) }
        }
        return result
    }

    private func select(_ group: LibraryGroup) {
        let files = group.files.filter { $0.available }
        guard !files.isEmpty && !engine.starting && !preparing else { return }
        if files.count == 1 { boot(files[0]) }
        else { selectedGroup = group; choosingFiles = true }
    }

    private func select(_ entry: LibraryEntry) {
        guard entry.available && !engine.starting && !preparing else { return }
        boot(entry)
    }

    @ViewBuilder private func fileActions(_ entry: LibraryEntry) -> some View {
        Button(text("Library info")) { infoEntry = entry }
        Button(text(store.removesImportedCopies(entry) ? "Library delete copies" : "Library remove"), role: .destructive) {
            store.remove(entry)
        }
    }

    private func lastBoot(_ entry: LibraryEntry) -> String {
        guard let date = entry.lastBooted else { return text("Library never") }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: uiLanguage == "auto" ? Locale.current.identifier : uiLanguage)
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    var body: some View {
        Group {
            if #available(iOS 16.0, *) {
                NavigationStack { libraryContent }
            } else {
                NavigationView { libraryContent }
            }
        }
        .environment(\.locale, Locale(identifier: uiLanguage == "auto" ? Locale.current.identifier : uiLanguage))
    }

    private var libraryContent: some View {
            VStack {
                if store.importing { ProgressView(text("Library importing")) }
                else if store.scanning || preparing || engine.starting { ProgressView(text("Library loading")) }
                if engine.sessionFailed {
                    Text(text("Error")).foregroundColor(.secondary)
                }
                if store.entries.isEmpty && !store.scanning && !store.importing && store.failedSources.isEmpty && store.error == nil {
                    Text(text("Library empty"))
                }
                if let error = store.error { Text(text(error)).foregroundColor(.secondary) }
                if !store.failedSources.isEmpty {
                    DisclosureGroup(String(format: text("Library partial scan"), store.failedSources.count)) {
                        ScrollView {
                            Text(store.failedSources.joined(separator: "\n"))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                        }.frame(maxHeight: 160)
                        Text(text("Library scan retry")).font(.footnote)
                    }.padding(.horizontal)
                }
                List(groups) { group in
                    let entry = group.latest
                    let spoken = String(format: text("Library row"), entry.displayName,
                                        entry.chipset ?? "—", lastBoot(entry))
                    HStack {
                        Button { select(group) } label: {
                            HStack {
                                if let path = entry.thumbnail, let image = UIImage(contentsOfFile: path) {
                                    Image(uiImage: image).resizable().interpolation(.none)
                                        .scaledToFit().frame(width: 60, height: 60)
                                }
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(entry.displayName).font(.headline).foregroundColor(.primary).lineLimit(1)
                                    Text("\(entry.chipset ?? "—") · \(group.sizes) · \(lastBoot(entry))")
                                        .font(.footnote).foregroundColor(.secondary)
                                    if !group.files.contains(where: { $0.available }) {
                                        Text(text("Library unavailable")).font(.caption)
                                    }
                                }
                                Spacer(minLength: 0)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.borderless)
                        .disabled(!group.files.contains(where: { $0.available }) || engine.starting || preparing)
                        .accessibilityLabel(spoken)
                        Menu {
                            if group.files.count == 1 { fileActions(entry) }
                            else {
                                ForEach(group.files) { file in
                                    Menu(file.name) { fileActions(file) }
                                }
                            }
                        } label: {
                            Image(systemName: "ellipsis").frame(width: 44, height: 44)
                                .contentShape(Rectangle())
                        }
                        .accessibilityLabel(String(format: text("Library file actions"), entry.displayName))
                    }
                    .padding(.vertical, 6)
                }
                .listStyle(.plain)
            }
            .background(Color(uiColor: .systemBackground))
            .navigationTitle(text("Library title"))
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Menu {
                        Button(text("Library add folder")) { folderPicker = true }
                        Button(text("Library import")) { filePicker = true }
                            .disabled(store.importing)
                            .keyboardShortcut("o", modifiers: .command)
                    } label: { Image(systemName: "plus") }
                    .accessibilityLabel(text("Library add"))
                    Button { store.refresh(engine: engine) } label: { Image(systemName: "arrow.clockwise") }
                        .accessibilityLabel(text("Library refresh"))
                        .disabled(store.importing)
                        .keyboardShortcut("r", modifiers: .command)
                    Button { showingSettings = true } label: { Image(systemName: "gearshape") }
                        .accessibilityLabel(text("Settings"))
                        .keyboardShortcut(",", modifiers: .command)
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    if canClose { Button(text("Done")) { close() } }
                }
            }
            .onAppear {
                // Firmware opened before the library existed lives in Application Support/firmware.
                let defaults = UserDefaults.standard
                if defaults.bool(forKey: "library_migrated") {
                    store.refresh(engine: engine)
                } else if let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
                    do {
                        let directory = support.appendingPathComponent("firmware")
                        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
                        if let name = names.sorted().first(where: { !$0.hasPrefix(".") }) {
                            store.importFile(directory.appendingPathComponent(name), engine: engine) { success in
                                if success { defaults.set(true, forKey: "library_migrated") }
                            }
                        } else {
                            defaults.set(true, forKey: "library_migrated")
                            store.refresh(engine: engine)
                        }
                    } catch {
                        let failure = error as NSError
                        if failure.domain == NSCocoaErrorDomain &&
                            (failure.code == CocoaError.Code.fileReadNoSuchFile.rawValue || failure.code == CocoaError.Code.fileNoSuchFile.rawValue) {
                            defaults.set(true, forKey: "library_migrated")
                        } else { store.error = "Library error" }
                        store.refresh(engine: engine)
                    }
                }
            }
            .sheet(isPresented: $showingSettings) { librarySettings }
            .sheet(isPresented: $folderPicker) {
                LibraryFolderPicker { url in store.addFolder(url, engine: engine) }
            }
            .fileImporter(isPresented: $filePicker, allowedContentTypes: [.data]) { result in
                switch result {
                case .success(let url): store.importFile(url, engine: engine)
                case .failure: store.error = "Library error"
                }
            }
            .confirmationDialog(selectedGroup?.latest.displayName ?? text("Choose firmware"), isPresented: $choosingFiles, titleVisibility: .visible) {
                ForEach(selectedGroup?.files.filter { $0.available } ?? []) { entry in
                    Button("\(entry.name) · \(String(format: "%.1f MiB", Double(entry.size) / 1048576))") { select(entry) }
                }
                Button(text("Cancel"), role: .cancel) { }
            }
            .alert(item: $infoEntry) { entry in
                Alert(title: Text(text("Library info")),
                    message: Text(String(format: text("Library info body"), entry.displayName,
                        entry.chipset ?? "—", entry.sha256 ?? "—", store.sourceDescription(entry))
                        + "\n\n" + String(format: text("Library delete copies detail"), entry.name)),
                    dismissButton: .default(Text(text("Done"))))
            }

    }
}
