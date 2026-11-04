import Foundation
import CoreGraphics
import SwiftUI
import UniformTypeIdentifiers
import UIKit

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

private struct LibraryIndex: Codable {
    var folders: [LibraryFolder] = []
    var entries: [LibraryEntry] = []
    var excluded: [String] = []
}

final class FirmwareLibraryStore: ObservableObject {
    @Published private(set) var entries: [LibraryEntry] = []
    @Published private(set) var scanning = false
    @Published var error: String?
    private var index = LibraryIndex()
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
        if let data = try? Data(contentsOf: indexURL),
           let loaded = try? JSONDecoder().decode(LibraryIndex.self, from: data) {
            index = loaded
            entries = loaded.entries
        }
    }

    private func save() {
        do {
            try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
            try JSONEncoder().encode(index).write(to: indexURL, options: .atomic)
        } catch { self.error = "Library error" }
    }

    func addFolder(_ url: URL, engine: QEMUEngine) {
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

    private func folderURL(_ id: String, index: LibraryIndex) -> URL? {
        guard let folder = index.folders.first(where: { $0.id == id }) else { return nil }
        var stale = false
        return try? URL(resolvingBookmarkData: folder.bookmark, options: [], relativeTo: nil, bookmarkDataIsStale: &stale)
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

    @discardableResult func withSource(_ entry: LibraryEntry, _ action: (URL) -> Void) -> Bool {
        if let path = entry.path {
            guard FileManager.default.isReadableFile(atPath: path) else { return false }
            action(URL(fileURLWithPath: path))
            return true
        }
        if let id = entry.folder, let folder = folderURL(id, index: index) {
            let scoped = folder.startAccessingSecurityScopedResource()
            defer { if scoped { folder.stopAccessingSecurityScopedResource() } }
            let file = folder.appendingPathComponent(entry.name)
            guard FileManager.default.isReadableFile(atPath: file.path) else { return false }
            action(file)
            return true
        }
        return false
    }

    func importFile(_ url: URL, engine: QEMUEngine) {
        let token = nextGeneration()
        scanning = true
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
                    let input = try FileHandle(forReadingFrom: url)
                    defer { try? input.close() }
                    FileManager.default.createFile(atPath: target.path, contents: nil)
                    let output = try FileHandle(forWritingTo: target)
                    defer { try? output.close() }
                    var total: Int64 = 0
                    while let data = try input.read(upToCount: 65536), !data.isEmpty {
                        guard self.isCurrent(token) else { throw NSError(domain: "FirmwareLibrary", code: 4) }
                        total += Int64(data.count)
                        guard total <= limit else { throw NSError(domain: "FirmwareLibrary", code: 3) }
                        try output.write(contentsOf: data)
                    }
                    guard self.isCurrent(token) else { throw NSError(domain: "FirmwareLibrary", code: 4) }
                    let metadata = try engine.libraryRequest(["path": target.path, "cache": self.cacheURL.path, "name": url.lastPathComponent])
                    let sha = metadata["sha256"] as? String
                    let byteCount = total
                    DispatchQueue.main.async {
                        guard self.isCurrent(token) else { try? FileManager.default.removeItem(at: directory); return }
                        if let sha = sha, self.index.entries.contains(where: { $0.available && $0.sha256 == sha }) {
                            try? FileManager.default.removeItem(at: directory)
                        } else {
                            self.index.entries.append(LibraryEntry(id: UUID().uuidString, name: url.lastPathComponent,
                                path: target.path, folder: nil, imported: true,
                                model: metadata["model"] as? String, display: metadata["name"] as? String,
                                chipset: metadata["chipset"] as? String,
                                sha256: sha, size: byteCount, lastBooted: nil, thumbnail: nil, available: true))
                            self.save()
                        }
                        self.scanning = false
                        self.refresh(engine: engine)
                    }
                } catch {
                    try? FileManager.default.removeItem(at: directory)
                    throw error
                }
            } catch {
                DispatchQueue.main.async {
                    if self.isCurrent(token) { self.scanning = false; self.error = "Library error" }
                }
            }
        }
    }

    func refresh(engine: QEMUEngine) {
        let token = nextGeneration()
        let original = index
        scanning = true
        scanner.async {
            var updated = original
            var oversized = Set<String>()
            var unreadable = Set<String>()
            for i in updated.entries.indices { updated.entries[i].available = false }
            for folder in updated.folders {
                if !self.isCurrent(token) { return }
                guard let url = self.folderURL(folder.id, index: updated) else { continue }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                guard let files = try? FileManager.default.contentsOfDirectory(at: url,
                        includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey], options: []) else { continue }
                for file in files {
                    if !self.isCurrent(token) { return }
                    guard let values = try? file.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
                          values.isRegularFile == true else { continue }
                    let name = file.lastPathComponent
                    let id = folder.id + ":" + name
                    if !FileManager.default.isReadableFile(atPath: file.path) {
                        unreadable.insert(id)
                        continue
                    }
                    guard let sizeLimit = try? engine.libraryRequest(["limit_name": name]),
                          let limit = (sizeLimit["limit"] as? NSNumber)?.int64Value else { continue }
                    if Int64(values.fileSize ?? 0) > limit { oversized.insert(id); continue }
                    if updated.excluded.contains(id) { continue }
                    if !updated.entries.contains(where: { $0.id == id }) {
                        updated.entries.append(LibraryEntry(id: id, name: name, path: nil, folder: folder.id,
                            imported: false, model: nil, display: nil, chipset: nil, sha256: nil,
                            size: Int64(values.fileSize ?? 0), lastBooted: nil, thumbnail: nil, available: true))
                    }
                    guard let position = updated.entries.firstIndex(where: { $0.id == id }) else { continue }
                    updated.entries[position].available = true
                    let pending = updated.entries
                    DispatchQueue.main.async {
                        if self.isCurrent(token) { self.entries = pending }
                    }
                    do {
                        if !self.isCurrent(token) { return }
                        let metadata = try engine.libraryRequest(["path": file.path, "cache": self.cacheURL.path, "name": name])
                        updated.entries[position].model = metadata["model"] as? String
                        updated.entries[position].display = metadata["name"] as? String
                        updated.entries[position].chipset = metadata["chipset"] as? String
                        updated.entries[position].sha256 = metadata["sha256"] as? String
                        updated.entries[position].size = (metadata["size"] as? NSNumber)?.int64Value ?? Int64(values.fileSize ?? 0)
                        updated.entries[position].available = true
                    } catch { }
                }
            }
            for position in updated.entries.indices where updated.entries[position].imported {
                if !self.isCurrent(token) { return }
                guard let path = updated.entries[position].path else { continue }
                let file = URL(fileURLWithPath: path)
                if FileManager.default.fileExists(atPath: path) && !FileManager.default.isReadableFile(atPath: path) {
                    unreadable.insert(updated.entries[position].id)
                    continue
                }
                updated.entries[position].available = FileManager.default.isReadableFile(atPath: path)
                do {
                    let limits = try engine.libraryRequest(["limit_name": updated.entries[position].name])
                    if let limit = (limits["limit"] as? NSNumber)?.int64Value,
                       let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                       let size = (attributes[.size] as? NSNumber)?.int64Value, size > limit {
                        oversized.insert(updated.entries[position].id)
                        continue
                    }
                    let metadata = try engine.libraryRequest(["path": path, "cache": self.cacheURL.path,
                                                               "name": updated.entries[position].name])
                    updated.entries[position].model = metadata["model"] as? String
                    updated.entries[position].display = metadata["name"] as? String
                    updated.entries[position].chipset = metadata["chipset"] as? String
                    updated.entries[position].sha256 = metadata["sha256"] as? String
                    updated.entries[position].size = (metadata["size"] as? NSNumber)?.int64Value ?? 0
                    updated.entries[position].available = FileManager.default.isReadableFile(atPath: file.path)
                } catch { }
            }
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
                self.save()
            }
        }
    }

    func remove(_ entry: LibraryEntry) {
        _ = nextGeneration()
        scanning = false
        let matches = index.entries.filter { candidate in
            candidate.id == entry.id || (entry.sha256 != nil && !entry.sha256!.isEmpty && candidate.sha256 == entry.sha256)
        }
        let root = importsURL.standardizedFileURL.resolvingSymlinksInPath().path + "/"
        for item in matches where item.imported {
            guard let path = item.path else { continue }
            let target = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
            guard target.path.hasPrefix(root) else { return }
            do { if FileManager.default.fileExists(atPath: target.path) { try FileManager.default.removeItem(at: target) } }
            catch { self.error = "Library error"; return }
        }
        let removed = Set(matches.map { $0.id })
        index.entries.removeAll { removed.contains($0.id) }
        for id in removed where !index.excluded.contains(id) { index.excluded.append(id) }
        entries.removeAll { removed.contains($0.id) }
        save()
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
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let ratio = min(1, 160 / CGFloat(max(image.width, image.height)))
            let size = CGSize(width: max(1, CGFloat(image.width) * ratio), height: max(1, CGFloat(image.height) * ratio))
            let format = UIGraphicsImageRendererFormat()
            format.scale = 1
            let renderer = UIGraphicsImageRenderer(size: size, format: format)
            let small = renderer.image { _ in UIImage(cgImage: image).draw(in: CGRect(origin: .zero, size: size)) }
            try small.pngData()?.write(to: target, options: .atomic)
            index.entries[position].thumbnail = target.path
            entries = index.entries
            save()
        } catch { self.error = "Library error" }
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
    let close: () -> Void
    let boot: (LibraryEntry) -> Void
    @State private var folderPicker = false
    @State private var filePicker = false
    @State private var infoEntry: LibraryEntry?

    private func select(_ entry: LibraryEntry) {
        guard entry.available && !engine.starting else { return }
        boot(entry)
    }

    private func lastBoot(_ entry: LibraryEntry) -> String {
        guard let date = entry.lastBooted else { return text("Library never") }
        return DateFormatter.localizedString(from: date, dateStyle: .short, timeStyle: .short)
    }

    var body: some View {
        Group {
            if #available(iOS 16.0, *) {
                NavigationStack { libraryContent }
            } else {
                NavigationView { libraryContent }
            }
        }
    }

    private var libraryContent: some View {
            VStack {
                if store.scanning { ProgressView(text("Library loading")) }
                if store.entries.isEmpty && !store.scanning { Text(text("Library empty")) }
                if let error = store.error { Text(text(error)).foregroundColor(.secondary) }
                List(store.entries) { entry in
                    let spoken = String(format: text("Library row"), entry.displayName,
                                        entry.chipset ?? "—", lastBoot(entry))
                    HStack {
                        if let path = entry.thumbnail, let image = UIImage(contentsOfFile: path) {
                            Image(uiImage: image).resizable().interpolation(.none)
                                .scaledToFit().frame(width: 48, height: 48)
                        }
                        VStack(alignment: .leading) {
                            Text(entry.displayName)
                            Text("\(entry.chipset ?? "—") · \(String(format: "%.1f MiB", Double(entry.size) / 1048576)) · \(lastBoot(entry))")
                                .font(.caption).foregroundColor(.secondary)
                            if !entry.available { Text(text("Library unavailable")).font(.caption) }
                        }
                        Spacer(minLength: 0)
                        if entry.available && (entry.sha256 ?? "").isEmpty { ProgressView().accessibilityHidden(true) }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { select(entry) }
                    .contextMenu {
                        Button(text("Library info")) { infoEntry = entry }
                        Button(text("Library remove"), role: .destructive) { store.remove(entry) }
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(spoken)
                    .accessibilityAddTraits(.isButton)
                    .accessibilityAction { select(entry) }
                    .accessibilityAction(named: Text(text("Library info"))) { infoEntry = entry }
                    .accessibilityAction(named: Text(text("Library remove"))) { store.remove(entry) }
                }
                .listStyle(.plain)
            }
            .navigationTitle(text("Library title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Menu {
                        Button(text("Library add folder")) { folderPicker = true }
                        Button(text("Library import")) { filePicker = true }
                    } label: { Image(systemName: "plus") }
                    .accessibilityLabel(text("Library add"))
                    Button { store.refresh(engine: engine) } label: { Image(systemName: "arrow.clockwise") }
                        .accessibilityLabel(text("Library refresh"))
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    if canClose { Button(text("Done")) { close() } }
                }
            }
            .onAppear { store.refresh(engine: engine) }
            .sheet(isPresented: $folderPicker) {
                LibraryFolderPicker { url in store.addFolder(url, engine: engine) }
            }
            .fileImporter(isPresented: $filePicker, allowedContentTypes: [.data]) { result in
                switch result {
                case .success(let url): store.importFile(url, engine: engine)
                case .failure(let error): store.error = "Library error"
                }
            }
            .alert(item: $infoEntry) { entry in
                Alert(title: Text(text("Library info")),
                      message: Text(String(format: text("Library info body"), entry.displayName,
                                           entry.chipset ?? "—", entry.sha256 ?? "—", store.sourceDescription(entry))),
                      dismissButton: .default(Text(text("Done"))))
            }

    }
}
