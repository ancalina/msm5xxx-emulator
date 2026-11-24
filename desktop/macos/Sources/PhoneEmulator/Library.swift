import SwiftUI
import AppKit

struct Firmware: Identifiable {
    let value: JSON
    var id: String { value["path"].string }
    var name: String { value["name"].string }
    var available: Bool { value["available"].bool }
    var subtitle: String { available ? "\(value["chipset"].string) · \(URL(fileURLWithPath: id).lastPathComponent)" : L("library_unavailable") }
}

@MainActor final class LibraryModel: ObservableObject {
    static let shared = LibraryModel()
    let backend = Backend()
    @Published var entries: [Firmware] = []
    @Published var folders: [String] = []
    @Published var scanning = false
    @Published var error = ""
    @Published var settings: [String: JSON] = [:]
    @Published var networkTimeDraft: String?
    @Published var generalSettingsSaving = false
    @Published var generalSettingsError = ""
    @Published var generalSettingsStatus = ""
    @Published var languageRevision = 0
    var windows: [String: EmulatorSceneModel] = [:]
    @Published var settingsEmulator: EmulatorSceneModel?
    @Published var hardwareDrafts: [String: [String: String]] = [:]
    @Published var hardwareSections: [String: [JSON]] = [:]
    @Published var hardwareErrors: [String: String] = [:]
    @Published var applyingHardware: Set<String> = []
    #if DEBUG
    weak var settingsWindow: NSWindow?
    #endif
    @Published var importing = false
    var importFolder = false
    var presentLibrary: (() -> Void)?
    var presentFirmware: ((URL) -> Void)?
    var presentSecondary: ((URL) -> Void)?
    var dismissSecondary: ((URL) -> Void)?
    private var initialized = false
    var shutdownComplete = false

    func initialize() async {
        guard !initialized else { return }; initialized = true
        var settingsFailure = ""
        do { try await loadSettings() } catch { settingsFailure = error.localizedDescription }
        await scan()
        if !settingsFailure.isEmpty {
            error = ([settingsFailure] + (error.isEmpty ? [] : [error])).joined(separator: "\n")
        }
    }
    func loadSettings() async throws {
        settings = try await backend.call("settings.get").object
        setInterfaceLanguage(settings["ui_language"]?.string ?? "auto")
        languageRevision += 1
    }
    func scan() async {
        guard !scanning else { return }
        scanning = true; error = ""
        defer { scanning = false }
        do {
            let result = try await backend.call("library.scan")
            entries = result["entries"].array.map(Firmware.init(value:))
            folders = result["folders"].array.map(\.string)
        } catch { self.error = error.localizedDescription }
    }
    func mutate(_ method: String, path: String) async {
        do { _ = try await backend.call(method, ["path": .string(path)]); await scan() }
        catch { self.error = error.localizedDescription }
    }
    func choose(folder: Bool = false) {
        guard !importing else { return }
        importFolder = folder; importing = true
    }
    func imported(_ result: Result<[URL], Error>, folder: Bool? = nil) {
        let folder = folder ?? importFolder
        Task {
            do {
                var failures: [String] = []
                for url in try result.get() {
                    let accessed = url.startAccessingSecurityScopedResource()
                    defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                    do {
                        _ = try await backend.call(folder ? "library.add_folder" : "library.add_file", ["path": .string(url.path)])
                    } catch { failures.append("\(url.lastPathComponent): \(error.localizedDescription)") }
                }
                await scan()
                if !failures.isEmpty {
                    let scanError = self.error
                    self.error = ([L("import_partial_failure")] + failures
                        + (scanError.isEmpty ? [] : [scanError])).joined(separator: "\n")
                }
            } catch { if (error as? CocoaError)?.code != .userCancelled { self.error = error.localizedDescription } }
        }
    }
    func receiveFiles(_ urls: [URL]) {
        guard !urls.isEmpty, urls.allSatisfy(\.isFileURL) else { return }
        presentLibrary?()
        imported(.success(urls), folder: false)
    }
    func model(for url: URL) -> EmulatorSceneModel {
        let key = url.resolvingSymlinksInPath().path
        if let model = windows[key], !model.session.closed { return model }
        let firmware = entries.first { URL(fileURLWithPath: $0.id).resolvingSymlinksInPath().path == key }
            ?? Firmware(value: .object(["path": .string(key), "name": .string(url.deletingPathExtension().lastPathComponent), "available": .bool(true)]))
        let model = EmulatorSceneModel(firmware: firmware, library: self)
        windows[key] = model
        return model
    }
    func open(_ firmware: Firmware) {
        guard firmware.available else { error = L("unavailable_note"); return }
        let url = URL(fileURLWithPath: firmware.id).resolvingSymlinksInPath()
        _ = model(for: url)
        NSDocumentController.shared.noteNewRecentDocumentURL(url)
        presentFirmware?(url)
    }
    func didClose(_ model: EmulatorSceneModel) {
        if settingsEmulator === model { settingsEmulator = nil }
        let key = URL(fileURLWithPath: model.session.firmware.id).resolvingSymlinksInPath().path
        Task {
            await model.session.close()
            if windows[key] === model { windows.removeValue(forKey: key) }
            await scan()
        }
    }
    func set(_ key: String, value: JSON, refreshTime: Bool = true) async throws {
        _ = try await backend.call("settings.set", ["key": .string(key), "value": value])
        settings[key] = value
        if refreshTime && ["network_host_time", "network_start_time"].contains(key) {
            for controller in windows.values where controller.session.running { await controller.session.action("session.network_time") }
        }
        if key == "ui_language" {
            setInterfaceLanguage(value.string)
            languageRevision += 1
            for controller in windows.values { await controller.session.reloadLayout() }
        }
    }
    func setNetworkTime(_ value: String) async throws {
        // Validate the time before changing the clock source, then refresh once.
        try await set("network_start_time", value: .string(value), refreshTime: false)
        try await set("network_host_time", value: .bool(false), refreshTime: false)
        for controller in windows.values where controller.session.running { await controller.session.action("session.network_time") }
    }
    func prepareForApplicationQuit() -> [Backend] {
        importing = false; settingsEmulator = nil
        let sessions = windows.values.map(\.session)
        for session in sessions { session.quiesceForApplicationQuit() }
        return sessions.map(\.backend)
    }
    func shutdown() async {
        guard !shutdownComplete else { return }
        importing = false
        let controllers = Array(windows.values)
        for c in controllers { await c.session.close() }
        await backend.close()
        shutdownComplete = true
    }
}

struct ErrorBanner: View {
    let message: String
    var body: some View {
        if !message.isEmpty {
            Label(message, systemImage: "exclamationmark.triangle")
                .foregroundStyle(.primary).textSelection(.enabled)
                .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary).accessibilityLabel(message)
        }
    }
}

struct LibraryView: View {
    @ObservedObject var model: LibraryModel
    @State private var info: Firmware?
    @SceneStorage("library.selection") private var selection: String?
    var body: some View {
        VStack(spacing: 0) {
            ErrorBanner(message: model.error)
            if model.scanning { ProgressView(L("library_loading")).controlSize(.small).padding() }
            if model.entries.isEmpty && !model.scanning {
                ContentUnavailableView {
                    Label(L("library_empty"), systemImage: "rectangle.stack")
                } actions: {
                    Button(L("library_import")) { model.choose() }.keyboardShortcut("o")
                }
            } else {
                List(selection: $selection) {
                    ForEach(model.entries) { firmware in
                        HStack(spacing: 12) {
                            Thumbnail(path: firmware.value["thumbnail"].string)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(firmware.name).font(.headline).lineLimit(1)
                                Text(firmware.subtitle).foregroundStyle(.secondary).lineLimit(1)
                            }
                            Spacer()
                            Button { model.open(firmware) } label: { Image(systemName: "play.fill") }
                                .disabled(!firmware.available).help(L("library_boot"))
                                .accessibilityLabel("\(L("library_boot")) \(firmware.name)")
                            Button { info = firmware } label: { Image(systemName: "info.circle") }
                                .help(L("library_info")).accessibilityLabel("\(L("library_info")) \(firmware.name)")
                            Button { Task { await model.mutate("library.remove", path: firmware.id) } } label: { Image(systemName: "minus.circle") }
                                .help(L("remove_help")).accessibilityLabel("\(L("library_remove")) \(firmware.name)")
                        }
                        .padding(.vertical, 5).tag(firmware.id).help(firmware.id)
                        .contentShape(Rectangle()).onTapGesture(count: 2) { model.open(firmware) }
                        .contextMenu {
                            Button(L("library_boot")) { model.open(firmware) }.disabled(!firmware.available)
                            Button(L("library_info")) { info = firmware }
                            Button(L("library_remove")) { Task { await model.mutate("library.remove", path: firmware.id) } }
                        }
                    }
                }
                .onKeyPress(.return) {
                    guard let item = model.entries.first(where: { $0.id == selection }) else { return .ignored }
                    model.open(item); return .handled
                }
            }
        }
        .frame(minWidth: 540, minHeight: 320)
        .navigationTitle(L("library_title"))
        .sheet(item: $info) { item in FirmwareInfo(firmware: item) }
    }
}

struct Thumbnail: View {
    let path: String
    @State private var image: NSImage?
    var body: some View {
        Group {
            if let image { Image(nsImage: image).interpolation(.none).resizable().scaledToFit() }
            else { Image(systemName: "iphone.gen1").font(.largeTitle).foregroundStyle(.secondary) }
        }.frame(width: 48, height: 56).accessibilityHidden(true)
            .task(id: path) {
                guard !path.isEmpty else { image = nil; return }
                let data = await Task.detached { try? Data(contentsOf: URL(fileURLWithPath: path)) }.value
                image = data.flatMap(NSImage.init(data:))
            }
    }
}

struct FirmwareInfo: View {
    let firmware: Firmware
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(firmware.name).font(.title2)
            Form {
                LabeledContent(L("library_model"), value: firmware.value["model"].string)
                LabeledContent(L("library_chipset"), value: firmware.value["chipset"].string)
                LabeledContent(L("library_size"), value: ByteCountFormatter.string(fromByteCount: Int64(firmware.value["size"].int), countStyle: .file))
                LabeledContent(L("library_path")) { Text(firmware.id).textSelection(.enabled).lineLimit(4) }
                LabeledContent(L("library_last"), value: firmware.value["last_booted"].isNull ? L("library_never") : Date(timeIntervalSince1970: Double(firmware.value["last_booted"].int)).formatted(date: .abbreviated, time: .shortened))
            }.textSelection(.enabled)
            HStack { Spacer(); Button(L("done")) { dismiss() }.keyboardShortcut(.defaultAction) }
        }.padding(24).frame(width: 460)
    }
}
