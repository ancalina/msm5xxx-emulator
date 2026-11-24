import SwiftUI

struct ApplicationSettings: View {
    @ObservedObject var library: LibraryModel
    var body: some View {
        Group {
            if let model = library.settingsEmulator, !model.session.closed {
                DeviceSettings(session: model.session, library: library)
                    .id(model.session.firmware.id)
            } else {
                GeneralSettings(library: library).frame(width: 560, height: 540)
            }
        }
        .focusedSceneValue(\.desktopScene, .settings)
        .background {
            #if DEBUG
            WindowAccessor { library.settingsWindow = $0 }
                .frame(width: 0, height: 0).allowsHitTesting(false)
            #endif
        }
    }
}

struct GeneralSettings: View {
    @ObservedObject private var appearance = AppPreferences.shared
    @ObservedObject var library: LibraryModel
    @State private var error = ""
    @State private var saving = false
    @State private var startTime = ""
    @State private var status = ""
    var body: some View {
        Form {
            Section {
                settingToggle("persistent_state")
                settingToggle("virtual_network")
                settingToggle("network_host_time")
                HStack(alignment: .firstTextBaseline) {
                    TextField(L("network_start_time"), text: $startTime)
                        .accessibilityLabel(Text(L("network_start_time")))
                        .help(L("time_format"))
                        .accessibilityHint(L("time_format"))
                    Button(L("apply")) { saveTime() }.disabled(saving)
                }
                settingToggle("experimental_rex")
            } footer: { Text(L("settings_notice")) }
            Section {
                Picker(L("ui_language"), selection: Binding(get: { library.settings["ui_language"]?.string ?? "auto" }, set: { save("ui_language", .string($0)) })) {
                    Text(L("auto_system")).tag("auto")
                    Text(L("korean")).tag("ko")
                    Text(L("english_language")).tag("en")
                }
            } footer: { Text(L("language_notice")) }
            Section {
                Picker(L("app_icon"), selection: Binding(get: { appearance.iconStyle }, set: { style in
                    Task { do { try await appearance.setIcon(style) } catch { self.error = error.localizedDescription } }
                })) {
                    Text(L("icon_full")).tag(AppIconStyle.full)
                    Text(L("icon_simple")).tag(AppIconStyle.simple)
                }
            }
            if saving { ProgressView(L("saving")) }
            if !status.isEmpty { Text(status).foregroundStyle(.secondary).accessibilityLabel(status) }
            ErrorBanner(message: error)
        }.formStyle(.grouped)
            .task {
                do { try await library.loadSettings(); startTime = library.settings["network_start_time"]?.string ?? "" }
                catch { self.error = error.localizedDescription }
            }
    }
    private func settingToggle(_ key: String) -> some View {
        Toggle(L(key), isOn: Binding(get: { library.settings[key]?.bool ?? false }, set: { save(key, .bool($0)) })).disabled(saving)
    }
    private func save(_ key: String, _ value: JSON) {
        saving = true; error = ""; status = ""
        Task {
            do { try await library.set(key, value: value); status = L("saved") }
            catch { self.error = error.localizedDescription }
            saving = false
        }
    }
    private func saveTime() { save("network_start_time", .string(startTime)) }
}

struct DeviceSettings: View {
    @ObservedObject var session: SessionModel
    @ObservedObject var library: LibraryModel
    @State private var loading = true
    @State private var selectedTab = 1
    private var firmwareID: String { session.firmware.id }
    private var applying: Bool { library.applyingHardware.contains(firmwareID) }
    private var sections: [JSON] { library.hardwareSections[firmwareID] ?? [] }
    private var values: [String: String] {
        var values: [String: String] = [:]
        for section in sections {
            for field in section["fields"].array { values[field["name"].string] = field["value"].text }
        }
        return values.merging(library.hardwareDrafts[firmwareID] ?? [:]) { _, draft in draft }
    }
    var body: some View {
        VStack(spacing: 0) {
            Text(session.title).font(.headline).padding()
            TabView(selection: $selectedTab) {
                GeneralSettings(library: library).tag(0).tabItem { Text(L("general")) }
                VStack(spacing: 0) {
                    if loading { ProgressView(L("detecting")).padding() }
                    ErrorBanner(message: library.hardwareErrors[firmwareID] ?? "")
                    Form {
                        ForEach(sections, id: \.selfID) { section in
                            Section(section["title"].string) {
                                ForEach(section["fields"].array, id: \.selfID) { field in
                                    let name = field["name"].string
                                    let binding = Binding(get: { values[name] ?? field["value"].text }, set: {
                                        guard !applying else { return }
                                        library.hardwareDrafts[firmwareID, default: [:]][name] = $0
                                    })
                                    if field["choices"].isNull {
                                        TextField(field["label"].string, text: binding)
                                            .accessibilityLabel(Text(field["label"].string))
                                    } else {
                                        Picker(field["label"].string, selection: binding) {
                                            ForEach(field["choices"].array.map(\.string), id: \.self) { choice in Text(choice).tag(choice) }
                                        }.accessibilityLabel(Text(field["label"].string))
                                    }
                                }
                            }
                        }
                    }.formStyle(.grouped).disabled(applying)
                    HStack {
                        Spacer()
                        Button(L("apply_restart")) { apply() }.disabled(loading || applying || sections.isEmpty || session.busy)
                    }.padding()
                }.tag(1).tabItem { Text(L("hardware")) }
            }

        }.frame(width: 600, height: 640)
        .task {
            if !applying {
                do {
                    library.hardwareSections[firmwareID] = try await session.backend.call("session.settings")["sections"].array
                } catch { library.hardwareErrors[firmwareID] = error.localizedDescription }
            }
            loading = false
        }
    }
    private func apply() {
        guard !loading, !applying, !session.busy else { return }
        let id = firmwareID, submittedValues = values
        library.applyingHardware.insert(id)
        library.hardwareErrors[id] = ""
        Task {
            defer { library.applyingHardware.remove(id) }
            do {
                _ = try await session.backend.call("session.apply_settings", ["values": .object(submittedValues.mapValues(JSON.string))])
                await session.reboot()
                guard session.error.isEmpty else { library.hardwareErrors[id] = session.error; return }
                library.hardwareSections[id] = try await session.backend.call("session.settings")["sections"].array
                library.hardwareDrafts.removeValue(forKey: id)
            } catch {
                library.hardwareErrors[id] = error.localizedDescription
                session.error = error.localizedDescription
            }
        }
    }
}

struct MappingView: View {
    @ObservedObject var session: SessionModel
    let bit: Int
    let title: String
    @Environment(\.dismiss) var dismiss
    @State private var value = ""
    @State private var error = ""
    @State private var busy = true
    @FocusState private var focused: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("edit_input") + " · " + title).font(.title2)
            TextField(L("key_value"), text: $value).focused($focused)
                .disabled(busy || session.settingsWritePending)
                .accessibilityLabel(Text(L("key_value")))
                .accessibilityHint(Text(L("key_help")))
            Text(L("key_help")).font(.callout).foregroundStyle(.secondary)
            ErrorBanner(message: error.isEmpty ? session.settingsWriteError : error)
            if session.settingsWritePending {
                ProgressView(L("saving"))
                Text(L("close_keeps_applying")).font(.callout)
            } else if !session.settingsStatus.isEmpty {
                Text(session.settingsStatus).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button(L(session.settingsWritePending ? "close" : "cancel")) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(L("apply")) { save() }.keyboardShortcut(.defaultAction).disabled(busy || session.settingsWritePending)
            }
        }.padding(24).frame(width: 420)
            .task {
                do {
                    let existing = try await session.backend.call("session.key_mapping", ["bit": .integer(bit)])
                    value = existing.isNull ? "" : String(format: "0x%02X", existing.int)
                } catch { self.error = error.localizedDescription }
                busy = false; focused = true
            }
    }
    private func save() {
        guard !busy, !session.settingsWritePending else { return }
        let submittedValue = value, presentation = session.sheetGeneration
        busy = true; error = ""
        session.settingsWritePending = true
        session.settingsWriteError = ""; session.settingsStatus = ""
        Task {
            defer { busy = false; session.settingsWritePending = false }
            do {
                let result = try await session.backend.call("session.set_key_mapping", ["bit": .integer(bit), "value": .string(submittedValue)])
                if result.isNull { session.mapped.remove(bit) } else { session.mapped.insert(bit) }
                session.settingsStatus = L("edit_input") + " · " + title + ": " + L("saved")
                if session.sheetGeneration == presentation { session.sheet = nil }
            } catch {
                session.settingsWriteError = error.localizedDescription
                session.error = error.localizedDescription
            }
        }
    }
}

struct NetworkTimeView: View {
    @ObservedObject var session: SessionModel
    @ObservedObject var library: LibraryModel
    @Environment(\.dismiss) var dismiss
    @State private var value = ""
    @State private var busy = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("network_time_title")).font(.title2)
            TextField(L("network_start_time"), text: $value)
                .disabled(busy || session.settingsWritePending)
                .accessibilityLabel(Text(L("network_start_time")))
                .accessibilityHint(Text(L("time_format")))
            Text(L("time_format")).foregroundStyle(.secondary)
            ErrorBanner(message: session.settingsWriteError)
            if session.settingsWritePending {
                ProgressView(L("saving"))
                Text(L("close_keeps_applying")).font(.callout)
            } else if !session.settingsStatus.isEmpty {
                Text(session.settingsStatus).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button(L(session.settingsWritePending ? "close" : "cancel")) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(L("apply")) { apply() }.keyboardShortcut(.defaultAction).disabled(busy || session.settingsWritePending)
            }
        }.padding(24).frame(width: 440)
        .onAppear { value = library.settings["network_start_time"]?.string ?? "" }
    }
    private func apply() {
        guard !busy, !session.settingsWritePending else { return }
        let submittedValue = value, presentation = session.sheetGeneration
        busy = true
        session.settingsWritePending = true
        session.settingsWriteError = ""; session.settingsStatus = ""
        Task {
            defer { busy = false; session.settingsWritePending = false }
            do {
                try await library.setNetworkTime(submittedValue)
                _ = try await session.backend.call("session.network_time")
                session.settingsStatus = L("network_time_title") + ": " + L("saved")
                if session.sheetGeneration == presentation { session.sheet = nil }
            } catch {
                session.settingsWriteError = error.localizedDescription
                session.error = error.localizedDescription
            }
        }
    }
}
