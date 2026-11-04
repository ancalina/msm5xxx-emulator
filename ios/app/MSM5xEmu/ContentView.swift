import SwiftUI
import UniformTypeIdentifiers
import CryptoKit

struct ContentView: View {
    @StateObject private var engine = QEMUEngine()
    @StateObject private var library = FirmwareLibraryStore()
    @State private var showingLibrary = !ContentView.bypassLibraryOnLaunch()
    @State private var runningLibraryID = ""
    @AppStorage("active_library_id") private var activeLibraryID = ""
    @State private var firmware: URL?
    @State private var message = ""
    @State private var jit = QEMUEngine.jitAvailable
    @State private var showingSettings = false
    @State private var showingCapture = false
    @State private var showingTime = false
    @State private var timeDraft = Date()
    @State private var showingSecondary = false
    @AppStorage("secondary_above") private var secondaryAbove = false
    @State private var editingMapping = false
    @State private var mappingBit = 0
    @State private var mappingValue = ""
    @State private var showingMapping = false
    @State private var firmwareIdentity = ""
    @State private var detailedValues: [String: String] = [:]
    private static let detailBounds = [0, 5, 13, 16, 20, 28, 33, 41]
    private static let detailFields = ["model", "chipset", "width", "height", "board_revision", "image_offset", "load_address", "flash_size", "ram_base", "ram_size", "ram_image_offset", "ram_image_size", "entry", "framebuffer_address", "framebuffer_stride", "framebuffer_format", "board_revision_register", "board_revision_value", "key_register", "key_active_low", "rex_idle_address", "rex_tick_address", "rex_tick_ms", "board_adc_value", "flash_id_address", "flash_id_value", "dmd_download_address", "primary_flash_probe_address", "secondary_flash_address", "secondary_flash_size", "secondary_flash_image", "secondary_flash_state", "secondary_flash_write_address", "flash_state", "nand_enabled", "nand_image", "nand_data_size", "nand_page_size", "nand_spare_size", "nand_pages_per_block", "nand_bus_width"]
    // Same settings and defaults as Android's settings dialog.
    @AppStorage("ui_language") private var uiLanguage = "auto"
    @AppStorage("persistent_state") private var persistentState = true
    @AppStorage("experimental_rex") private var experimentalRex = false
    @AppStorage("virtual_network") private var virtualNetwork = false
    @AppStorage("network_host_time") private var networkHostTime = true
    @AppStorage("network_start_time_enabled") private var networkStartTimeEnabled = false
    @AppStorage("network_start_time") private var networkStartTime = 1037837100.0

    // Same order, labels and guest bits as Android's KEY_LAYOUT; volume keys sit in the side column.
    private static let keypad: [[(String, Int)]] = [
        [("Menu", 0), ("▲", 1), ("Cancel", 2)], [("◀", 4), ("OK", 5), ("▶", 6)],
        [("Call", 3), ("▼", 9), ("End", 7)], [("1", 11), ("2", 12), ("3", 13)],
        [("4", 14), ("5", 15), ("6", 16)], [("7", 17), ("8", 18), ("9", 19)],
        [("*", 20), ("0", 21), ("#", 22)],
    ]

    private static func bypassLibraryOnLaunch() -> Bool {
        if UserDefaults.standard.bool(forKey: "pending_boot") { return true }
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return false }
        return FileManager.default.fileExists(atPath: support.appendingPathComponent("autorun").path)
    }

    private var hasProfile: Bool {
        !firmwareIdentity.isEmpty && engine.identity == firmwareIdentity
    }

    private func text(_ key: String) -> String {
        let language = uiLanguage == "auto"
            ? (Locale.preferredLanguages.first?.hasPrefix("ko") == true ? "ko" : "en") : uiLanguage
        let path = Bundle.main.path(forResource: language, ofType: "lproj")
        let bundle = path.flatMap { Bundle(path: $0) } ?? .main
        return String(localized: String.LocalizationValue(key), bundle: bundle)
    }

    private func detailLabel(_ key: String) -> String { text("detail." + key) }

    var body: some View {
        Group {
            if showingLibrary {
                FirmwareLibraryView(store: library, engine: engine, text: text,
                    canClose: engine.running || engine.used || firmware != nil,
                    close: { showingLibrary = false },
                    boot: { entry in
                        library.ensureEntry(entry)
                        library.pauseScanning()
                        let found = library.withSource(entry) { url in
                            if importFirmware(url) {
                                activeLibraryID = entry.id
                                showingLibrary = false
                            } else { library.error = "Library error" }
                        }
                        if !found { library.error = "Library unavailable" }
                    })
            } else {
                emulatorView
            }
        }
        .onAppear(perform: pickStoredFirmware)
        .onChange(of: engine.running) { running in
            if running {
                runningLibraryID = activeLibraryID
                library.recordBoot(runningLibraryID.isEmpty ? nil : runningLibraryID, sha: engine.identity)
            } else {
                library.recordFrame(runningLibraryID.isEmpty ? nil : runningLibraryID, image: engine.frame)
                runningLibraryID = ""
            }
            UIAccessibility.post(notification: .announcement, argument: text(running ? "Booted" : "Powered off"))
        }
        .onChange(of: engine.status) { value in
            UIAccessibility.post(notification: .announcement, argument: text(value))
        }
        .onChange(of: message) { value in
            if !value.isEmpty { UIAccessibility.post(notification: .announcement, argument: value) }
        }
        .onReceive(Timer.publish(every: 0.1, on: .main, in: .common).autoconnect()) { _ in
            engine.refresh()
        }
    }

    private var statusBlock: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(text(engine.status)).foregroundColor(.gray)
            Text(localizedMetrics).foregroundColor(.gray)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(localizedMetrics)
            if !message.isEmpty { Text(message).foregroundColor(.gray) }
        }
        .font(.system(size: 10)).foregroundColor(.white).lineLimit(3)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    @ViewBuilder private var moreControl: some View {
        if editingMapping {
            Button(text("Done editing")) { editingMapping = false }
                .frame(maxWidth: .infinity).frame(height: 44)
        } else {
            Menu {
                Toggle(text("Virtual network"), isOn: Binding(
                    get: { virtualNetwork },
                    set: { value in
                        guard value != virtualNetwork else { return }
                        virtualNetwork = value
                        restartOnNextLaunchIfRunning()
                    }))
                Button(text("Start")) { run() }.disabled(engine.running || engine.used || firmware == nil)
                Button(text("Stop emulator")) { engine.stop() }.disabled(!engine.running)
                Button(text("Reboot emulator")) { restartOnNextLaunchIfRunning() }.disabled(!engine.running)
                Button(text("Choose firmware…")) { showingLibrary = true }
                Button(text("Capture")) { showingCapture = true }.disabled(engine.frame == nil)
                Button(text("Edit key input")) { editingMapping = true }.disabled(!engine.running)
                Menu(text("Time")) {
                    Button {
                        networkHostTime = true
                        networkStartTimeEnabled = false
                        if virtualNetwork { restartOnNextLaunchIfRunning() }
                    } label: {
                        if networkHostTime { Label(text("Host time"), systemImage: "checkmark").accessibilityAddTraits(.isSelected) }
                        else { Text(text("Host time")) }
                    }
                    Button {
                        timeDraft = Date(timeIntervalSince1970: networkStartTime)
                        showingTime = true
                    } label: {
                        if !networkHostTime { Label(text("Set time…"), systemImage: "checkmark").accessibilityAddTraits(.isSelected) }
                        else { Text(text("Set time…")) }
                    }
                }
                Button(text("Settings…")) { showingSettings = true }
            } label: {
                Text(text("•••")).font(.title2).foregroundColor(.white)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color(white: 0.33))
            }
            .frame(height: 44)
            .accessibilityLabel(text("More actions"))
            .accessibilityHint(text("Menu hint"))
        }
    }

    private var emulatorView: some View {
        VStack(spacing: 2) {
            if secondaryAbove { secondaryDisplay }
            ZStack {
                Color.black
                if let frame = engine.frame {
                    Image(decorative: frame, scale: 1).resizable().interpolation(.none)
                        .aspectRatio(contentMode: .fit)
                } else {
                    Text(firmware?.lastPathComponent ?? text("No firmware")).foregroundColor(.gray)
                }
            }
            .frame(maxHeight: .infinity)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(text("Phone screen"))
            if !secondaryAbove { secondaryDisplay }

            GeometryReader { geometry in
                HStack(spacing: 2) {
                    VStack(spacing: 2) {
                        key(text("Vol+"), 10).frame(height: 44)
                        key(text("Vol-"), 8).frame(height: 44)
                        Button(text(engine.foldOpen ? "Close fold" : "Open fold")) { engine.toggleFold() }
                            .buttonStyle(HandsetKeyStyle(dimmed: !engine.running))
                            .frame(height: 44)
                        statusBlock
                        moreControl
                    }
                    .frame(width: geometry.size.width / 3)
                    VStack(spacing: 2) {
                        ForEach(0..<Self.keypad.count, id: \.self) { row in
                            HStack(spacing: 2) {
                                ForEach(0..<3, id: \.self) { column in
                                    let (label, bit) = Self.keypad[row][column]
                                    key(text(label), bit)
                                }
                            }
                        }
                    }
                }
            }
            .frame(height: 320)
        }
        .padding(2)
        .environment(\.locale, Locale(identifier: uiLanguage == "auto" ? Locale.current.identifier : uiLanguage))
        .background(Color(white: 0.07).ignoresSafeArea())
        // JIT can be granted while running (TrollStore "Open with JIT", Dopamine); poll cheaply.
        .onReceive(Timer.publish(every: 2, on: .main, in: .common).autoconnect()) { _ in
            // Headless test runs (autorun marker) leave the latest LCD frame as frame.png.
            if let frame = engine.frame,
               let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first,
               FileManager.default.fileExists(atPath: support.appendingPathComponent("autorun").path) {
                try? UIImage(cgImage: frame).pngData()?.write(to: support.appendingPathComponent("frame.png"))
            }
            let now = QEMUEngine.jitAvailable
            if now != jit || QEMUEngine.codeSigningFlags & 0x1000_0000 != 0 && !now {
                jit = now
                NSLog("MSM5xEmu JIT %@ (cs flags 0x%08x)", now ? "available" : "unavailable", QEMUEngine.codeSigningFlags)
            }
        }
        .sheet(isPresented: $showingTime) {
            NavigationView {
                Form {
                    DatePicker(text("Set time…"), selection: $timeDraft,
                        in: Date(timeIntervalSince1970: 315964800)...Date(timeIntervalSince1970: 5813520000),
                        displayedComponents: [.date, .hourAndMinute])
                }.navigationTitle(text("Time"))
                    .toolbar {
                        Button(text("Save")) {
                            networkStartTime = timeDraft.timeIntervalSince1970
                            networkHostTime = false
                            networkStartTimeEnabled = true
                            showingTime = false
                            if virtualNetwork { restartOnNextLaunchIfRunning() }
                        }
                    }
            }
        }
        .sheet(isPresented: $showingMapping) {
            NavigationView {
                Form {
                    Text(text("Event code (blank restores automatic mapping)"))
                    TextField(text("Event code"), text: $mappingValue).autocapitalization(.none)
                    Button(text("Save")) {
                        let raw = mappingValue.trimmingCharacters(in: .whitespacesAndNewlines)
                        let number = Self.parseEventCode(raw)
                        guard raw.isEmpty || number != nil else {
                            message = text("Invalid event code"); return
                        }
                        engine.setMapping(mappingBit, value: number) { accepted in
                            if accepted { showingMapping = false }
                            else { message = text("Input mapping rejected") }
                        }
                    }
                }.navigationTitle(text("Input mapping"))
                    .toolbar { Button(text("Cancel")) { showingMapping = false } }
            }
        }
        .sheet(isPresented: $showingCapture) {
            if let frame = engine.frame, let data = UIImage(cgImage: frame).pngData() {
                CaptureShare(data: data, savedMessage: text("Screenshot saved"))
            }
        }
        .sheet(isPresented: $showingSettings) {
            NavigationView {
                Form {
                    Toggle(text("Persistent device state"), isOn: $persistentState)
                    Picker(text("UI language"), selection: $uiLanguage) {
                        Text(text("Auto (System)")).tag("auto")
                        Text(text("Korean")).tag("ko")
                        Text(text("English")).tag("en")
                    }
                    Toggle(text("Additional display"), isOn: $showingSecondary)
                        .disabled(!engine.secondaryAvailable)
                    Picker(text("Display position"), selection: $secondaryAbove) {
                        Text(text("Above")).tag(true)
                        Text(text("Below")).tag(false)
                    }
                    if !hasProfile { Text(text("Profile required")) }
                    Section(text("Detailed settings")) {
                        Toggle(text("Experimental static REX controller"), isOn: $experimentalRex)
                    }.disabled(!hasProfile)
                    ForEach(0..<7, id: \.self) { section in
                        Section(text("section." + String(section))) {
                            ForEach(Self.detailFields[Self.detailBounds[section]..<Self.detailBounds[section + 1]], id: \.self) { name in
                                TextField(detailLabel(name), text: Binding(
                                    get: { detailedValues[name] ?? "" },
                                    set: { value in
                                        detailedValues[name] = value.isEmpty ? nil : value
                                        UserDefaults.standard.set(detailedValues, forKey: "details.\(firmwareIdentity)")
                                    }))
                                    .autocapitalization(.none)
                            }
                        }.disabled(!hasProfile)
                    }
                }
                .navigationTitle(text("Settings"))
                .toolbar { Button(text("Done")) { showingSettings = false } }
            }
        }


    }

    private var localizedMetrics: String {
        engine.metrics.replacingOccurrences(of: "Run ", with: text("Run") + " ")
            .replacingOccurrences(of: "Frame ", with: text("Frame") + " ")
    }

    @ViewBuilder private var secondaryDisplay: some View {
        if showingSecondary && engine.secondaryAvailable {
            VStack {
                if let frame = engine.secondaryFrame {
                    Image(decorative: frame, scale: 1).resizable().interpolation(.none)
                        .aspectRatio(contentMode: .fit).frame(height: 90)
                }
                if engine.secondaryPreview {
                    Text(text("Preview: colors and orientation unverified")).font(.caption)
                }
            }.foregroundColor(.white)
        }
    }

    private static func parseEventCode(_ source: String) -> Int? {
        var value = source.lowercased()
        if value.isEmpty { return nil }
        var sign = 1
        let logHex = value.count > 1 && value.hasPrefix("0")
            && !value.hasPrefix("0x") && !value.hasPrefix("0o") && !value.hasPrefix("0b")
        if !logHex && (value.hasPrefix("+") || value.hasPrefix("-")) {
            if value.hasPrefix("-") { sign = -1 }
            value.removeFirst()
        }
        var radix = logHex ? 16 : 10
        if !logHex && value.hasPrefix("0x") { radix = 16; value.removeFirst(2) }
        else if !logHex && value.hasPrefix("0o") { radix = 8; value.removeFirst(2) }
        else if !logHex && value.hasPrefix("0b") { radix = 2; value.removeFirst(2) }
        else if !logHex && value.count > 1 && value.hasPrefix("0")
                    && value.replacingOccurrences(of: "_", with: "").contains(where: { $0 != "0" }) { return nil }
        guard let number = Int(value.replacingOccurrences(of: "_", with: ""), radix: radix) else { return nil }
        let result = number * sign
        return (0...255).contains(result) ? result : nil
    }

    private func restartOnNextLaunchIfRunning() {
        guard engine.running else { return }
        UserDefaults.standard.set(true, forKey: "pending_boot")
        engine.stop()
        message = text("Reopen the app to start the selected firmware.")
    }

    private func run() {
        guard let firmware = firmware else { return }
        engine.start(firmware, persistentState: persistentState, experimentalRex: experimentalRex,
                     virtualNetwork: virtualNetwork, networkHostTime: networkHostTime,
                     networkStartTime: networkStartTimeEnabled ? networkStartTime : nil)
    }

    @ViewBuilder private func key(_ label: String, _ bit: Int) -> some View {
        if editingMapping {
            Button(label) {
                mappingBit = bit
                let key = "keymap.\(engine.identity).\(bit)"
                if let saved = UserDefaults.standard.object(forKey: key) as? Int {
                    mappingValue = String(format: "0x%02X", saved)
                } else { mappingValue = "" }
                showingMapping = true
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
                .accessibilityLabel(spokenKey(bit, fallback: label))
                .accessibilityHint(text("Reassign hint"))
        } else {
            PhoneKey(label: label, accessibilityName: spokenKey(bit, fallback: label), enabled: engine.running && (engine.inputBits.contains(bit) || UserDefaults.standard.object(forKey: "keymap.\(engine.identity).\(bit)") != nil),
                     transition: { engine.key(bit, pressed: $0) })
        }
    }

    private func spokenKey(_ bit: Int, fallback: String) -> String {
        switch bit {
        case 10: return text("Volume up")
        case 8: return text("Volume down")
        case 1: return text("Up")
        case 9: return text("Down")
        case 4: return text("Left")
        case 6: return text("Right")
        default: return fallback
        }
    }

    /// Reuse a firmware already in Application Support/firmware (imported earlier or copied in over
    /// SSH); an `autorun` file next to that folder starts it without touching the screen.
    private func pickStoredFirmware() {
        guard firmware == nil, !engine.used,
              let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return }
        let pending = UserDefaults.standard.bool(forKey: "pending_boot")
        let marker = FileManager.default.fileExists(atPath: support.appendingPathComponent("autorun").path)
        if !pending && !marker {
            showingLibrary = true
            return
        }
        showingLibrary = false
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: support.appendingPathComponent("firmware").path),
              let name = names.filter({ !$0.hasPrefix(".") }).sorted().first else { return }
        firmware = support.appendingPathComponent("firmware").appendingPathComponent(name)
        loadDetailedSettings()
        if pending {
            UserDefaults.standard.removeObject(forKey: "pending_boot")
            run()
        } else if marker {
            activeLibraryID = ""
            NSLog("MSM5xEmu autorun %@", name)
            run()
        }
    }

    private func loadDetailedSettings() {
        guard let firmware = firmware, let stream = InputStream(url: firmware) else { return }
        stream.open()
        defer { stream.close() }
        var hash = SHA256()
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count <= 0 { break }
            hash.update(data: Data(buffer.prefix(count)))
        }
        firmwareIdentity = hash.finalize().map { String(format: "%02x", $0) }.joined()
        detailedValues = UserDefaults.standard.dictionary(forKey: "details.\(firmwareIdentity)") as? [String: String] ?? [:]
    }

    private func supportStagingURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    /// Copy the picked image into the app container; the original is never modified.
    private func importFirmware(_ url: URL) -> Bool {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let dir = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                  appropriateFor: nil, create: true)
                .appendingPathComponent("firmware", isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let target = dir.appendingPathComponent(url.lastPathComponent)
            let staged = supportStagingURL()
            try FileManager.default.copyItem(at: url, to: staged)
            defer { try? FileManager.default.removeItem(at: staged) }
            // Preserve the previous selection if the source could not be copied.
            if engine.running { restartOnNextLaunchIfRunning() }
            for old in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] {
                try FileManager.default.removeItem(at: old)
            }
            try FileManager.default.moveItem(at: staged, to: target)
            firmware = target
            loadDetailedSettings()
            if engine.used {
                UserDefaults.standard.set(true, forKey: "pending_boot")
                message = text("Reopen the app to start the selected firmware.")
            } else {
                run()
            }
            if !engine.used { message = String(format: text("Imported file"), target.lastPathComponent) }
            return true
        } catch {
            message = error.localizedDescription
            return false
        }
    }
}


private struct HandsetKeyStyle: ButtonStyle {
    let dimmed: Bool
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13))
            .lineLimit(1).minimumScaleFactor(0.7)
            .foregroundColor(enabled && !dimmed ? .white : .gray)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(white: !enabled || dimmed ? 0.18 : configuration.isPressed ? 0.44 : 0.33))
            .contentShape(Rectangle())
    }
}

private struct PhoneKey: View {
    let label: String
    let accessibilityName: String
    let enabled: Bool
    let transition: (Bool) -> Void
    @State private var pressed = false
    var body: some View {
        Text(label)
            .font(.system(size: 13))
            .lineLimit(1).minimumScaleFactor(0.7)
            .foregroundColor(enabled ? .white : .gray)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(white: !enabled ? 0.18 : pressed ? 0.44 : 0.33))
            .contentShape(Rectangle())
            .gesture(DragGesture(minimumDistance: 0)
                .onChanged { _ in
                    if enabled && !pressed { pressed = true; transition(true) }
                }
                .onEnded { _ in
                    if pressed { pressed = false; transition(false) }
                })
            .accessibilityLabel(accessibilityName)
            .accessibilityAddTraits(.isButton)
            .accessibilityAction {
                if enabled { transition(true); transition(false) }
            }
            .onDisappear { if pressed { pressed = false; transition(false) } }
    }
}

private struct CaptureShare: UIViewControllerRepresentable {
    let data: Data
    let savedMessage: String
    func makeUIViewController(context: Context) -> UIActivityViewController {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("MSM5xEmu.png")
        try? data.write(to: url, options: .atomic)
        let controller = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        controller.completionWithItemsHandler = { _, completed, _, _ in
            if completed { UIAccessibility.post(notification: .announcement, argument: savedMessage) }
        }
        return controller
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
