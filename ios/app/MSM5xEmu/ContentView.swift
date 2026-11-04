import SwiftUI
import UniformTypeIdentifiers
import CryptoKit

struct ContentView: View {
    @StateObject private var engine = QEMUEngine()
    @State private var firmware: URL?
    @State private var importing = false
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

    private func text(_ english: String) -> String {
        let korean = uiLanguage == "ko" || (uiLanguage == "auto" && Locale.preferredLanguages.first?.hasPrefix("ko") == true)
        let translations = [
            "Virtual network": "가상 통신망", "Start": "실행", "Stop emulator": "에뮬 종료",
            "Reboot emulator": "에뮬 재부팅", "Choose firmware…": "펌웨어 선택…",
            "Edit key input": "키 입력 편집", "Done editing": "편집 완료", "Time": "시간",
            "Display position": "보조 화면 표시 위치", "Above": "위", "Below": "아래",
            "Host time": "호스트 시간", "Set time…": "지정 시간…", "Settings…": "설정…",
            "Reopen the app to start the selected firmware.": "선택한 펌웨어를 실행하려면 앱을 다시 여세요.",
            "No firmware": "펌웨어 없음", "Phone display": "휴대전화 화면",
            "Close fold": "폴더 닫기", "Open fold": "폴더 열기",
            "Choose firmware": "펌웨어 선택", "Settings": "설정", "Capture": "화면 캡처",
            "Additional display": "보조 화면", "Stop": "중지", "Run": "실행",
            "Relaunch app to run again": "다시 실행하려면 앱을 재시작하세요",
            "More actions": "더보기", "Persistent device state": "기기 상태 저장",
            "Virtual network (calls unavailable)": "가상 통신망 (통화 미지원)",
            "Use device clock for network time": "통신망 시간에 기기 시계 사용",
            "Network start time": "통신망 시작 시간", "More…": "더보기…", "More": "더보기",
            "Experimental static REX controller": "실험적 정적 REX 컨트롤러", "Done": "완료",
            "Preview: colors and orientation unverified": "미리보기: 색상과 방향이 확인되지 않음",
            "UI language": "화면 언어", "Auto (System)": "자동 (시스템)",
            "Reboot unavailable — relaunch the app": "재부팅할 수 없음 — 앱을 다시 실행하세요",
            "Finish mapping": "매핑 완료", "Edit input mapping": "입력 매핑 편집",
            "Event code (blank restores automatic mapping)": "이벤트 코드 (비우면 자동 매핑)",
            "Event code": "이벤트 코드", "Save": "저장", "Invalid event code": "잘못된 이벤트 코드",
            "Input mapping rejected": "입력 매핑이 거부됨", "Input mapping": "입력 매핑", "Cancel": "취소",
            "Menu": "메뉴", "Call": "통화", "End": "종료", "Vol+": "볼륨+", "Vol-": "볼륨-",
            "Loading runtime": "실행 환경 불러오는 중", "Running (detector-admitted input only)": "실행 중",
            "Stopped. Relaunch app for another session.": "중지됨. 다시 실행하려면 앱을 재시작하세요.",
            "QEMU exited. Relaunch app for another session.": "종료됨. 다시 실행하려면 앱을 재시작하세요."
        ]
        return korean ? (translations[english] ?? english) : english
    }

    private func detailLabel(_ key: String) -> String {
        let korean = uiLanguage == "ko" || (uiLanguage == "auto" && Locale.preferredLanguages.first?.hasPrefix("ko") == true)
        let labels: [String: String] = korean ? ["model": "모델", "chipset": "칩셋", "width": "화면 너비", "height": "화면 높이", "board_revision": "Board revision 이름", "image_offset": "이미지 오프셋", "load_address": "로드 주소", "flash_size": "Flash 크기", "ram_base": "RAM 시작 주소", "ram_size": "RAM 크기", "ram_image_offset": "RAM image 오프셋", "ram_image_size": "RAM image 크기 (0=끔)", "entry": "진입점 오프셋", "framebuffer_address": "Framebuffer 주소 (빈 값=끔)", "framebuffer_stride": "Framebuffer stride bytes", "framebuffer_format": "Framebuffer pixel format", "board_revision_register": "Board revision 레지스터", "board_revision_value": "Board revision 값", "key_register": "키 레지스터", "key_active_low": "키 active-low", "rex_idle_address": "REX idle 함수", "rex_tick_address": "REX tick 함수", "rex_tick_ms": "REX tick 밀리초", "board_adc_value": "Board ADC 값", "flash_id_address": "Flash ID 함수", "flash_id_value": "Flash ID 값", "dmd_download_address": "DMD download 함수", "primary_flash_probe_address": "NOR probe 함수", "secondary_flash_address": "보조 NOR 주소 (0=끔)", "secondary_flash_size": "보조 NOR 크기", "secondary_flash_image": "보조 NOR image", "secondary_flash_state": "보조 NOR state", "secondary_flash_write_address": "보조 NOR write 함수", "flash_state": "Flash state", "nand_enabled": "NAND 사용", "nand_image": "NAND raw image", "nand_data_size": "NAND data 크기", "nand_page_size": "NAND page 크기", "nand_spare_size": "NAND spare 크기", "nand_pages_per_block": "NAND block당 pages", "nand_bus_width": "NAND bus bytes"] : ["model": "Model", "chipset": "Chipset", "width": "Screen Width", "height": "Screen Height", "board_revision": "Board Revision Name", "image_offset": "Image Offset", "load_address": "Load Address", "flash_size": "Flash Size", "ram_base": "RAM Base", "ram_size": "RAM Size", "ram_image_offset": "RAM Image Offset", "ram_image_size": "RAM Image Size (0=off)", "entry": "Entry Offset", "framebuffer_address": "Framebuffer Address (empty=off)", "framebuffer_stride": "Framebuffer stride bytes", "framebuffer_format": "Framebuffer pixel format", "board_revision_register": "Board Revision Register", "board_revision_value": "Board Revision Value", "key_register": "Key Register", "key_active_low": "Key Active-Low", "rex_idle_address": "REX Idle Function", "rex_tick_address": "REX Tick Function", "rex_tick_ms": "REX Tick Milliseconds", "board_adc_value": "Board ADC Value", "flash_id_address": "Flash ID Function", "flash_id_value": "Flash ID Value", "dmd_download_address": "DMD Download Function", "primary_flash_probe_address": "NOR Probe Function", "secondary_flash_address": "Secondary NOR Address (0=off)", "secondary_flash_size": "Secondary NOR Size", "secondary_flash_image": "Secondary NOR Image", "secondary_flash_state": "Secondary NOR State", "secondary_flash_write_address": "Secondary NOR Write Function", "flash_state": "Flash state", "nand_enabled": "Enable NAND", "nand_image": "NAND raw image", "nand_data_size": "NAND Data Size", "nand_page_size": "NAND Page Size", "nand_spare_size": "NAND Spare Size", "nand_pages_per_block": "NAND Pages per Block", "nand_bus_width": "NAND bus bytes"]
        return labels[key] ?? key
    }

    var body: some View {
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
            .accessibilityLabel(text("Phone display"))
            if !secondaryAbove { secondaryDisplay }

            GeometryReader { geometry in
                HStack(spacing: 2) {
                    VStack(spacing: 2) {
                        key(text("Vol+"), 10).frame(height: 40)
                        key(text("Vol-"), 8).frame(height: 40)
                        Button(text(engine.foldOpen ? "Close fold" : "Open fold")) { engine.toggleFold() }
                            .disabled(!engine.running || !engine.foldSupported)
                            .font(.system(size: 11)).frame(maxWidth: .infinity).frame(height: 40)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(text(engine.status)).foregroundColor(.gray)
                            Text(engine.metrics).foregroundColor(.gray)
                            if !message.isEmpty { Text(message).foregroundColor(.gray) }
                        }
                        .font(.system(size: 10)).foregroundColor(.white).lineLimit(3)
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                        if editingMapping {
                            Button(text("Done editing")) { editingMapping = false }
                                .frame(maxWidth: .infinity).frame(height: 40)
                        } else {
                            Menu {
                                Button {
                                    virtualNetwork.toggle()
                                    restartOnNextLaunchIfRunning()
                                } label: {
                                    if virtualNetwork { Label(text("Virtual network"), systemImage: "checkmark") }
                                    else { Text(text("Virtual network")) }
                                }
                                Button(text("Start")) { run() }.disabled(engine.running || engine.used || firmware == nil)
                                Button(text("Stop emulator")) { engine.stop() }.disabled(!engine.running)
                                Button(text("Reboot emulator")) { restartOnNextLaunchIfRunning() }.disabled(!engine.running)
                                Button(text("Choose firmware…")) { importing = true }
                                Button(text("Capture")) { showingCapture = true }.disabled(engine.frame == nil)
                                Button(text("Edit key input")) { editingMapping = true }.disabled(!engine.running)
                                Menu(text("Time")) {
                                    Button {
                                        networkHostTime = true
                                        networkStartTimeEnabled = false
                                        if virtualNetwork { restartOnNextLaunchIfRunning() }
                                    } label: {
                                        if networkHostTime { Label(text("Host time"), systemImage: "checkmark") }
                                        else { Text(text("Host time")) }
                                    }
                                    Button {
                                        timeDraft = Date(timeIntervalSince1970: networkStartTime)
                                        showingTime = true
                                    } label: {
                                        if !networkHostTime { Label(text("Set time…"), systemImage: "checkmark") }
                                        else { Text(text("Set time…")) }
                                    }
                                }
                                Button(text("Settings…")) { showingSettings = true }
                            } label: {
                                Text("•••").font(.title2).foregroundColor(.white)
                                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                                    .background(Color(white: 0.33)).cornerRadius(4)
                            }
                            .frame(height: 40)
                            .accessibilityLabel(text("More actions"))
                        }
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
            .frame(height: 280)
        }
        .padding(2)
        .background(Color(white: 0.07).ignoresSafeArea())
        .onAppear(perform: pickStoredFirmware)
        .onReceive(Timer.publish(every: 0.1, on: .main, in: .common).autoconnect()) { _ in
            engine.refresh()
        }
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
                CaptureShare(data: data)
            }
        }
        .sheet(isPresented: $showingSettings) {
            NavigationView {
                Form {
                    Toggle(text("Persistent device state"), isOn: $persistentState)
                    Picker(text("UI language"), selection: $uiLanguage) {
                        Text(text("Auto (System)")).tag("auto")
                        Text("한국어").tag("ko")
                        Text("English").tag("en")
                    }
                    Toggle(text("Additional display"), isOn: $showingSecondary)
                        .disabled(!engine.secondaryAvailable)
                    Picker(text("Display position"), selection: $secondaryAbove) {
                        Text(text("Above")).tag(true)
                        Text(text("Below")).tag(false)
                    }
                    NavigationLink(text("More…")) {
                        Form {
                            Toggle(text("Experimental static REX controller"), isOn: $experimentalRex)
                            ForEach(Self.detailFields, id: \.self) { name in
                                TextField(detailLabel(name), text: Binding(
                                    get: { detailedValues[name] ?? "" },
                                    set: { value in
                                        detailedValues[name] = value.isEmpty ? nil : value
                                        UserDefaults.standard.set(detailedValues, forKey: "details.\(firmwareIdentity)")
                                    }))
                                    .autocapitalization(.none)
                            }
                        }.navigationTitle(text("More"))
                    }
                }
                .navigationTitle(text("Settings"))
                .toolbar { Button(text("Done")) { showingSettings = false } }
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            switch result {
            case .success(let url): importFirmware(url)
            case .failure(let error): message = error.localizedDescription
            }
        }
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
        } else {
            PhoneKey(label: label, enabled: engine.running && (engine.inputBits.contains(bit) || UserDefaults.standard.object(forKey: "keymap.\(engine.identity).\(bit)") != nil),
                     transition: { engine.key(bit, pressed: $0) })
        }
    }

    /// Reuse a firmware already in Application Support/firmware (imported earlier or copied in over
    /// SSH); an `autorun` file next to that folder starts it without touching the screen.
    private func pickStoredFirmware() {
        guard firmware == nil, !engine.used,
              let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first,
              let names = try? FileManager.default.contentsOfDirectory(atPath: support.appendingPathComponent("firmware").path),
              let name = names.filter({ !$0.hasPrefix(".") }).sorted().first else { return }
        firmware = support.appendingPathComponent("firmware").appendingPathComponent(name)
        loadDetailedSettings()
        if UserDefaults.standard.bool(forKey: "pending_boot") {
            UserDefaults.standard.removeObject(forKey: "pending_boot")
            run()
        } else if FileManager.default.fileExists(atPath: support.appendingPathComponent("autorun").path) {
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

    /// Copy the picked image into the app container; the original is never modified.
    private func importFirmware(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let dir = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                  appropriateFor: nil, create: true)
                .appendingPathComponent("firmware", isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let target = dir.appendingPathComponent(url.lastPathComponent)
            // Stop the active session before replacing its selected image.
            if engine.running { restartOnNextLaunchIfRunning() }
            // Keep one image so the next launch reuses exactly this pick.
            for old in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] {
                try? FileManager.default.removeItem(at: old)
            }
            try FileManager.default.copyItem(at: url, to: target)
            firmware = target
            loadDetailedSettings()
            if engine.used {
                UserDefaults.standard.set(true, forKey: "pending_boot")
                message = text("Reopen the app to start the selected firmware.")
            } else {
                run()
            }
            if !engine.used { message = "Imported \(target.lastPathComponent)" }
        } catch {
            message = error.localizedDescription
        }
    }
}


private struct PhoneKey: View {
    let label: String
    let enabled: Bool
    let transition: (Bool) -> Void
    @State private var pressed = false
    var body: some View {
        Text(label)
            .font(.system(size: 13))
            .foregroundColor(enabled ? .white : .gray)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(white: !enabled ? 0.18 : pressed ? 0.44 : 0.33))
            .cornerRadius(4)
            .contentShape(Rectangle())
            .gesture(DragGesture(minimumDistance: 0)
                .onChanged { _ in
                    if enabled && !pressed { pressed = true; transition(true) }
                }
                .onEnded { _ in
                    if pressed { pressed = false; transition(false) }
                })
            .accessibilityAddTraits(.isButton)
            .accessibilityAction {
                if enabled { transition(true); transition(false) }
            }
            .onDisappear { if pressed { pressed = false; transition(false) } }
    }
}

private struct CaptureShare: UIViewControllerRepresentable {
    let data: Data
    func makeUIViewController(context: Context) -> UIActivityViewController {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("MSM5xEmu.png")
        try? data.write(to: url, options: .atomic)
        return UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
