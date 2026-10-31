import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var engine = QEMUEngine()
    @State private var firmware: URL?
    @State private var importing = false
    @State private var message = ""
    @State private var jit = QEMUEngine.jitAvailable
    @State private var showingSettings = false
    // Same settings and defaults as Android's settings dialog.
    @AppStorage("persistent_state") private var persistentState = true
    @AppStorage("experimental_rex") private var experimentalRex = false
    @AppStorage("virtual_network") private var virtualNetwork = false

    // Same order, labels and guest bits as Android's KEY_LAYOUT; volume keys sit in the side column.
    private static let keypad: [[(String, Int)]] = [
        [("Menu", 0), ("▲", 1), ("Cancel", 2)], [("◀", 4), ("OK", 5), ("▶", 6)],
        [("Call", 3), ("▼", 9), ("End", 7)], [("1", 11), ("2", 12), ("3", 13)],
        [("4", 14), ("5", 15), ("6", 16)], [("7", 17), ("8", 18), ("9", 19)],
        [("*", 20), ("0", 21), ("#", 22)],
    ]

    var body: some View {
        VStack(spacing: 2) {
            ZStack {
                Color.black
                if let frame = engine.frame {
                    Image(decorative: frame, scale: 1).resizable().interpolation(.none)
                        .aspectRatio(contentMode: .fit)
                } else {
                    Text(firmware?.lastPathComponent ?? "No firmware").foregroundColor(.gray)
                }
            }
            .frame(maxHeight: .infinity)
            .accessibilityLabel("Phone display")

            GeometryReader { geometry in
                HStack(spacing: 2) {
                    VStack(spacing: 2) {
                        key("Vol+", 10).frame(height: 40)
                        key("Vol-", 8).frame(height: 40)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(firmware?.lastPathComponent ?? "No firmware")
                            Text(engine.status).foregroundColor(.gray)
                            Text(jit ? "JIT (TCG)" : "No JIT (TCI)").foregroundColor(.gray)
                            if !message.isEmpty { Text(message).foregroundColor(.gray) }
                        }
                        .font(.system(size: 10)).foregroundColor(.white).lineLimit(3)
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                        Menu {
                            // QEMU runs once per app process; after Stop, picks and settings apply on relaunch.
                            Button("Choose firmware") { importing = true }.disabled(engine.running)
                            Button("Settings") { showingSettings = true }.disabled(engine.running)
                            if engine.running {
                                Button("Stop") { engine.stop() }
                            } else if engine.used {
                                Button("Relaunch app to run again") {}.disabled(true)
                            } else {
                                Button("Run") { run() }.disabled(firmware == nil)
                            }
                        } label: {
                            Text("⋮").font(.title2).foregroundColor(.white)
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                                .background(Color(white: 0.33)).cornerRadius(4)
                        }
                        .frame(height: 40)
                        .accessibilityLabel("More actions")
                    }
                    .frame(width: geometry.size.width / 3)
                    VStack(spacing: 2) {
                        ForEach(0..<Self.keypad.count, id: \.self) { row in
                            HStack(spacing: 2) {
                                ForEach(0..<3, id: \.self) { column in
                                    let (label, bit) = Self.keypad[row][column]
                                    key(label, bit)
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
        .sheet(isPresented: $showingSettings) {
            NavigationView {
                Form {
                    Toggle("Persistent device state (firmware SHA-isolated)", isOn: $persistentState)
                    Toggle("Experimental static REX controller", isOn: $experimentalRex)
                    Toggle("Virtual network (calls unavailable)", isOn: $virtualNetwork)
                }
                .navigationTitle("Settings")
                .toolbar { Button("Done") { showingSettings = false } }
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            switch result {
            case .success(let url): importFirmware(url)
            case .failure(let error): message = error.localizedDescription
            }
        }
    }

    private func run() {
        guard let firmware = firmware else { return }
        engine.start(firmware, persistentState: persistentState, experimentalRex: experimentalRex,
                     virtualNetwork: virtualNetwork)
    }

    private func key(_ label: String, _ bit: Int) -> some View {
        PhoneKey(label: label, enabled: engine.running && engine.inputBits.contains(bit),
                 transition: { engine.key(bit, pressed: $0) })
    }

    /// Reuse a firmware already in Application Support/firmware (imported earlier or copied in over
    /// SSH); an `autorun` file next to that folder starts it without touching the screen.
    private func pickStoredFirmware() {
        guard firmware == nil, !engine.used,
              let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first,
              let names = try? FileManager.default.contentsOfDirectory(atPath: support.appendingPathComponent("firmware").path),
              let name = names.filter({ !$0.hasPrefix(".") }).sorted().first else { return }
        firmware = support.appendingPathComponent("firmware").appendingPathComponent(name)
        if FileManager.default.fileExists(atPath: support.appendingPathComponent("autorun").path) {
            NSLog("MSM5xEmu autorun %@", name)
            run()
        }
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
            // Keep one image so the next launch reuses exactly this pick.
            for old in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] {
                try? FileManager.default.removeItem(at: old)
            }
            try FileManager.default.copyItem(at: url, to: target)
            firmware = target
            message = "Imported \(target.lastPathComponent)"
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
