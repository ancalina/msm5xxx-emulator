import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var engine = QEMUEngine()
    @State private var firmware: URL?
    @State private var importing = false
    @State private var message = ""
    @State private var jit = QEMUEngine.jitAvailable

    private let keys = [["Soft1", "Up", "Soft2"], ["Left", "OK", "Right"], ["Send", "Down", "End"],
                        ["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["*", "0", "#"]]
    private let bits = ["Soft1": 0, "Up": 1, "Soft2": 2, "Left": 4, "OK": 5, "Right": 6,
                        "Send": 3, "Down": 9, "End": 7, "1": 11, "2": 12, "3": 13,
                        "4": 14, "5": 15, "6": 16, "7": 17, "8": 18, "9": 19,
                        "*": 20, "0": 21, "#": 22]

    var body: some View {
        VStack(spacing: 12) {
            Group {
                if let frame = engine.frame {
                    Image(decorative: frame, scale: 1).resizable().interpolation(.none)
                        .aspectRatio(contentMode: .fit)
                } else {
                    Rectangle().fill(Color.black).aspectRatio(128.0 / 160.0, contentMode: .fit)
                        .overlay(Text(firmware?.lastPathComponent ?? "No firmware").foregroundColor(.gray).padding())
                }
            }
            .frame(maxHeight: 260)
            .accessibilityLabel("Phone display")

            VStack(spacing: 6) {
                ForEach(keys, id: \.self) { row in
                    HStack(spacing: 6) {
                        ForEach(row, id: \.self) { key in
                            PhoneKey(label: key, enabled: engine.running && engine.inputBits.contains(bits[key]!),
                                     transition: { engine.key(bits[key]!, pressed: $0) })
                        }
                    }
                }
            }

            Button("Choose firmware") { importing = true }
                .buttonStyle(.borderedProminent)
                .disabled(engine.used)
            HStack {
                Button("Run") { if let firmware = firmware { engine.start(firmware) } }
                    .disabled(firmware == nil || engine.used)
                Button("Stop") { engine.stop() }.disabled(!engine.running)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(engine.status)
                Text(jit ? "JIT: available (TCG)" : "JIT: unavailable (TCI only)")
                if !message.isEmpty { Text(message) }
            }
            .font(.footnote)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding()
        .onReceive(Timer.publish(every: 0.1, on: .main, in: .common).autoconnect()) { _ in
            engine.refresh()
        }
        // JIT can be granted while running (TrollStore "Open with JIT", Dopamine); poll cheaply.
        .onReceive(Timer.publish(every: 2, on: .main, in: .common).autoconnect()) { _ in
            let now = QEMUEngine.jitAvailable
            if now != jit || QEMUEngine.codeSigningFlags & 0x1000_0000 != 0 && !now {
                jit = now
                NSLog("MSM5xEmu JIT %@ (cs flags 0x%08x)", now ? "available" : "unavailable", QEMUEngine.codeSigningFlags)
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            switch result {
            case .success(let url): importFirmware(url)
            case .failure(let error): message = error.localizedDescription
            }
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
            try? FileManager.default.removeItem(at: target)
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
            .frame(maxWidth: .infinity, minHeight: 36)
            .background(Color.secondary.opacity(pressed ? 0.4 : 0.15))
            .cornerRadius(6)
            .opacity(enabled ? 1 : 0.4)
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
