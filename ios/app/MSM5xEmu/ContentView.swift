import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    private let engine = QEMUEngine()
    @State private var firmware: URL?
    @State private var importing = false
    @State private var message = ""
    @State private var lastKey = ""
    @State private var jit = QEMUEngine.jitAvailable

    private let keys = [["Soft1", "Up", "Soft2"], ["Left", "OK", "Right"], ["Send", "Down", "End"],
                        ["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["*", "0", "#"]]

    var body: some View {
        VStack(spacing: 12) {
            // LCD placeholder; frames will come from the transport once the guest runs.
            Rectangle()
                .fill(Color.black)
                .aspectRatio(128.0 / 160.0, contentMode: .fit)
                .frame(maxHeight: 260)
                .overlay(Text(firmware?.lastPathComponent ?? "No firmware").foregroundColor(.gray).padding())
                .accessibilityLabel("Phone display")

            VStack(spacing: 6) {
                ForEach(keys, id: \.self) { row in
                    HStack(spacing: 6) {
                        ForEach(row, id: \.self) { key in
                            Button(key) { lastKey = key }
                                .frame(maxWidth: .infinity, minHeight: 36)
                                .background(Color.secondary.opacity(0.15))
                                .cornerRadius(6)
                        }
                    }
                }
            }

            Button("Choose firmware") { importing = true }
                .buttonStyle(.borderedProminent)

            VStack(alignment: .leading, spacing: 2) {
                Text(engine.status)
                Text(jit ? "JIT: available (TCG)" : "JIT: unavailable (TCI only)")
                if !lastKey.isEmpty { Text("Key: \(lastKey)") }
                if !message.isEmpty { Text(message) }
            }
            .font(.footnote)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding()
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
