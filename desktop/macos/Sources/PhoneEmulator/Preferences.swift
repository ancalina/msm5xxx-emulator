import AppKit
import Combine

enum AppIconStyle: String, Codable, CaseIterable { case full, simple }
enum DockSide: String, Codable { case left, right }

/// Frontend-only preferences; emulator settings continue to use the backend protocol.
@MainActor final class AppPreferences: ObservableObject {
    static let shared = AppPreferences()
    private struct Document: Codable {
        var icon: AppIconStyle = .full
        var docking: [String: DockSide] = [:]
    }
    @Published private(set) var iconStyle: AppIconStyle
    private var document: Document
    private let file: URL
    private let writes = DispatchQueue(label: "desktop.preferences")
    private init() {
        let root = ProcessInfo.processInfo.environment["MSM5XXX_STATE_DIR"].map { URL(fileURLWithPath: $0) }
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".msm5xxx-emulator")
        file = root.appendingPathComponent("desktop-macos.json")
        document = (try? Data(contentsOf: file)).flatMap { try? JSONDecoder().decode(Document.self, from: $0) } ?? Document()
        iconStyle = document.icon
    }
    func applyIcon() {
        if iconStyle == .full { NSApp.applicationIconImage = nil; return }
        let name = "AppIconSimple"
        let url = Bundle.main.url(forResource: name, withExtension: "icns") ?? applicationResources.url(forResource: name, withExtension: "icns")
        if let url, let image = NSImage(contentsOf: url) { NSApp.applicationIconImage = image }
    }
    func setIcon(_ style: AppIconStyle) async throws {
        let old = document.icon
        document.icon = style
        do { try await save() } catch { document.icon = old; throw error }
        iconStyle = style; applyIcon()
    }
    func side(for firmware: String) -> DockSide? { document.docking[firmware] }
    func setSide(_ side: DockSide?, for firmware: String) async throws {
        document.docking[firmware] = side
        try await save()
    }
    private func save() async throws {
        let data = try JSONEncoder().encode(document), file = self.file
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            writes.async {
                do {
                    try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
                    try data.write(to: file, options: .atomic)
                    continuation.resume()
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
}
