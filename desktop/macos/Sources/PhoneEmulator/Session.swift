import SwiftUI
import AppKit
import UniformTypeIdentifiers
import ImageIO

@MainActor final class DisplayModel: ObservableObject {
    @Published var frame: LCDFrame?
}

private struct KeyPressReceipt: Sendable { let acceptedAt: TimeInterval }

@MainActor final class SessionModel: ObservableObject {
    let backend = Backend()
    let firmware: Firmware
    let display = DisplayModel(), secondary = DisplayModel()
    @Published var running = false
    @Published var busy = false
    @Published var error = ""
    @Published var title: String
    @Published var chipset = ""
    @Published var lcdSize = CGSize(width: 128, height: 128)
    @Published var layout: JSON = .null
    @Published var keypad = KeypadMetrics(layout: .null)
    @Published var openingMinimum = CGSize.zero
    @Published var state: JSON = .null
    @Published var editing = false
    @Published var mapped: Set<Int> = []
    @Published var available: Set<Int> = []
    @Published var sheet: SessionSheet?
    @Published var secondaryStatus = ""
    var onGeometry: (() -> Void)?
    var onSecondary: (() -> Void)?
    var onTitle: (() -> Void)?
    var onStopped: (() -> Void)?
    var closed = false
    private var shutdownTask: Task<Void, Never>?
    private var opened = false
    @Published var exporting = false
    @Published var captureDocument: PNGDocument?
    var captureName = ""
    var captureDirectory: URL?
    private var keyboardHeld: [String: Int] = [:]
    #if DEBUG
    private(set) var keyboardObservations: [String] = []
    var capturePanel: NSSavePanel? { NSApp.windows.compactMap { $0 as? NSSavePanel }.first { $0.isVisible && !($0 is NSOpenPanel) } }
    #endif
    private var frames: Task<Void, Never>?
    private var states: Task<Void, Never>?
    private var held: [Int: UUID] = [:]
    private var releasing: Set<Int> = []
    private var pressTasks: [Int: Task<KeyPressReceipt, Never>] = [:]
    private var pendingReleases: [Int: Task<Void, Never>] = [:]
    private var sequence = -1, secondarySequence = -1
    private var secondarySeen = false
    var hold: Double { max(0.001, Double(layout["key_hold_ms"].int) / 1000) }

    init(firmware: Firmware) { self.firmware = firmware; title = firmware.name }
    var subtitle: String {
        let network = state["virtual_cell"].isNull ? "" : L(state["virtual_cell"].string == "configured" ? "virtual_network_active" : "virtual_network_unavailable")
        return "\(chipset) · \(Int(lcdSize.width))×\(Int(lcdSize.height))" + (network.isEmpty ? "" : " · \(network)")
    }
    func reloadLayout() async {
        do {
            layout = try await backend.call("ui.layout")
            keypad = KeypadMetrics(layout: layout)
            onGeometry?()
        } catch { self.error = error.localizedDescription }
    }
    func start() async {
        guard !busy, !closed, !running else { return }
        busy = true; error = ""
        defer { busy = false }
        do {
            if !opened {
                _ = try await backend.call("session.open", ["firmware": .string(firmware.id)])
                opened = true
            }
            await reloadLayout()
            let result = try await backend.call("session.start")
            guard !closed else { _ = try? await backend.call("session.stop"); return }
            title = result["title"].string; chipset = result["chipset"].string
            available = Set(result["native_keys"].array.map(\.int))
            mapped = []
            for key in layout["keys"].array {
                if !(try await backend.call("session.key_mapping", ["bit": key["bit"]])).isNull { mapped.insert(key["bit"].int) }
            }
            running = true; sequence = -1; secondarySequence = -1
            onTitle?(); beginPolling()
        } catch {
            self.error = error.localizedDescription
            if opened { _ = try? await backend.call("session.stop") }
            running = false; onStopped?()
        }
    }
    private func beginPolling() {
        frames?.cancel(); states?.cancel()
        frames = Task { [weak self] in
            while let self, !Task.isCancelled, self.running, !self.closed {
                let began = ProcessInfo.processInfo.systemUptime
                do {
                    let result = try await self.backend.call("session.frame", ["since": .integer(self.sequence), "secondary_since": .integer(self.secondarySequence)])
                    guard !Task.isCancelled else { return }
                    if !result["running"].bool { self.unexpectedStop(); return }
                    let pair = await Task.detached(priority: .userInitiated) {
                        (LCDFrame.decode(result), LCDFrame.decode(result["secondary"]))
                    }.value
                    guard !Task.isCancelled, self.running, !self.closed else { return }
                    if result["rgb"].isNull || pair.0 != nil { self.sequence = result["seq"].int }
                    if let frame = pair.0 {
                        self.display.frame = frame
                        let size = CGSize(width: CGFloat(frame.width), height: CGFloat(frame.height))
                        if self.lcdSize != size { self.lcdSize = size; self.onGeometry?(); self.onTitle?() }
                    }
                    let sub = result["secondary"]
                    if !sub.isNull {
                        if let frame = pair.1 { self.secondary.frame = frame; self.secondarySequence = sub["seq"].int }
                        let enabled = sub["enabled"].isNull ? L("power_unknown") : L(sub["enabled"].bool ? "power_on" : "power_off")
                        let note = sub["preview"].bool ? L("secondary_preview") : L("secondary_unknown")
                        if let frame = self.secondary.frame {
                            self.secondaryStatus = "\(enabled) · \(frame.width)×\(frame.height) · \(note)"
                            if !self.secondarySeen { self.secondarySeen = true; self.onSecondary?() }
                        }
                    }
                } catch { if !Task.isCancelled { self.error = error.localizedDescription; self.unexpectedStop() }; return }
                let delay = max(0, 1.0 / 30 - (ProcessInfo.processInfo.systemUptime - began))
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
        }
        states = Task { [weak self] in
            while let self, !Task.isCancelled, self.running, !self.closed {
                let began = ProcessInfo.processInfo.systemUptime
                do {
                    let value = try await self.backend.call("session.state")
                    guard !Task.isCancelled else { return }
                    self.state = value
                    if !value["input_error"].isNull { self.error = value["input_error"].string }
                    if !value["running"].bool { self.unexpectedStop(); return }
                    self.onTitle?()
                } catch { if !Task.isCancelled { self.error = error.localizedDescription; self.unexpectedStop() }; return }
                let delay = max(0, 0.1 - (ProcessInfo.processInfo.systemUptime - began))
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
        }
    }
    private func unexpectedStop() {
        running = false; frames?.cancel(); states?.cancel()
        if error.isEmpty { error = L("backend_stopped") }
        state = .null; display.frame = nil; onStopped?()
        // Stop also releases the transport so Power can retry the session.
        Task { _ = try? await backend.call("session.stop") }
    }
    func stop() async {
        guard !busy else { return }
        busy = true
        frames?.cancel(); states?.cancel()
        releaseKeyboard()
        await releaseAllAndWait()
        do { if opened { _ = try await backend.call("session.stop") } }
        catch { self.error = error.localizedDescription }
        running = false; state = .null; display.frame = nil; secondary.frame = nil
        secondarySequence = -1; secondarySeen = false; onStopped?(); busy = false
    }
    func reboot() async { await stop(); if !closed { await start() } }
    func close() async {
        if let shutdownTask { await shutdownTask.value; return }
        exporting = false
        closed = true
        frames?.cancel(); states?.cancel()
        let task = Task { @MainActor in
            while busy { try? await Task.sleep(nanoseconds: 20_000_000) }
            await stop(); await backend.close()
        }
        shutdownTask = task
        await task.value
    }
    func quiesceForApplicationQuit() {
        closed = true
        exporting = false
        frames?.cancel(); states?.cancel()
        for task in pendingReleases.values { task.cancel() }
        for task in pressTasks.values { task.cancel() }
        held.removeAll(); releasing.removeAll()
        running = false; onStopped?()
    }
    func enabled(_ bit: Int) -> Bool { running && (available.contains(bit) || mapped.contains(bit)) }
    func press(_ bit: Int) {
        guard enabled(bit), held[bit] == nil else { return }
        let token = UUID(); held[bit] = token
        let backend = self.backend
        pressTasks[bit] = Task.detached(priority: .userInitiated) { [weak self] in
            var message: String?
            do {
                let accepted = try await backend.call("session.key", ["bit": .integer(bit), "pressed": .bool(true)])
                if !accepted.bool { message = L("mapping_rejected") }
            } catch { message = error.localizedDescription }
            let receipt = KeyPressReceipt(acceptedAt: ProcessInfo.processInfo.systemUptime)
            if let message {
                Task { @MainActor [weak self] in
                    if let self, !self.closed { self.error = message }
                }
            }
            return receipt
        }
    }
    func release(_ bit: Int) {
        guard let token = held[bit], let press = pressTasks[bit], !releasing.contains(bit) else { return }
        releasing.insert(bit)
        let backend = self.backend, minimumHold = hold
        pendingReleases[bit] = Task.detached(priority: .userInitiated) { [weak self] in
            let receipt = await press.value
            let remaining = max(0, minimumHold - (ProcessInfo.processInfo.systemUptime - receipt.acceptedAt))
            try? await Task.sleep(nanoseconds: UInt64(remaining * 1_000_000_000))
            guard !Task.isCancelled else { return }
            _ = try? await backend.call("session.key", ["bit": .integer(bit), "pressed": .bool(false)])
            await self?.finishedRelease(bit, token: token)
        }
    }
    private func finishedRelease(_ bit: Int, token: UUID) {
        guard held[bit] == token else { return }
        held.removeValue(forKey: bit); releasing.remove(bit)
        pendingReleases[bit] = nil; pressTasks[bit] = nil
    }
    func tap(_ bit: Int) { press(bit); release(bit) }
    func releaseAll() { for bit in Array(held.keys) { release(bit) } }
    private func releaseAllAndWait() async {
        releaseAll()
        let tasks = Array(pendingReleases.values)
        for task in tasks { await task.value }
    }
    func action(_ method: String, _ params: [String: JSON] = [:]) async {
        do { _ = try await backend.call(method, params) } catch { self.error = error.localizedDescription }
    }
    func releaseKeyboard() {
        for bit in keyboardHeld.values { release(bit) }
        keyboardHeld.removeAll()
    }
    func handleKeyPress(_ event: KeyPress) -> KeyPress.Result {
        #if DEBUG
        if keyboardObservations.count >= 32 { keyboardObservations.removeFirst() }
        keyboardObservations.append("key=\(event.key), chars=\(event.characters), phase=\(event.phase), modifiers=\(event.modifiers)")
        #endif
        let symbol: String
        switch event.key {
        case .upArrow: symbol = "Up"
        case .downArrow: symbol = "Down"
        case .leftArrow: symbol = "Left"
        case .rightArrow: symbol = "Right"
        case .return: symbol = "Return"
        case .escape: symbol = "Escape"
        default: symbol = event.characters == "+" ? "plus" : event.characters == "-" ? "minus" : event.characters
        }
        return handleKeyboard(symbol, phase: event.phase, modifiers: event.modifiers)
    }
    func handleKeyboard(_ symbol: String, phase: KeyPress.Phases, modifiers: EventModifiers = []) -> KeyPress.Result {
        if phase == .up, let bit = keyboardHeld.removeValue(forKey: symbol) { release(bit); return .handled }
        guard modifiers.intersection([.command, .control, .option]).isEmpty, sheet == nil, !editing,
              let bit = layout["keyboard"].object[symbol]?.int, enabled(bit) else { return .ignored }
        if phase == .down, keyboardHeld[symbol] == nil { keyboardHeld[symbol] = bit; press(bit) }
        return .handled
    }
    func capture(directory: URL? = nil, filename: String? = nil) {
        guard !exporting, let frame = display.frame else { return }
        captureDirectory = directory; captureName = filename ?? "\(title).png"
        Task {
            let data = await Task.detached { () -> Data? in
                let data = NSMutableData()
                guard let destination = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil) else { return nil }
                CGImageDestinationAddImage(destination, frame.image, nil)
                return CGImageDestinationFinalize(destination) ? data as Data : nil
            }.value
            if let data { captureDocument = PNGDocument(data: data); exporting = true }
            else { error = L("capture_error") }
        }
    }
}

struct PNGDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.png] }
    var data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

enum SessionSheet: String, Identifiable {
    case info, time, mapping
    var id: String { rawValue }
}
