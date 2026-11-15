import Foundation
import Darwin
import CoreGraphics

indirect enum JSON: Codable, Sendable {
    case object([String: JSON]), array([JSON]), string(String), number(Double), bool(Bool), null
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([JSON].self) { self = .array(v) }
        else { self = .object(try c.decode([String: JSON].self)) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .object(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .bool(let v): try c.encode(v)
        case .null: try c.encodeNil()
        }
    }
    subscript(_ key: String) -> JSON { object[key] ?? .null }
    var object: [String: JSON] { if case .object(let v) = self { return v }; return [:] }
    var array: [JSON] { if case .array(let v) = self { return v }; return [] }
    var string: String { if case .string(let v) = self { return v }; return "" }
    var text: String {
        switch self { case .number(let n): return n.rounded() == n ? String(format: "%.0f", n) : String(n)
        case .bool(let v): return String(v); default: return string }
    }
    var int: Int { if case .number(let v) = self { return Int(v) }; return 0 }
    var bool: Bool { if case .bool(let v) = self { return v }; return false }
    var isNull: Bool { if case .null = self { return true }; return false }
    static func integer(_ n: Int) -> JSON { .number(Double(n)) }
}

struct BackendError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// All process I/O and JSON work runs on one serial queue per backend.
final class Backend: @unchecked Sendable {
    private let queue = DispatchQueue(label: "emulator.backend", qos: .userInitiated)
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var buffered = Data()
    private var nextID = 0
    private var closed = false
    private var closeFinished = false
    private var closeWaiters: [CheckedContinuation<Void, Never>] = []
    #if DEBUG
    let trace = BackendTrace()
    #endif

    private func launch() throws {
        guard process == nil else { return }
        let env = ProcessInfo.processInfo.environment
        let binary = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
        let defaultRoot = Bundle.main.bundleURL.pathExtension == "app"
            ? Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent()
            : binary.deletingLastPathComponent().deletingLastPathComponent()
        let root = URL(fileURLWithPath: env["MSM5XXX_BUNDLE"] ?? defaultRoot.path)
        let bundled = root.appendingPathComponent("python/bin/python3").path
        let alternative = root.appendingPathComponent("python/python3").path
        let python = env["MSM5XXX_PYTHON"] ?? ([bundled, alternative].first { FileManager.default.isExecutableFile(atPath: $0) } ?? "python3")
        let p = Process(), stdinPipe = Pipe(), stdoutPipe = Pipe(), stderrPipe = Pipe()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = [python, "-m", "msm5xxx_emulator.backend", "--qemu", env["MSM5XXX_QEMU"] ?? root.appendingPathComponent("bin/qemu-system-arm").path]
        var environment = env
        environment["PYTHONPATH"] = root.appendingPathComponent("src").path
        environment["PYTHONUNBUFFERED"] = "1"
        environment["LC_MESSAGES"] = Locale.preferredLanguages.first?.hasPrefix("ko") == true ? "ko_KR.UTF-8" : "en_US.UTF-8"
        p.environment = environment
        p.standardInput = stdinPipe; p.standardOutput = stdoutPipe; p.standardError = stderrPipe
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil }
            else { try? FileHandle.standardError.write(contentsOf: data) }
        }
        try p.run()
        process = p; input = stdinPipe.fileHandleForWriting; output = stdoutPipe.fileHandleForReading
    }

    func call(_ method: String, _ params: [String: JSON] = [:]) async throws -> JSON {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    guard !self.closed else { throw BackendError(message: L("backend_closed")) }
                    try self.launch()
                    self.nextID += 1
                    let id = self.nextID
                    let request = JSON.object(["id": .integer(id), "method": .string(method), "params": .object(params)])
                    var data = try JSONEncoder().encode(request); data.append(10)
                    try self.input!.write(contentsOf: data)
                    #if DEBUG
                    self.trace.append(method, params)
                    #endif
                    while self.buffered.firstIndex(of: 10) == nil {
                        let part = self.output!.availableData
                        guard !part.isEmpty else { throw BackendError(message: L("backend_closed")) }
                        self.buffered.append(part)
                        guard self.buffered.count <= 32 * 1024 * 1024 else { throw BackendError(message: L("invalid_reply")) }
                    }
                    let end = self.buffered.firstIndex(of: 10)!
                    let line = self.buffered.prefix(upTo: end)
                    let reply = try JSONDecoder().decode(JSON.self, from: line)
                    self.buffered.removeSubrange(...end)
                    guard reply["id"].int == id else { throw BackendError(message: L("invalid_reply")) }
                    if !reply["error"].isNull { throw BackendError(message: reply["error"]["message"].string) }
                    continuation.resume(returning: reply["result"])
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

    func close() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async {
                if self.closeFinished { continuation.resume(); return }
                self.closeWaiters.append(continuation)
                guard !self.closed else { return }
                self.closed = true
                try? self.input?.close(); self.input = nil
                let process = self.process
                DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
                    if process?.isRunning == true { process?.terminate()
                        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
                            if let process, process.isRunning { kill(process.processIdentifier, SIGKILL) }
                        }
                    }
                }
                DispatchQueue.global().async {
                    process?.waitUntilExit()
                    self.queue.async {
                        self.closeFinished = true
                        let waiters = self.closeWaiters; self.closeWaiters.removeAll()
                        for waiter in waiters { waiter.resume() }
                    }
                }
            }
        }
    }
}

struct LCDFrame: @unchecked Sendable {
    let width: Int, height: Int, image: CGImage
    static func decode(_ value: JSON) -> LCDFrame? {
        let w = value["width"].int, h = value["height"].int
        guard w > 0, h > 0, w <= 2048, h <= 2048,
              let data = Data(base64Encoded: value["rgb"].string), data.count == w * h * 3,
              let provider = CGDataProvider(data: data as CFData),
              let image = CGImage(width: w, height: h, bitsPerComponent: 8, bitsPerPixel: 24,
                                  bytesPerRow: w * 3, space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGBitmapInfo(rawValue: 0), provider: provider,
                                  decode: nil, shouldInterpolate: false, intent: .defaultIntent) else { return nil }
        return LCDFrame(width: w, height: h, image: image)
    }
}

#if DEBUG
final class BackendTrace: @unchecked Sendable {
    struct Event { let method: String; let params: [String: JSON]; let time: TimeInterval }
    private let lock = NSLock()
    private var events: [Event] = []
    func append(_ method: String, _ params: [String: JSON]) {
        // Retain input events only; display polling must not grow this log.
        guard method == "session.key" else { return }
        lock.lock(); defer { lock.unlock() }
        if events.count >= 512 { events.removeFirst(256) }
        events.append(Event(method: method, params: params, time: ProcessInfo.processInfo.systemUptime))
    }
    var snapshot: [Event] { lock.lock(); defer { lock.unlock() }; return events }
}
#endif
