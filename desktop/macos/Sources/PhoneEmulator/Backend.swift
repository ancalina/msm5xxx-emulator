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
    private var qemuLaunchPath: String?
    private var closed = false
    private let lifecycleLock = NSLock()
    private var watchedProcess: Process?
    private var shutdownDeadline: TimeInterval?
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
            ? Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/runtime")
            : binary.deletingLastPathComponent().deletingLastPathComponent()
        let root = URL(fileURLWithPath: env["MSM5XXX_BUNDLE"] ?? defaultRoot.path)
        let bundled = root.appendingPathComponent("python/bin/python3").path
        let alternative = root.appendingPathComponent("python/python3").path
        let python = env["MSM5XXX_PYTHON"] ?? ([bundled, alternative].first { FileManager.default.isExecutableFile(atPath: $0) } ?? "python3")
        let p = Process(), stdinPipe = Pipe(), stdoutPipe = Pipe(), stderrPipe = Pipe()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        let qemu = env["MSM5XXX_QEMU"] ?? root.appendingPathComponent("bin/qemu-system-arm").path
        qemuLaunchPath = qemu
        p.arguments = [python, "-m", "msm5xxx_emulator.backend", "--qemu", qemu]
        var environment = env
        environment["PYTHONPATH"] = root.appendingPathComponent("src").path
        environment["PYTHONUNBUFFERED"] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONNOUSERSITE"] = "1"
        if environment["MSM5XXX_STATE_DIR"] == nil {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            var testState: String? = nil
            #if DEBUG
            testState = Bundle.main.object(forInfoDictionaryKey: "MSM5xxxUpdateTestStateDirectory") as? String
            #endif
            environment["MSM5XXX_STATE_DIR"] = testState ?? support.appendingPathComponent("MSM5xxx").path
        }
        environment["LC_MESSAGES"] = Locale.preferredLanguages.first?.hasPrefix("ko") == true ? "ko_KR.UTF-8" : "en_US.UTF-8"
        p.environment = environment
        p.standardInput = stdinPipe; p.standardOutput = stdoutPipe; p.standardError = stderrPipe
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil }
            else { try? FileHandle.standardError.write(contentsOf: data) }
        }
        for handle in [stdinPipe.fileHandleForWriting, stdoutPipe.fileHandleForReading] {
            let flags = fcntl(handle.fileDescriptor, F_GETFL)
            guard flags >= 0, fcntl(handle.fileDescriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        guard shutdownDeadline == nil else { throw BackendError(message: L("backend_closed")) }
        try p.run()
        watchedProcess = p
        process = p; input = stdinPipe.fileHandleForWriting; output = stdoutPipe.fileHandleForReading
    }

    func beginShutdownDeadline() {
        lifecycleLock.lock()
        guard shutdownDeadline == nil else { lifecycleLock.unlock(); return }
        shutdownDeadline = ProcessInfo.processInfo.systemUptime + 10
        let snapshot = watchedProcess
        lifecycleLock.unlock()
        guard let snapshot else { return }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 10) {
            if snapshot.isRunning { snapshot.terminate() }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 1) {
                if snapshot.isRunning { kill(snapshot.processIdentifier, SIGKILL) }
            }
        }
    }

    private func checkShutdownDeadline() throws {
        lifecycleLock.lock()
        let deadline = shutdownDeadline
        lifecycleLock.unlock()
        if let deadline, ProcessInfo.processInfo.systemUptime >= deadline {
            throw BackendError(message: L("backend_shutdown_timeout"))
        }
    }

    private func waitForIO(_ descriptor: Int32, events: Int16) throws {
        while true {
            try checkShutdownDeadline()
            var item = pollfd(fd: descriptor, events: events, revents: 0)
            let ready = poll(&item, 1, 250)
            if ready < 0 {
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            if ready == 0 { continue }
            if item.revents & Int16(POLLNVAL | POLLERR) != 0 {
                throw BackendError(message: L("backend_closed"))
            }
            if item.revents & (events | Int16(POLLHUP)) != 0 { return }
        }
    }

    private func writeRequest(_ data: Data) throws {
        let descriptor = input!.fileDescriptor
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                try waitForIO(descriptor, events: Int16(POLLOUT))
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count > 0 { offset += count; continue }
                if count < 0, errno == EINTR || errno == EAGAIN { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
    }

    private func readResponsePart() throws -> Data {
        let descriptor = output!.fileDescriptor
        var bytes = [UInt8](repeating: 0, count: 65536)
        while true {
            try waitForIO(descriptor, events: Int16(POLLIN))
            let count = bytes.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress!, $0.count) }
            if count > 0 { return Data(bytes.prefix(count)) }
            if count < 0, errno == EINTR || errno == EAGAIN { continue }
            if count == 0 { throw BackendError(message: L("backend_closed")) }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    func call(_ method: String, _ params: [String: JSON] = [:]) async throws -> JSON {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    guard !self.closed else { throw BackendError(message: L("backend_closed")) }
                    try self.launch()
                    try self.checkShutdownDeadline()
                    if method == "session.start", let path = self.qemuLaunchPath,
                       path.hasPrefix("/"), !FileManager.default.fileExists(atPath: path) {
                        throw BackendError(message: L("runtime_executable_missing"))
                    }
                    self.nextID += 1
                    let id = self.nextID
                    let request = JSON.object(["id": .integer(id), "method": .string(method), "params": .object(params)])
                    var data = try JSONEncoder().encode(request); data.append(10)
                    try self.writeRequest(data)
                    #if DEBUG
                    self.trace.append(method, params)
                    #endif
                    while self.buffered.firstIndex(of: 10) == nil {
                        let part = try self.readResponsePart()
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
        beginShutdownDeadline()
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async {
                if self.closeFinished { continuation.resume(); return }
                self.closeWaiters.append(continuation)
                guard !self.closed else { return }
                self.closed = true
                try? self.input?.close(); self.input = nil
                let process = self.process
                DispatchQueue.global().async {
                    process?.waitUntilExit()
                    self.queue.async {
                        try? self.output?.close(); self.output = nil
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
