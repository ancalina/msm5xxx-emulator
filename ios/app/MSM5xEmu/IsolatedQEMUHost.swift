import Foundation
import ExtensionFoundation
import Darwin

@available(iOS 26.0, *)
extension AppExtensionPoint {
    @Definition
    static var qemuSession: AppExtensionPoint {
        Name("qemu-session")
        UserInterface(false)
    }
}

/// Each session owns a fresh process, including during asynchronous startup.
/// A timeout requests cancellation; only confirmed exit releases that ownership.
@available(iOS 26.0, *)
final class IsolatedQEMUHost: NSObject, QEMUProcessHost {
    private let lock = NSLock()
    private var session: Session?
    private var lastExit: NSNumber = -1

    func start(arguments: [String], error errorPointer: AutoreleasingUnsafeMutablePointer<NSError?>?) -> Bool {
        guard !arguments.isEmpty, arguments.count <= 4096,
              arguments.allSatisfy({ !$0.contains("\0") }) else {
            errorPointer?.pointee = Self.failure("Invalid QEMU arguments")
            return false
        }
        lock.lock()
        let previous = session
        lock.unlock()
        if let previous, !previous.isFinished {
            // A previous timed-out start may still be resolving its process.
            guard previous.isCancelled else {
                errorPointer?.pointee = Self.failure("A QEMU session is already active")
                return false
            }
            previous.cancel()
            guard previous.wait(timeout: 30) != nil else {
                errorPointer?.pointee = Self.failure("The previous QEMU session is still closing")
                return false
            }
        }
        let context = Session()
        lock.lock()
        session = context
        lock.unlock()
        let ready = DispatchSemaphore(value: 0)
        let result = StartResult()
        do {
            let support = try FileManager.default.url(for: .applicationSupportDirectory,
                in: .userDomainMask, appropriateFor: nil, create: true)
            let temporary = FileManager.default.temporaryDirectory
            // Default bookmarks carry ephemeral access grants into the helper.
            let bookmarks = try [support, temporary].map {
                try $0.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
            }
            let path = support.appendingPathComponent("session.log").path
            let fd = Darwin.open(path, O_WRONLY | O_CREAT | O_APPEND, mode_t(0o600))
            guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            let log = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            Task {
                do {
                    let monitor = try await AppExtensionPoint.Monitor(appExtensionPoint: .qemuSession)
                    guard !context.isCancelled else { throw Self.failure("QEMU start was cancelled") }
                    guard let identity = monitor.identities.first else {
                        throw Self.failure("QEMU session extension is unavailable")
                    }
                    let configuration = AppExtensionProcess.Configuration(appExtensionIdentity: identity,
                        onInterruption: { context.confirmExit() })
                    let child = try await AppExtensionProcess(configuration: configuration)
                    guard context.attach(child) else {
                        child.invalidate()
                        throw Self.failure("QEMU session exited during startup")
                    }
                    let channel = try child.makeXPCConnection()
                    channel.remoteObjectInterface = Self.serviceInterface()
                    channel.exportedInterface = NSXPCInterface(with: QEMUSessionEvents.self)
                    channel.exportedObject = context
                    channel.interruptionHandler = { [weak context] in context?.connectionLost() }
                    channel.invalidationHandler = { [weak context] in context?.connectionLost() }
                    guard context.attach(channel) else {
                        channel.invalidate()
                        throw Self.failure("QEMU session exited during startup")
                    }
                    channel.resume()
                    let proxy = channel.remoteObjectProxyWithErrorHandler { failure in
                        result.fail(failure)
                        context.connectionLost()
                        ready.signal()
                    }
                    guard let service = proxy as? QEMUSessionService else {
                        throw Self.failure("QEMU session connection is unavailable")
                    }
                    guard context.attach(service) else {
                        service.terminate()
                        throw Self.failure("QEMU start was cancelled")
                    }
                    service.start(arguments: arguments, bookmarks: bookmarks, log: log) { accepted, reason in
                        if !accepted { result.fail(Self.failure(reason ?? "Unable to start QEMU")) }
                        try? log.close()
                        ready.signal()
                    }
                } catch {
                    try? log.close()
                    result.fail(error)
                    context.startFailed()
                    ready.signal()
                }
            }
        } catch {
            context.startFailed()
            errorPointer?.pointee = error as NSError
            return false
        }
        if ready.wait(timeout: .now() + 30) == .timedOut {
            context.cancel()
            _ = context.wait(timeout: 30)
            errorPointer?.pointee = Self.failure("QEMU session did not start in time")
            return false
        }
        if let failure = result.error {
            context.cancel()
            _ = context.wait(timeout: 30)
            errorPointer?.pointee = failure as NSError
            return false
        }
        if context.isFinished {
            errorPointer?.pointee = Self.failure("QEMU exited during startup")
            return false
        }
        return true
    }

    func poll() -> NSNumber? {
        lock.lock()
        let current = session
        let previous = lastExit
        lock.unlock()
        if let current { return current.status }
        return previous
    }

    func requestQuit() {
        lock.lock(); let current = session; lock.unlock()
        current?.requestQuit()
    }

    func requestKill() {
        lock.lock(); let current = session; lock.unlock()
        current?.cancel()
    }

    func wait(timeout: Double, error errorPointer: AutoreleasingUnsafeMutablePointer<NSError?>?) -> NSNumber? {
        lock.lock(); let current = session; let previous = lastExit; lock.unlock()
        guard let current else { return previous }
        guard let code = current.wait(timeout: timeout) else {
            errorPointer?.pointee = Self.failure("QEMU session did not exit in time")
            return nil
        }
        lock.lock()
        if session === current { session = nil; lastExit = code }
        lock.unlock()
        return code
    }

    static func serviceInterface() -> NSXPCInterface {
        let interface = NSXPCInterface(with: QEMUSessionService.self)
        let selector = #selector(QEMUSessionService.start(arguments:bookmarks:log:completion:))
        interface.setClasses(NSSet(array: [NSArray.self, NSString.self]) as! Set<AnyHashable>,
                             for: selector, argumentIndex: 0, ofReply: false)
        interface.setClasses(NSSet(array: [NSArray.self, NSData.self]) as! Set<AnyHashable>,
                             for: selector, argumentIndex: 1, ofReply: false)
        interface.setClasses(NSSet(array: [FileHandle.self]) as! Set<AnyHashable>,
                             for: selector, argumentIndex: 2, ofReply: false)
        interface.setClasses(NSSet(array: [NSString.self]) as! Set<AnyHashable>,
                             for: selector, argumentIndex: 1, ofReply: true)
        return interface
    }

    private static func failure(_ message: String) -> NSError {
        NSError(domain: "MSM5xEmu.Session", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    private final class StartResult {
        private let lock = NSLock()
        private var stored: Error?
        func fail(_ error: Error) {
            lock.lock(); if stored == nil { stored = error }; lock.unlock()
        }
        var error: Error? {
            lock.lock(); defer { lock.unlock() }; return stored
        }
    }

    private final class Session: NSObject, QEMUSessionEvents {
        private let condition = NSCondition()
        private var child: AppExtensionProcess?
        private var channel: NSXPCConnection?
        private var service: QEMUSessionService?
        private var cancelled = false
        private var finished = false
        private var exitCode: Int32?

        var isFinished: Bool { condition.lock(); defer { condition.unlock() }; return finished }
        var isCancelled: Bool { condition.lock(); defer { condition.unlock() }; return cancelled }
        var status: NSNumber? {
            condition.lock(); defer { condition.unlock() }
            return finished ? NSNumber(value: exitCode ?? -1) : nil
        }
        func attach(_ process: AppExtensionProcess) -> Bool {
            condition.lock(); defer { condition.unlock() }
            guard !finished else { return false }
            child = process
            return true
        }
        func attach(_ connection: NSXPCConnection) -> Bool {
            condition.lock(); defer { condition.unlock() }
            guard !finished else { return false }
            channel = connection
            return true
        }
        func attach(_ remote: QEMUSessionService) -> Bool {
            condition.lock(); defer { condition.unlock() }
            guard !finished else { return false }
            service = remote
            return !cancelled
        }
        func requestQuit() {
            condition.lock(); let remote = service; condition.unlock()
            remote?.requestQuit()
        }
        func cancel() {
            condition.lock()
            cancelled = true
            let remote = service
            let connection = channel
            let process = child
            condition.unlock()
            if let remote { remote.terminate() }
            else if let connection { connection.invalidate() }
            else if let process {
                // Connection creation can fail transiently after process launch.
                // Keep the lease and retry reaching its termination service.
                do {
                    let recovery = try process.makeXPCConnection()
                    recovery.remoteObjectInterface = IsolatedQEMUHost.serviceInterface()
                    recovery.interruptionHandler = { [weak self] in self?.connectionLost() }
                    recovery.invalidationHandler = { [weak self] in self?.connectionLost() }
                    guard attach(recovery) else { recovery.invalidate(); return }
                    recovery.resume()
                    if let remote = recovery.remoteObjectProxyWithErrorHandler({ [weak self] _ in
                        self?.connectionLost()
                    }) as? QEMUSessionService {
                        _ = attach(remote)
                        remote.terminate()
                    } else { recovery.invalidate() }
                } catch {
                    // A later Start retries cancellation with this same lease.
                }
            }
        }
        func connectionLost() {
            condition.lock(); cancelled = true; let connection = channel; condition.unlock()
            // Invalidating also makes the extension exit on its own side.
            // It does not itself release this session's ownership.
            connection?.invalidate()
        }
        func startFailed() {
            condition.lock()
            let noChild = child == nil
            condition.unlock()
            if noChild { confirmExit() }
            else { cancel() }
        }
        func finished(status: Int32, reply: @escaping () -> Void) {
            condition.lock(); if !finished { exitCode = status }; condition.unlock()
            reply()
        }
        func confirmExit() {
            condition.lock()
            guard !finished else { condition.unlock(); return }
            finished = true
            let process = child
            let connection = channel
            child = nil; channel = nil; service = nil
            condition.broadcast()
            condition.unlock()
            connection?.interruptionHandler = nil
            connection?.invalidationHandler = nil
            connection?.invalidate()
            process?.invalidate()
        }
        func wait(timeout: Double) -> NSNumber? {
            condition.lock(); defer { condition.unlock() }
            let deadline = Date(timeIntervalSinceNow: max(0, timeout))
            while !finished && condition.wait(until: deadline) { }
            return finished ? NSNumber(value: exitCode ?? -1) : nil
        }
    }
}
