import Foundation
import Darwin
import ExtensionFoundation

@available(iOS 26.0, *)
@main
final class QEMUSessionExtension: AppExtension {
    required init() {}

    @AppExtensionPoint.Bind
    var boundExtensionPoint: AppExtensionPoint {
        AppExtensionPoint.Identifier(host: "me.ancal.msm5xemu", name: "qemu-session")
    }

    var configuration: some AppExtensionConfiguration {
        ConnectionHandler { connection in
            connection.exportedInterface = QEMUSessionController.serviceInterface()
            connection.remoteObjectInterface = NSXPCInterface(with: QEMUSessionEvents.self)
            connection.exportedObject = QEMUSessionController(connection: connection)
            connection.invalidationHandler = { _exit(0) }
            connection.interruptionHandler = { _exit(0) }
            connection.resume()
            return true
        }
    }
}

@available(iOS 26.0, *)
private final class QEMUSessionController: NSObject, QEMUSessionService {
    private let lock = NSLock()
    private var started = false
    private var accessedURLs: [URL] = []
    private weak var connection: NSXPCConnection?

    init(connection: NSXPCConnection) { self.connection = connection }

    private static func allowedClasses(_ classes: [AnyClass]) -> Set<AnyHashable> {
        NSSet(array: classes) as! Set<AnyHashable>
    }

    fileprivate static func serviceInterface() -> NSXPCInterface {
        let interface = NSXPCInterface(with: QEMUSessionService.self)
        let selector = #selector(QEMUSessionService.start(arguments:bookmarks:log:completion:))
        interface.setClasses(Self.allowedClasses([NSArray.self, NSString.self]),
                             for: selector, argumentIndex: 0, ofReply: false)
        interface.setClasses(Self.allowedClasses([NSArray.self, NSData.self]),
                             for: selector, argumentIndex: 1, ofReply: false)
        interface.setClasses(Self.allowedClasses([FileHandle.self]),
                             for: selector, argumentIndex: 2, ofReply: false)
        interface.setClasses(Self.allowedClasses([NSString.self]),
                             for: selector, argumentIndex: 1, ofReply: true)
        return interface
    }

    func start(arguments: [String], bookmarks: [Data], log: FileHandle,
               completion: @escaping (Bool, String?) -> Void) {
        lock.lock()
        guard !started else {
            lock.unlock()
            completion(false, "This QEMU session helper has already been used")
            return
        }
        started = true
        lock.unlock()

        guard arguments.count > 0, arguments.allSatisfy({ !$0.contains("\0") }),
              bookmarks.count == 2 else {
            completion(false, "Invalid QEMU session request")
            return
        }
        do {
            accessedURLs = try Self.resolveDirectories(bookmarks)
            guard dup2(log.fileDescriptor, STDOUT_FILENO) >= 0,
                  dup2(log.fileDescriptor, STDERR_FILENO) >= 0 else {
                completion(false, "Unable to attach QEMU session log")
                return
            }
            try log.close()
            var launchError: NSError?
            guard QEMUSessionCore.start(arguments: arguments, error: &launchError,
                finished: { [weak self] status in
                    guard let connection = self?.connection,
                          let remote = connection.remoteObjectProxy as? QEMUSessionEvents else { return }
                    let reply = DispatchSemaphore(value: 0)
                    remote.finished(status: status) { reply.signal() }
                    _ = reply.wait(timeout: .now() + 1)
                }) else {
                completion(false, launchError?.localizedDescription ?? "Unable to start QEMU")
                return
            }
            completion(true, nil)
        } catch {
            completion(false, error.localizedDescription)
        }
    }

    func requestQuit() {
        QEMUSessionCore.requestQuit()
    }

    func terminate() {
        _exit(0)
    }

    private static func resolveDirectories(_ bookmarks: [Data]) throws -> [URL] {
        var accessed: [URL] = []
        do {
            for bookmark in bookmarks {
                var stale = false
                let url = try URL(resolvingBookmarkData: bookmark, options: [], relativeTo: nil,
                                  bookmarkDataIsStale: &stale)
                // A stale flag only advises re-creating the bookmark; the URL still resolves.
                // Implicit (non security-scoped) grants report false here yet still give access.
                if url.startAccessingSecurityScopedResource() { accessed.append(url) }
                var isDirectory: ObjCBool = false
                guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
                      isDirectory.boolValue else {
                    throw NSError(domain: "MSM5xEmu.QEMUSession", code: 2,
                                  userInfo: [NSLocalizedDescriptionKey: "QEMU session directory is unavailable: \(url.path)"])
                }
            }
            return accessed
        } catch {
            accessed.forEach { $0.stopAccessingSecurityScopedResource() }
            throw error
        }
    }
}
