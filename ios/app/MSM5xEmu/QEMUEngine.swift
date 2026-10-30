import Darwin
import Foundation

/// Loads the embedded QEMU framework (built by ios/build_qemu_framework.sh): QEMU (TCG) when JIT
/// memory is usable, otherwise QEMUTCI. Running a guest in-process is not wired up yet: QEMU still
/// exits the process on shutdown.
final class QEMUEngine {
    typealias Entry = @convention(c) (Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32

    private(set) var entry: Entry?
    let status: String

    /// True when this process may create executable JIT memory: TrollStore's dynamic-codesigning
    /// entitlement, an attached debugger (StikJIT, Jitterbug, AltJIT) or the simulator.
    static let jitAvailable: Bool = {
        let size = Int(getpagesize())
        let page = mmap(nil, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0)
        guard page != MAP_FAILED else { return false }
        munmap(page, size)
        return true
    }()

    init() {
        let name = QEMUEngine.jitAvailable ? "QEMU" : "QEMUTCI"
        guard let dir = Bundle.main.privateFrameworksPath,
              let handle = dlopen("\(dir)/\(name).framework/\(name)", RTLD_NOW) else {
            status = "\(name).framework not loaded" + (dlerror().map { ": " + String(cString: $0) } ?? "")
            return
        }
        guard let symbol = dlsym(handle, "qemu_entry") else {
            status = "qemu_entry missing in \(name)"
            return
        }
        entry = unsafeBitCast(symbol, to: Entry.self)
        status = "QEMU 10.2.1 loaded (\(name == "QEMU" ? "TCG" : "TCI"))"
    }
}
