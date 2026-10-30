import Darwin
import Foundation

@_silgen_name("csops")
private func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

/// Loads the embedded QEMU.framework (built by ios/build_qemu_framework.sh).
/// Running a guest in-process is not wired up yet: QEMU still exits the process on shutdown.
final class QEMUEngine {
    typealias Entry = @convention(c) (Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32

    private(set) var entry: Entry?
    let status: String

    /// TCG needs JIT; on a device that means a debugger such as StikJIT attached (CS_DEBUGGED).
    static var jitAvailable: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        var flags: UInt32 = 0
        return csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size) == 0 && flags & 0x1000_0000 != 0
        #endif
    }

    init() {
        guard let dir = Bundle.main.privateFrameworksPath,
              let handle = dlopen(dir + "/QEMU.framework/QEMU", RTLD_NOW) else {
            status = "QEMU.framework not loaded" + (dlerror().map { ": " + String(cString: $0) } ?? "")
            return
        }
        guard let symbol = dlsym(handle, "qemu_entry") else {
            status = "qemu_entry missing"
            return
        }
        entry = unsafeBitCast(symbol, to: Entry.self)
        status = "QEMU 10.2.1 loaded"
    }
}
