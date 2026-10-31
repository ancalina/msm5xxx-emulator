import Darwin
import Foundation

@_silgen_name("csops")
private func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

/// Loads the embedded QEMU framework (built by ios/build_qemu_framework.sh): QEMU (TCG) when JIT
/// memory is usable, otherwise QEMUTCI. Running a guest in-process is not wired up yet: QEMU still
/// exits the process on shutdown.
final class QEMUEngine {
    typealias Entry = @convention(c) (Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32

    private(set) var entry: Entry?
    let status: String

    /// True when this process may turn freshly written memory executable, as QEMU's split-wx TCG
    /// does: an attached debugger (TrollStore "Open with JIT", Dopamine, StikJIT, Jitterbug) or the
    /// simulator. Re-probed on every call because JIT can be granted while the app runs.
    static var jitAvailable: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        let size = Int(getpagesize())
        guard let page = mmap(nil, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
              page != MAP_FAILED else { return false }
        defer { munmap(page, size) }
        page.storeBytes(of: UInt32(0xD65F03C0), as: UInt32.self)  // ret
        return mprotect(page, size, PROT_READ | PROT_EXEC) == 0
        #endif
    }

    /// Code-signing flags of this process; CS_DEBUGGED (0x10000000) is what JIT enablers set.
    static var codeSigningFlags: UInt32 {
        var flags: UInt32 = 0
        _ = csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size)
        return flags
    }

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
        NSLog("MSM5xEmu engine: %@; JIT %@; cs flags 0x%08x", status, QEMUEngine.jitAvailable ? "available" : "unavailable", QEMUEngine.codeSigningFlags)
    }
}
