import Darwin
import Foundation
import Combine
import CoreGraphics

@_silgen_name("csops")
private func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

/// Loads the embedded QEMU framework (built by ios/build_qemu_framework.sh): QEMU (TCG) when JIT
/// memory is usable, otherwise QEMUTCI. All Python calls run on one serial queue.
final class QEMUEngine: ObservableObject {
    typealias Entry = @convention(c) (Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32

    private(set) var entry: Entry?
    @Published private(set) var status = "Loading runtime"
    @Published private(set) var frame: CGImage?
    @Published private(set) var inputBits = Set<Int>()
    @Published private(set) var running = false
    @Published private(set) var used = false
    private let queue = DispatchQueue(label: "me.ancal.msm5xemu.python")
    private var runtimeReady = false
    private var polling = false

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
        typealias ABIVersion = @convention(c) () -> Int32
        guard let abi = dlsym(handle, "msm5xxx_qemu_embedding_abi"),
              unsafeBitCast(abi, to: ABIVersion.self)() == 1,
              let quit = dlsym(handle, "msm5xxx_qemu_request_quit") else {
            status = "Rebuild QEMU frameworks with the iOS embedding guard"
            return
        }
        PythonBridge.configureQEMUEntry(symbol, requestQuit: quit)
        entry = unsafeBitCast(symbol, to: Entry.self)
        status = "QEMU 10.2.1 loaded (\(name == "QEMU" ? "TCG" : "TCI"))"
        NSLog("MSM5xEmu engine: %@; JIT %@; cs flags 0x%08x", status, QEMUEngine.jitAvailable ? "available" : "unavailable", QEMUEngine.codeSigningFlags)
    }

    func start(_ firmware: URL) {
        guard entry != nil, !used else { return }
        used = true
        queue.async {
            do {
                if !self.runtimeReady {
                    try PythonBridge.initializeRuntime()
                    self.runtimeReady = true
                }
                let detected = try PythonBridge.call("detect_profile", argument: firmware.path)
                guard let data = detected.data(using: .utf8),
                      let admission = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      admission["accepted"] as? Bool == true,
                      let profile = admission["profile"] else {
                    throw NSError(domain: "MSM5xEmu", code: 1,
                                  userInfo: [NSLocalizedDescriptionKey: "Detector rejected firmware: \(detected)"])
                }
                let support = try FileManager.default.url(for: .applicationSupportDirectory,
                    in: .userDomainMask, appropriateFor: nil, create: true)
                let request: [String: Any] = ["firmware": firmware.path, "profile": profile,
                    "qemu": "qemu-system-arm", "state": support.appendingPathComponent("state").path,
                    "experimental_rex": false]
                let json = try JSONSerialization.data(withJSONObject: request)
                let result = try PythonBridge.call("start_session", argument: String(decoding: json, as: UTF8.self))
                let started = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any]
                let bits = Set(started?["input_bits"] as? [Int] ?? [])
                DispatchQueue.main.async {
                    self.running = true
                    self.inputBits = bits
                    self.status = "Running (detector-admitted input only)"; NSLog("MSM5xEmu running, input bits %@", String(describing: bits.sorted()))
                }
            } catch { self.report(error) }
        }
    }

    func key(_ bit: Int, pressed: Bool) {
        guard running, inputBits.contains(bit) else { return }
        queue.async {
            do {
                let json = try JSONSerialization.data(withJSONObject:
                    ["bit": bit, "event_code": NSNull(), "pressed": pressed])
                _ = try PythonBridge.call("set_session_key", argument: String(decoding: json, as: UTF8.self))
            } catch { self.report(error) }
        }
    }

    func stop() {
        guard running else { return }
        running = false
        inputBits = []
        queue.async {
            do {
                _ = try PythonBridge.call("stop_session", argument: nil)
                DispatchQueue.main.async { self.status = "Stopped. Relaunch app for another session." }
            } catch { self.report(error) }
        }
    }

    func refresh() {
        guard running, !polling else { return }
        polling = true
        queue.async {
            defer { DispatchQueue.main.async { self.polling = false } }
            do {
                let packet = try PythonBridge.bytes("session_frame")
                if packet.count > 16 {
                    func word(_ offset: Int) -> Int {
                        (0..<4).reduce(0) { $0 | Int(packet[offset + $1]) << ($1 * 8) }
                    }
                    let width = word(4), height = word(8)
                    guard word(0) == 1, (1...2048).contains(width), (1...2048).contains(height),
                          packet.count == 16 + width * height * 3,
                          let provider = CGDataProvider(data: packet.subdata(in: 16..<packet.count) as CFData),
                          let image = CGImage(width: width, height: height, bitsPerComponent: 8,
                            bitsPerPixel: 24, bytesPerRow: width * 3, space: CGColorSpaceCreateDeviceRGB(),
                            bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.none.rawValue),
                            provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent)
                    else { return }
                    DispatchQueue.main.async { self.frame = image }
                }
                let status = try PythonBridge.call("session_status", argument: nil)
                let value = try JSONSerialization.jsonObject(with: Data(status.utf8)) as? [String: Any]
                if value?["process_running"] as? Bool == false {
                    DispatchQueue.main.async {
                        self.running = false; self.inputBits = []
                        self.status = "QEMU exited. Relaunch app for another session."
                    }
                }
            } catch {
                DispatchQueue.main.async { self.running = false; self.inputBits = [] }
                self.report(error)
            }
        }
    }

    private func report(_ error: Error) {
        NSLog("MSM5xEmu error: %@", String(describing: error))
        DispatchQueue.main.async { self.status = error.localizedDescription }
    }

}
