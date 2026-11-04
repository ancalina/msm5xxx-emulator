import Darwin
import Foundation
import Combine
import CoreGraphics
import AVFoundation

/// Loads the embedded QEMU framework (built by ios/build_qemu_framework.sh): QEMU (TCG) when JIT
/// memory is usable, otherwise QEMUTCI. All Python calls run on one serial queue.
final class QEMUEngine: ObservableObject {
    typealias Entry = @convention(c) (Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32

    private(set) var entry: Entry?
    @Published private(set) var status = "Loading runtime"
    @Published private(set) var frame: CGImage?
    @Published private(set) var secondaryFrame: CGImage?
    @Published private(set) var secondaryAvailable = false
    @Published private(set) var secondaryPreview = false
    @Published private(set) var foldSupported = false
    @Published private(set) var foldOpen = false
    @Published private(set) var metrics = "Run —  PC —\nLCD —  Frame —"
    @Published private(set) var inputBits = Set<Int>()
    @Published private(set) var identity = ""
    @Published private(set) var running = false
    @Published private(set) var starting = false
    @Published private(set) var used = false
    @Published private(set) var paused = false
    @Published private(set) var poweredOff = false
    @Published private(set) var errorDetail = ""
    @Published private(set) var sessionFailed = false
    @Published private(set) var refreshInterval = 0.1
    private let queue = DispatchQueue(label: "me.ancal.msm5xemu.python")
    private var runtimeReady = false
    private var polling = false
    // All Python entry points stay on `queue`; it also services audio packets at
    // short intervals without tying guest audio cadence to screen refresh.
    private var audioPolling = false
    private var audioSink: MSM5xxxAudioSink?
    private var sessionStarted = false
    private var sceneActive = true
    private var audioInterrupted = false
    private var audioGeneration = 0
    private var monitorPaused = false
    private var parked = false
    private var unchangedPolls = 0
    private var audioDiagnostics = false
    private var audioPackets = 0
    private var audioNonzeroPackets = 0
    private var audioMalformedPackets = 0
    private var lastMetricsLog = Date.distantPast
    private var lastAudioLog = Date.distantPast
    private var lastAudioError = Date.distantPast
    private var lastAudioRecovery = Date.distantPast

    /// True when this process may turn freshly written memory executable, as QEMU's split-wx TCG
    /// does: an attached debugger (TrollStore "Open with JIT", Dopamine, StikJIT, Jitterbug) or the
    /// simulator. Re-probed on every call because JIT can be granted while the app runs.
    static var jitAvailable: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        if UserDefaults.standard.bool(forKey: "internal_force_tci") { return false }
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
        typealias CSOps = @convention(c) (pid_t, UInt32, UnsafeMutableRawPointer?, Int) -> Int32
        guard let handle = dlopen(nil, RTLD_LAZY) else { return 0 }
        defer { dlclose(handle) }
        guard let symbol = dlsym(handle, "csops") else { return 0 }
        let operation = unsafeBitCast(symbol, to: CSOps.self)
        var flags: UInt32 = 0
        _ = operation(getpid(), 0, &flags, MemoryLayout<UInt32>.size)
        return flags
    }

    init() {
        let name = QEMUEngine.jitAvailable ? "QEMU" : "QEMUTCI"
        guard let dir = Bundle.main.privateFrameworksPath,
              let handle = dlopen("\(dir)/\(name).framework/\(name)", RTLD_NOW) else {
            NSLog("QEMU framework unavailable: %@", dlerror().map { String(cString: $0) } ?? "")
            status = "QEMU unavailable"
            return
        }
        guard let symbol = dlsym(handle, "qemu_entry") else {
            status = "QEMU entry unavailable"
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
        status = "Ready"
        NSLog("MSM5xEmu engine: %@; JIT %@; cs flags 0x%08x", name, QEMUEngine.jitAvailable ? "available" : "unavailable", QEMUEngine.codeSigningFlags)
        // Readable over SSH for device checks: which engine this process loaded.
        if let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            try? "\(name) jit=\(QEMUEngine.jitAvailable) cs=0x\(String(QEMUEngine.codeSigningFlags, radix: 16))\n"
                .write(to: support.appendingPathComponent("engine.txt"), atomically: true, encoding: .utf8)
        }
    }

    // Called from the library's background queue, never from the Python queue.
    func libraryRequest(_ request: [String: String]) throws -> [String: Any] {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<[String: Any], Error>!
        queue.async {
            defer { semaphore.signal() }
            do {
                if !self.runtimeReady {
                    try PythonBridge.initializeRuntime()
                    self.runtimeReady = true
                }
                let data = try JSONSerialization.data(withJSONObject: request)
                let reply = try PythonBridge.call("library_describe", argument: String(decoding: data, as: UTF8.self))
                guard let value = try JSONSerialization.jsonObject(with: Data(reply.utf8)) as? [String: Any] else {
                    throw NSError(domain: "FirmwareLibrary", code: 1)
                }
                result = .success(value)
            } catch { result = .failure(error) }
        }
        semaphore.wait()
        return try result.get()
    }

    func start(_ firmware: URL, persistentState: Bool = true, experimentalRex: Bool = false,
               virtualNetwork: Bool = false, networkHostTime: Bool = true,
               networkStartTime: Double? = nil) {
        guard entry != nil, !used else {
            clearDisplay()
            status = "Unable to start. Force-close and reopen the app to try again."
            errorDetail = entry == nil ? "QEMU unavailable" : "QEMU already used"
            sessionFailed = true
            return
        }
        used = true
        starting = true
        sessionFailed = false
        errorDetail = ""
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
                let firmwareInfo = (profile as? [String: Any])?["firmware"] as? [String: Any]
                let identity = firmwareInfo?["sha256"] as? String ?? ""
                DispatchQueue.main.async { self.identity = identity }
                let support = try FileManager.default.url(for: .applicationSupportDirectory,
                    in: .userDomainMask, appropriateFor: nil, create: true)
                // iOS drops stderr; keep QEMU/Python diagnostics next to the state for inspection.
                let log = support.appendingPathComponent("session.log").path
                freopen(log, "w", stderr); freopen(log, "a", stdout); setvbuf(stderr, nil, _IONBF, 0)
                let request: [String: Any] = ["firmware": firmware.path, "profile": profile,
                    "qemu": "qemu-system-arm",
                    "state": persistentState ? support.appendingPathComponent("state").path : NSNull(),
                    "settings": UserDefaults.standard.dictionary(forKey: "details.\(identity)") as? [String: String] ?? [:],
                    "experimental_rex": experimentalRex, "virtual_network": virtualNetwork,
                    "network_host_time": networkHostTime, "network_start_time": networkStartTime as Any? ?? NSNull()]
                let json = try JSONSerialization.data(withJSONObject: request)
                let result = try PythonBridge.call("start_session", argument: String(decoding: json, as: UTF8.self))
                let started = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any]
                self.sessionStarted = true
                let bits = Set(started?["input_bits"] as? [Int] ?? [])
                self.audioDiagnostics = FileManager.default.fileExists(atPath: support.appendingPathComponent("autorun").path)
                if started?["audio_admitted"] as? Bool == true {
                    let sink = MSM5xxxAudioSink()
                    if sink.start() {
                        self.audioSink = sink
                    } else {
                        NSLog("MSM5xEmu iOS audio unavailable; QEMU remains running")
                    }
                    // Keep draining the bounded native stream even if the host
                    // audio session cannot start, so playback failure cannot
                    // stall guest execution.
                    self.audioPolling = true
                    self.pollAudio()
                }
                if !self.sceneActive { try self.applySceneActive(false) }
                DispatchQueue.main.async {
                    self.starting = false
                    self.running = true
                    self.inputBits = bits
                    self.status = "Running (detector-admitted input only)"; NSLog("MSM5xEmu running, input bits %@", String(describing: bits.sorted()))
                }
            } catch {
                DispatchQueue.main.async { self.starting = false }
                self.failSession(error, message: "Unable to start. Force-close and reopen the app to try again.")
            }
        }
    }

    func key(_ bit: Int, pressed: Bool) {
        let mapped = UserDefaults.standard.object(forKey: "keymap.\(identity).\(bit)") != nil
        guard running, inputBits.contains(bit) || mapped else { return }
        if refreshInterval != 0.1 { refreshInterval = 0.1 }
        queue.async {
            self.unchangedPolls = 0
            do {
                let key = "keymap.\(self.identity).\(bit)"
                let eventCode = UserDefaults.standard.object(forKey: key) as? Int
                let json = try JSONSerialization.data(withJSONObject:
                    ["bit": bit, "event_code": eventCode as Any? ?? NSNull(), "pressed": pressed])
                _ = try PythonBridge.call("set_session_key", argument: String(decoding: json, as: UTF8.self))
            } catch { self.report(error) }
        }
    }

    func setMapping(_ bit: Int, value: Int?, completion: @escaping (Bool) -> Void) {
        guard running, !identity.isEmpty else { completion(false); return }
        let identity = self.identity
        guard let value = value else {
            UserDefaults.standard.removeObject(forKey: "keymap.\(identity).\(bit)")
            completion(true)
            return
        }
        queue.async {
            do {
                let json = try JSONSerialization.data(withJSONObject: ["bit": bit, "event_code": value])
                let result = try PythonBridge.call("can_session_key", argument: String(decoding: json, as: UTF8.self))
                let data = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any]
                let accepted = data?["accepted"] as? Bool == true
                DispatchQueue.main.async {
                    if accepted && self.identity == identity && self.running {
                        UserDefaults.standard.set(value, forKey: "keymap.\(identity).\(bit)")
                        completion(true)
                    } else { completion(false) }
                }
            } catch { DispatchQueue.main.async { completion(false) } }
        }
    }

    func toggleFold() {
        guard running && foldSupported else { return }
        let open = !foldOpen
        queue.async {
            do {
                let json = try JSONSerialization.data(withJSONObject: ["open": open])
                _ = try PythonBridge.call("session_fold", argument: String(decoding: json, as: UTF8.self))
            } catch { self.report(error) }
        }
    }

    private func networkRequest(refresh: Bool, includeEnabled: Bool = false) -> String {
        let defaults = UserDefaults.standard
        let manual = defaults.bool(forKey: "network_start_time_enabled")
        var request: [String: Any] = ["host_time": !manual,
                                      "start_time": manual ? defaults.double(forKey: "network_start_time") : NSNull(),
                                      "refresh": refresh]
        if includeEnabled { request["enabled"] = defaults.bool(forKey: "virtual_network") }
        return String(decoding: try! JSONSerialization.data(withJSONObject: request), as: UTF8.self)
    }

    func refreshNetworkTime() {
        guard running else { return }
        let request = networkRequest(refresh: true)
        queue.async {
            do { _ = try PythonBridge.call("refresh_network_time", argument: request) }
            catch { self.report(error) }
        }
    }

    func reboot() {
        guard running else { return }
        let request = networkRequest(refresh: false, includeEnabled: true)
        queue.async {
            do {
                _ = try PythonBridge.call("reset_session", argument: request)
                DispatchQueue.main.async {
                    self.frame = nil
                    self.secondaryFrame = nil
                }
            } catch {
                self.failSession(error, message: "Unable to reboot. Force-close and reopen the app to try again.")
            }
        }
    }

    func powerOff(completion: @escaping (Bool) -> Void) {
        guard running, !starting else { completion(false); return }
        starting = true
        queue.async {
            do {
                self.parked = true
                try self.applySceneActive(self.sceneActive)
                DispatchQueue.main.async {
                    self.poweredOff = true
                    self.running = false
                    self.starting = false
                    completion(true)
                }
            } catch {
                self.failSession(error, message: "Unable to stop. Force-close and reopen the app to try again.")
                DispatchQueue.main.async { completion(false) }
            }
        }
    }

    func powerOn(completion: @escaping (Bool) -> Void) {
        guard poweredOff, !starting else { completion(false); return }
        starting = true
        let request = networkRequest(refresh: false, includeEnabled: true)
        queue.async {
            do {
                _ = try PythonBridge.call("reset_session", argument: request)
                self.parked = false
                try self.applySceneActive(self.sceneActive)
                DispatchQueue.main.async {
                    self.frame = nil
                    self.secondaryFrame = nil
                    self.poweredOff = false
                    self.running = true
                    self.starting = false
                    completion(true)
                }
            } catch {
                self.failSession(error, message: "Unable to start. Force-close and reopen the app to try again.")
                DispatchQueue.main.async { completion(false) }
            }
        }
    }

    func stop(completion: ((Bool) -> Void)? = nil) {
        guard running else { completion?(false); return }
        running = false
        starting = true
        inputBits = []
        queue.async {
            do {
                self.stopAudio()
                _ = try PythonBridge.call("stop_session", argument: nil)
                self.sessionStarted = false
                DispatchQueue.main.async {
                    self.starting = false
                    self.clearDisplay()
                    self.status = "Stopped. Force-close and reopen the app to run again."
                    completion?(true)
                }
            } catch {
                self.failSession(error, message: "Unable to stop. Force-close and reopen the app to try again.")
                DispatchQueue.main.async { completion?(false) }
            }
        }
    }

    func setSceneActive(_ active: Bool) {
        queue.async {
            do {
                try self.applySceneActive(active)
            } catch {
                self.failSession(error, message: "Unable to pause or resume. Force-close and reopen the app to try again.")
            }
        }
    }

    private func applySceneActive(_ active: Bool) throws {
        sceneActive = active
        let shouldPause = !active || parked
        guard sessionStarted, monitorPaused != shouldPause else { return }
        if shouldPause {
            audioGeneration += 1
            audioSink?.pauseOutput()
        }
        let request = shouldPause ? "{\"paused\":true}" : "{\"paused\":false}"
        _ = try PythonBridge.call("set_session_paused", argument: request)
        monitorPaused = shouldPause
        NSLog("MSM5xEmu %@", shouldPause ? "paused" : "resumed")
        if !shouldPause {
            audioSink?.resumeOutput()
            audioGeneration += 1
            pollAudio(generation: audioGeneration)
        }
        DispatchQueue.main.async { self.paused = shouldPause }
    }

    func setAudioInterrupted(_ interrupted: Bool) {
        queue.async {
            self.audioInterrupted = interrupted
            if interrupted { self.audioSink?.pauseOutput() }
            else if self.sceneActive && !self.monitorPaused { self.audioSink?.resumeOutput() }
        }
    }

    func resetAudioServices() {
        queue.async {
            guard self.audioPolling else { return }
            self.audioSink?.close()
            self.audioSink = nil
        }
    }

    func refresh() {
        guard running, !paused, !polling else { return }
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
                    else { throw NSError(domain: "MSM5xEmu", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid display frame"]) }
                    DispatchQueue.main.async { self.frame = image }
                }
                let secondary = try PythonBridge.bytes("session_secondary_frame")
                if packet.count > 16 || secondary.count > 16 {
                    self.unchangedPolls = 0
                    DispatchQueue.main.async { if self.refreshInterval != 0.1 { self.refreshInterval = 0.1 } }
                } else {
                    self.unchangedPolls += 1
                    if self.unchangedPolls == 8 {
                        DispatchQueue.main.async { self.refreshInterval = 0.5 }
                    }
                }
                if secondary.count > 16 {
                    func word(_ offset: Int) -> Int {
                        (0..<4).reduce(0) { $0 | Int(secondary[offset + $1]) << ($1 * 8) }
                    }
                    let width = word(4), height = word(8)
                    if word(0) == 1, (1...2048).contains(width), (1...2048).contains(height),
                       secondary.count == 16 + width * height * 3,
                       let provider = CGDataProvider(data: secondary.subdata(in: 16..<secondary.count) as CFData),
                       let image = CGImage(width: width, height: height, bitsPerComponent: 8,
                           bitsPerPixel: 24, bytesPerRow: width * 3, space: CGColorSpaceCreateDeviceRGB(),
                           bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.none.rawValue),
                           provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent) {
                        DispatchQueue.main.async { self.secondaryFrame = image }
                    }
                }
                let status = try PythonBridge.call("session_status", argument: nil)
                let value = try JSONSerialization.jsonObject(with: Data(status.utf8)) as? [String: Any]
                let supported = value?["fold_supported"] as? Bool ?? false
                let open = value?["fold_open"] as? Bool ?? false
                let run = value?["instructions"] as? Int ?? 0
                let pc = value?["pc"] as? Int ?? 0
                let lcd = value?["lcd_writes"] as? Int ?? 0
                let frame = value?["frame_sequence"] as? Int ?? 0
                if Date().timeIntervalSince(self.lastMetricsLog) >= 10 {
                    self.lastMetricsLog = Date()
                    NSLog("MSM5xEmu Run %lld PC %llx LCD %lld Frame %lld", Int64(run), UInt64(bitPattern: Int64(pc)), Int64(lcd), Int64(frame))
                }
                DispatchQueue.main.async {
                    self.secondaryAvailable = value?["secondary_available"] as? Bool ?? false
                    self.secondaryPreview = value?["secondary_preview"] as? Bool ?? false
                    self.foldSupported = supported
                    self.foldOpen = open
                    self.metrics = "Run \(run)  PC 0x\(String(format: "%08X", pc))\nLCD \(lcd)  Frame \(frame)"
                }
                if self.audioDiagnostics && self.audioPolling && Date().timeIntervalSince(self.lastAudioLog) >= 10 {
                    self.lastAudioLog = Date()
                    NSLog("MSM5xEmu audio packets=%d nonzero=%d malformed=%d consumed_frames=%llu underflows=%@ overflows=%@",
                          self.audioPackets, self.audioNonzeroPackets, self.audioMalformedPackets,
                          self.audioSink?.consumedFrames ?? 0,
                          String(describing: value?["audio_underflow_frames"] ?? 0),
                          String(describing: value?["audio_overflow_frames"] ?? 0))
                }
                if value?["process_running"] as? Bool == false {
                    throw NSError(domain: "MSM5xEmu", code: 2, userInfo: [NSLocalizedDescriptionKey: "QEMU exited"])
                }
            } catch {
                self.failSession(error, message: "Emulation stopped. Force-close and reopen the app to try again.")
            }
        }
    }

    private func pollAudio(generation: Int? = nil) {
        let generation = generation ?? audioGeneration
        guard audioPolling, sceneActive, !monitorPaused, generation == audioGeneration else { return }
        var received = false
        if Date().timeIntervalSince(lastAudioRecovery) >= 1 {
            lastAudioRecovery = Date()
            if let sink = audioSink { sink.resumeOutput() }
            else {
                let sink = MSM5xxxAudioSink()
                if sink.start() { audioSink = sink }
            }
        }
        do {
            // Bound each drain to avoid starving display and input work.
            for _ in 0..<4 {
                let packet = try PythonBridge.bytes("session_audio")
                if packet.isEmpty { break }
                received = true
                if audioDiagnostics {
                    audioPackets += 1
                    if packet.dropFirst(32).contains(where: { $0 != 0 }) { audioNonzeroPackets += 1 }
                }
                if let sink = audioSink, !sink.offer(packet) {
                    audioMalformedPackets += 1
                }
            }
        } catch {
            if Date().timeIntervalSince(lastAudioError) >= 10 {
                lastAudioError = Date()
                NSLog("MSM5xEmu iOS audio poll failed: %@", String(describing: error))
            }
        }
        queue.asyncAfter(deadline: .now() + .milliseconds(received ? 20 : 30)) { self.pollAudio(generation: generation) }
    }

    private func stopAudio() {
        audioPolling = false
        audioGeneration += 1
        audioSink?.close()
        audioSink = nil
    }

    private func report(_ error: Error) {
        NSLog("MSM5xEmu error: %@", String(describing: error))
        DispatchQueue.main.async { self.errorDetail = error.localizedDescription }
    }

    private func clearDisplay() {
        frame = nil; secondaryFrame = nil; secondaryAvailable = false
        secondaryPreview = false; foldSupported = false; foldOpen = false
        inputBits = []; metrics = "Run —  PC —\nLCD —  Frame —"; paused = false
    }

    private func failSession(_ error: Error, message: String) {
        NSLog("MSM5xEmu error: %@", String(describing: error))
        stopAudio()
        sessionStarted = false
        DispatchQueue.main.async {
            self.running = false; self.starting = true
            self.clearDisplay()
            self.errorDetail = error.localizedDescription
            self.status = message
            self.sessionFailed = true
        }
        if runtimeReady { _ = try? PythonBridge.call("stop_session", argument: nil) }
        DispatchQueue.main.async { self.starting = false }
    }

}

/// Plays detector-admitted native PCM packets. QEMU and guest scheduling stay
/// independent of this host consumer; a playback failure only disables audio.
private final class MSM5xxxAudioSink {
    private static let sampleRate = 44_100.0
    private static let packetBytes = 1_796
    private static let headerBytes = 32
    private static let frameBytes = 4
    private static let prebufferFrames: AVAudioFrameCount = 2_646
    private static let maximumQueuedFrames: AVAudioFrameCount = 8_820
    private static let shortToneStartDelay = DispatchTimeInterval.milliseconds(10)

    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private let format = AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 2)!
    private let lock = NSLock()
    private var pendingFrames: AVAudioFrameCount = 0
    private var playing = false
    private var generation: UInt64 = 0
    private var epoch: UInt64 = 0
    private var sequence: UInt64 = 0
    private var nextFrame: UInt64 = 0
    private var closed = false
    private var suspended = false
    private var completedFrames: UInt64 = 0

    var consumedFrames: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return completedFrames
    }

    func start() -> Bool {
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)
            engine.attach(player)
            engine.connect(player, to: engine.mainMixerNode, format: format)
            engine.prepare()
            try engine.start()
            return true
        } catch {
            NSLog("MSM5xEmu AVAudioEngine start failed: %@", String(describing: error))
            close()
            return false
        }
    }

    func pauseOutput() {
        lock.lock()
        suspended = true
        lock.unlock()
        player.pause()
        engine.pause()
    }

    func resumeOutput() {
        lock.lock()
        let needsRestart = !closed && (suspended || !engine.isRunning)
        if needsRestart { suspended = true }
        lock.unlock()
        guard needsRestart else { return }
        do {
            try AVAudioSession.sharedInstance().setActive(true)
            if !engine.isRunning { try engine.start() }
            lock.lock()
            generation &+= 1
            pendingFrames = 0
            playing = false
            lock.unlock()
            player.stop()
            player.reset()
            lock.lock()
            if !closed { suspended = false }
            lock.unlock()
        } catch {
            NSLog("MSM5xEmu audio resume failed: %@", String(describing: error))
        }
    }

    /// Accept exactly one M5P2 packet and preserve the native frame timeline.
    func offer(_ data: Data) -> Bool {
        guard !closed, data.count == Self.packetBytes,
              data[0] == 0x4d, data[1] == 0x35, data[2] == 0x50, data[3] == 0x32,
              readUInt(data, 4, 4) == 2 else { return false }
        let packetEpoch = readUInt(data, 8, 8)
        let packetSequence = readUInt(data, 16, 8)
        let startFrame = readUInt(data, 24, 8)
        let frames = (data.count - Self.headerBytes) / Self.frameBytes
        guard packetEpoch > 0, packetSequence > 0, frames > 0,
              (data.count - Self.headerBytes) % Self.frameBytes == 0,
              startFrame <= UInt64(Int64.max) - UInt64(frames) else { return false }

        if packetEpoch != epoch {
            resetTimeline()
            epoch = packetEpoch
            sequence = 0
            nextFrame = startFrame
        } else {
            guard packetSequence > sequence else { return false }
            if packetSequence != sequence + 1 || startFrame != nextFrame {
            // Overflow or a dropped packet starts a fresh bounded playback timeline.
                resetTimeline()
            }
        }

        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: AVAudioFrameCount(frames)),
              let channels = buffer.floatChannelData else { return false }
        buffer.frameLength = AVAudioFrameCount(frames)
        for frame in 0..<frames {
            for channel in 0..<2 {
                let offset = Self.headerBytes + frame * Self.frameBytes + channel * 2
                let bits = UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
                channels[channel][frame] = Float(Int16(bitPattern: bits)) / 32_768.0
            }
        }

        sequence = packetSequence
        nextFrame = startFrame + UInt64(frames)
        schedule(buffer)
        return true
    }

    private func schedule(_ buffer: AVAudioPCMBuffer) {
        let frames = buffer.frameLength
        lock.lock()
        // Guest time can run ahead of the speaker. Drop excess new audio rather
        // than allowing the scheduled AVAudioPlayerNode queue to add latency.
        guard frames <= Self.maximumQueuedFrames - pendingFrames else {
            lock.unlock()
            return
        }
        pendingFrames += frames
        let shouldStart = !suspended && engine.isRunning && !playing && pendingFrames >= Self.prebufferFrames
        if shouldStart { playing = true }
        let scheduledGeneration = generation
        let shouldScheduleFallback = !suspended && !playing
        lock.unlock()
        player.scheduleBuffer(buffer) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            if self.generation == scheduledGeneration {
                self.pendingFrames = self.pendingFrames >= frames
                    ? self.pendingFrames - frames : 0
                self.completedFrames &+= UInt64(frames)
            }
            self.lock.unlock()
        }
        if shouldStart { player.play() }
        else if shouldScheduleFallback {
            DispatchQueue.global(qos: .userInitiated).asyncAfter(
                deadline: .now() + Self.shortToneStartDelay
            ) { [weak self] in
                self?.startIfQueued(generation: scheduledGeneration)
            }
        }
    }

    private func resetTimeline() {
        lock.lock()
        generation &+= 1
        pendingFrames = 0
        playing = false
        lock.unlock()
        player.stop()
        player.reset()
    }

    private func startIfQueued(generation expectedGeneration: UInt64) {
        lock.lock()
        guard !closed, !suspended, engine.isRunning, generation == expectedGeneration,
              !playing, pendingFrames > 0 else {
            lock.unlock()
            return
        }
        playing = true
        player.play()
        lock.unlock()
    }

    private func readUInt(_ data: Data, _ offset: Int, _ count: Int) -> UInt64 {
        (0..<count).reduce(UInt64(0)) { value, byte in
            value | (UInt64(data[offset + byte]) << (byte * 8))
        }
    }

    func close() {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return
        }
        closed = true
        generation &+= 1
        pendingFrames = 0
        playing = false
        lock.unlock()
        player.stop()
        engine.stop()
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }
}
