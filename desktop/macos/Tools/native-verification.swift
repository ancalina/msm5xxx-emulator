import AppKit
import ApplicationServices

// Run from the bundle root, or set MSM5XXX_BUNDLE. This tool never ships in the app.
let args = Array(CommandLine.arguments.dropFirst())
guard let first = args.first else { fatalError("Usage: swift native-verification.swift OUTPUT [SCREENSHOTS]") }
let output = URL(fileURLWithPath: first)
let screenshots = args.count > 1 ? URL(fileURLWithPath: args[1]) : output.appendingPathComponent("native")
let root = URL(fileURLWithPath: ProcessInfo.processInfo.environment["MSM5XXX_BUNDLE"] ?? FileManager.default.currentDirectoryPath).standardizedFileURL.path + "/"
try FileManager.default.createDirectory(at: screenshots, withIntermediateDirectories: true)
var seen = Set<String>(), lastInput = -1
var testedPID: pid_t?
var lastCapture: [String: TimeInterval] = [:]
var lastSave = ProcessInfo.processInfo.systemUptime - 2
func owned(_ app: NSRunningApplication?) -> Bool {
    app?.bundleIdentifier == "io.github.ancalina.MSM5xxx.desktop" && app?.executableURL?.path.hasPrefix(root) == true
}
func attribute(_ node: AXUIElement, _ key: String) -> CFTypeRef? {
    var result: CFTypeRef?
    return AXUIElementCopyAttributeValue(node, key as CFString, &result) == .success ? result : nil
}
func control(pid: pid_t, identifier: String, windowTitle: String) throws -> (AXUIElement, CGPoint) {
    let app = AXUIElementCreateApplication(pid)
    AXUIElementSetMessagingTimeout(app, 0.5)
    let windows = (attribute(app, "AXWindows") as? [AXUIElement]) ?? []
    let matching = windows.filter { (attribute($0, "AXTitle") as? String ?? "").hasPrefix(windowTitle) }
    var queue = windowTitle.isEmpty ? windows : matching
    var seen = Set<CFHashCode>(), visited = 0
    let deadline = ProcessInfo.processInfo.systemUptime + 15
    while !queue.isEmpty && visited < 2000 && ProcessInfo.processInfo.systemUptime < deadline {
        let node = queue.removeLast()
        guard seen.insert(CFHash(node)).inserted else { continue }; visited += 1
        if attribute(node, "AXIdentifier") as? String == identifier,
           let raw = attribute(node, "AXPosition"), CFGetTypeID(raw) == AXValueGetTypeID() {
            var point = CGPoint.zero, size = CGSize.zero
            if AXValueGetValue(raw as! AXValue, .cgPoint, &point) {
                if let rawSize = attribute(node, "AXSize"), CFGetTypeID(rawSize) == AXValueGetTypeID() { _ = AXValueGetValue(rawSize as! AXValue, .cgSize, &size) }
                if size.width > 0 && size.height > 0 { return (node, CGPoint(x: point.x + size.width / 2, y: point.y + size.height / 2)) }
            }
        }
        queue += (attribute(node, "AXChildren") as? [AXUIElement]) ?? []
    }
    throw NSError(domain: "Native verification", code: 4, userInfo: [NSLocalizedDescriptionKey: "Accessibility control not found: " + identifier])
}
func reply(_ value: [String: Any]) throws {
    try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).write(to: output.appendingPathComponent("input-response.json"), options: .atomic)
}
print("Native verification driver; event access:", CGPreflightPostEventAccess()); fflush(stdout)
var waitingForUnlock = false
while true {
    if FileManager.default.fileExists(atPath: output.appendingPathComponent("result.txt").path) { break }
    let locked = ((CGSessionCopyCurrentDictionary() as? [String: Any])?["CGSSessionScreenIsLocked"] as? NSNumber)?.boolValue == true
    if locked {
        if !waitingForUnlock { print("Waiting for desktop unlock"); fflush(stdout); waitingForUnlock = true }
        Thread.sleep(forTimeInterval: 1); continue
    }
    waitingForUnlock = false
    if let data = try? Data(contentsOf: output.appendingPathComponent("input-request.json")),
       let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
       let id = request["id"] as? Int, id != lastInput {
        lastInput = id
        do {
            guard CGPreflightPostEventAccess() else { throw NSError(domain: "Native verification", code: 1, userInfo: [NSLocalizedDescriptionKey: "The terminal running the native driver needs macOS event-posting access."]) }
            let pid = (request["pid"] as? NSNumber)?.int32Value ?? 0
            guard let app = NSRunningApplication(processIdentifier: pid), owned(app), app.isActive,
                  NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else {
                throw NSError(domain: "Native verification", code: 2, userInfo: [NSLocalizedDescriptionKey: "The requested emulator instance is not the active app."])
            }
            testedPID = pid
            var response: [String: Any] = ["id": id, "status": "PASS"]
            for item in (request["events"] as? [[String: Any]]) ?? [] {
                guard owned(app), app.isActive, NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else {
                    throw NSError(domain: "Native verification", code: 2, userInfo: [NSLocalizedDescriptionKey: "The requested emulator instance lost focus during native input."])
                }
                let type = item["type"] as? String ?? ""
                if type == "axLocate" || type == "axPress" {
                    guard AXIsProcessTrusted() else { throw NSError(domain: "Native verification", code: 6, userInfo: [NSLocalizedDescriptionKey: "The terminal running the driver needs macOS accessibility access."]) }
                    let (node, point) = try control(pid: pid, identifier: item["identifier"] as? String ?? "", windowTitle: request["window_title"] as? String ?? "")
                    response["x"] = Double(point.x); response["y"] = Double(point.y)
                    if type == "axPress", AXUIElementPerformAction(node, kAXPressAction as CFString) != .success {
                        throw NSError(domain: "Native verification", code: 5, userInfo: [NSLocalizedDescriptionKey: "Accessibility press failed."])
                    }
                    continue
                }
                let event: CGEvent?
                if type == "keyDown" || type == "keyUp" {
                    event = CGEvent(keyboardEventSource: nil, virtualKey: CGKeyCode(item["code"] as? Int ?? 0), keyDown: type == "keyDown")
                    event?.flags = CGEventFlags(rawValue: (item["flags"] as? NSNumber)?.uint64Value ?? 0)
                } else {
                    let types: [String: CGEventType] = ["leftDown": .leftMouseDown, "leftUp": .leftMouseUp, "leftDrag": .leftMouseDragged, "rightDown": .rightMouseDown, "rightUp": .rightMouseUp]
                    guard let mouseType = types[type] else { throw NSError(domain: "Native verification", code: 3, userInfo: [NSLocalizedDescriptionKey: "Unknown native event type."]) }
                    let point = CGPoint(x: (item["x"] as? NSNumber)?.doubleValue ?? 0, y: (item["y"] as? NSNumber)?.doubleValue ?? 0)
                    event = CGEvent(mouseEventSource: nil, mouseType: mouseType, mouseCursorPosition: point, mouseButton: type.hasPrefix("right") ? .right : .left)
                    event?.flags = CGEventFlags(rawValue: (item["flags"] as? NSNumber)?.uint64Value ?? 0)
                }
                event?.post(tap: .cghidEventTap)
                Thread.sleep(forTimeInterval: 0.02)
            }
            if let last = (request["events"] as? [[String: Any]])?.last,
               ((last["flags"] as? NSNumber)?.uint64Value ?? 0) != 0,
               owned(app), app.isActive, NSWorkspace.shared.frontmostApplication?.processIdentifier == pid,
               let neutral = CGEvent(mouseEventSource: nil, mouseType: .mouseMoved,
                                     mouseCursorPosition: CGEvent(source: nil)!.location, mouseButton: .left) {
                // A modified synthetic click leaves its flags in the session event state.
                neutral.flags = []
                neutral.post(tap: .cghidEventTap)
            }
            try reply(response)
            print("native input", id); fflush(stdout)
        } catch { try reply(["id": id, "error": error.localizedDescription]) }
    }
    let checks = (try? String(contentsOf: output.appendingPathComponent("checks.txt"), encoding: .utf8)) ?? ""
    for line in checks.split(separator: "\n") where line.hasPrefix("snapshot ") {
        let parts = line.split(separator: ",")
        guard parts.count > 1, let number = parts[1].split(separator: "=").last, let windowID = UInt32(number), !seen.contains(String(parts[0])) else { continue }
        let rows = (CGWindowListCopyWindowInfo(.optionIncludingWindow, windowID) as? [[String: Any]]) ?? []
        guard let row = rows.first(where: { ($0[kCGWindowNumber as String] as? NSNumber)?.uint32Value == windowID }), let pid = row[kCGWindowOwnerPID as String] as? pid_t, owned(NSRunningApplication(processIdentifier: pid)) else { continue }
        let name = String(parts[0].dropFirst(9))
        let now = ProcessInfo.processInfo.systemUptime
        guard now - (lastCapture[name] ?? -2) >= 1 else { continue }
        lastCapture[name] = now
        let capture = Process(); capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        capture.arguments = ["-x", "-o", "-l", String(windowID), screenshots.appendingPathComponent(name + ".png").path]
        try capture.run(); capture.waitUntilExit()
        if capture.terminationStatus == 0 { seen.insert(String(parts[0])); testedPID = pid }
        print("snapshot", name, capture.terminationStatus); fflush(stdout)
    }
    if checks.contains("NATIVE_SAVE_READY"), !FileManager.default.fileExists(atPath: output.appendingPathComponent("phone-capture.png").path), ProcessInfo.processInfo.systemUptime - lastSave > 1 {
        let ready = checks.split(separator: "\n").last { $0.hasPrefix("NATIVE_SAVE_READY") }
        let pid = ready?.split(separator: " ").first { $0.hasPrefix("pid=") }.flatMap { Int32($0.dropFirst(4)) }
        let windowID = ready?.split(separator: " ").first { $0.hasPrefix("window=") }.flatMap { UInt32($0.dropFirst(7)) }
        let windows = windowID.flatMap { CGWindowListCopyWindowInfo([.optionOnScreenOnly, .optionIncludingWindow], $0) as? [[String: Any]] } ?? []
        let panelVisible = windows.contains { row in
            (row[kCGWindowNumber as String] as? NSNumber)?.uint32Value == windowID && (row[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == pid
        }
        if panelVisible, let pid, let app = NSRunningApplication(processIdentifier: pid), owned(app), app.isActive,
           NSWorkspace.shared.frontmostApplication?.processIdentifier == pid, CGPreflightPostEventAccess() {
            for down in [true, false] {
                guard owned(app), app.isActive, NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else { break }
                let event = CGEvent(keyboardEventSource: nil, virtualKey: 36, keyDown: down)
                event?.flags = []
                event?.post(tap: .cghidEventTap)
                Thread.sleep(forTimeInterval: 0.02)
            }
            print("native Save"); fflush(stdout)
        }
        lastSave = ProcessInfo.processInfo.systemUptime
    }
    if FileManager.default.fileExists(atPath: output.appendingPathComponent("result.txt").path) { break }
    if let pid = testedPID, NSRunningApplication(processIdentifier: pid)?.isTerminated != false {
        try "FAIL: requested application exited before verification completed\n".write(to: output.appendingPathComponent("result.txt"), atomically: true, encoding: .utf8)
        break
    }
    Thread.sleep(forTimeInterval: 0.05)
}
