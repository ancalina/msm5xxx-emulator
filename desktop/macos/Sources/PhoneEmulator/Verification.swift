#if DEBUG
import AppKit
import SwiftUI
import ImageIO
import UniformTypeIdentifiers
import ApplicationServices

/// Environment options preserve SwiftUI's normal Launch Services open-application event.
var desktopDebugArguments: [String] {
    var arguments = CommandLine.arguments
    let environment = ProcessInfo.processInfo.environment
    if !arguments.contains("--verify") && !arguments.contains("--verify-feedback"),
       let samples = environment["MSM5XXX_VERIFY_SAMPLES"], let output = environment["MSM5XXX_VERIFY_OUTPUT"] {
        arguments += [environment["MSM5XXX_VERIFY_MODE"] == "feedback" ? "--verify-feedback" : "--verify", samples, output]
    }
    if !arguments.contains("--inspect"), let output = environment["MSM5XXX_INSPECT_OUTPUT"] { arguments += ["--inspect", output] }
    if environment["MSM5XXX_VERIFY_NATIVE_DRAG"] == "1", !arguments.contains("--verify-native-drag") { arguments.append("--verify-native-drag") }
    return arguments
}

/// Runs only in debug builds, with an explicit --verify SAMPLES OUTPUT invocation.
@MainActor enum VerificationHarness {
    private static var started = false
    static func armStartupCheckIfRequested() {
        let args = desktopDebugArguments
        guard let i = args.firstIndex(where: { $0 == "--verify" || $0 == "--verify-feedback" }), args.count > i + 2 else { return }
        let output = URL(fileURLWithPath: args[i + 2])
        var unlockedSeconds = 0
        let timer = Timer(timeInterval: 1, repeats: true) { timer in
            MainActor.assumeIsolated {
                if started { timer.invalidate(); return }
                guard !desktopLocked else { return }
                unlockedSeconds += 1
                guard unlockedSeconds >= 600 else { return }
                timer.invalidate()
                try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
                try? "FAIL: Library scene did not appear at launch\n".write(to: output.appendingPathComponent("result.txt"), atomically: true, encoding: .utf8)
                DispatchQueue.main.async { NSApp.terminate(nil) }
            }
        }
        RunLoop.main.add(timer, forMode: .common)
    }
    static func startIfRequested(library: LibraryModel) {
        let args = desktopDebugArguments
        guard let i = args.firstIndex(where: { $0 == "--verify" || $0 == "--verify-feedback" }), args.count > i + 2 else { return }
        guard !started else { return }; started = true
        let samples = URL(fileURLWithPath: args[i + 1]), output = URL(fileURLWithPath: args[i + 2])
        Task {
            let activity = ProcessInfo.processInfo.beginActivity(options: .userInitiated, reason: "Firmware verification")
            defer { ProcessInfo.processInfo.endActivity(activity) }
            do {
                try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
                if args.contains("--verify-feedback") { try await runFeedback(library, samples: samples, output: output) }
                else { try await run(library, samples: samples, output: output) }
                try "PASS\n".write(to: output.appendingPathComponent("result.txt"), atomically: true, encoding: .utf8)
            } catch {
                try? "FAIL: \(error.localizedDescription)\n".write(to: output.appendingPathComponent("result.txt"), atomically: true, encoding: .utf8)
            }
            for controller in library.windows.values { controller.session.sheet = nil }
            await pause(0.3)
            await library.shutdown()
            // Leave the current main-actor task before AppKit enters its termination loop.
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
    }
    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw BackendError(message: message) }
    }
    private static func pause(_ seconds: Double) async { try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000)) }
    private static var desktopLocked: Bool {
        ((CGSessionCopyCurrentDictionary() as? [String: Any])?["CGSSessionScreenIsLocked"] as? NSNumber)?.boolValue == true
    }
    private static func interactiveDesktop(_ output: URL) async {
        var waited = false
        while desktopLocked {
            if !waited { log("Waiting for an unlocked Mac desktop", output); waited = true }
            await pause(1)
        }
        if waited { NSApp.activate(ignoringOtherApps: true) }
    }
    private static func until(_ description: String, timeout: Double = 600, _ condition: () -> Bool) async throws {
        var elapsed = 0.0, previous = ProcessInfo.processInfo.systemUptime
        while !condition() {
            let now = ProcessInfo.processInfo.systemUptime
            if !desktopLocked { elapsed += now - previous }
            previous = now
            if elapsed > timeout { throw BackendError(message: "Timed out: " + description) }
            await pause(0.2)
        }
    }
    private static func log(_ text: String, _ output: URL) {
        let line = Data((text + "\n").utf8)
        let url = output.appendingPathComponent("checks.txt")
        if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) }
        if let file = try? FileHandle(forWritingTo: url) { _ = try? file.seekToEnd(); try? file.write(contentsOf: line); try? file.close() }
    }
    static func snapshot(_ window: NSWindow, _ name: String, _ output: URL) async throws {
        if desktopDebugArguments.contains("--verify") { await interactiveDesktop(output) }
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil); window.displayIfNeeded(); await pause(0.6)
        if LibraryModel.shared.windows.values.contains(where: { $0.secondaryWindow === window }) {
            try require(window.subtitle.contains(L("secondary_preview")) || window.subtitle.contains(L("secondary_unknown")), "Secondary window subtitle is missing its display note")
            log("PASS secondary subtitle note \(name): \(window.subtitle)", output)
        }
        guard let view = window.contentView?.superview,
              let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw BackendError(message: "No snapshot view: " + name) }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else { throw BackendError(message: "No snapshot PNG") }
        try png.write(to: output.appendingPathComponent(name + ".png"))
        log("snapshot \(name), window=\(window.windowNumber), content=\(window.phoneContentSize), subtitle=\(window.subtitle)", output)
        if !desktopDebugArguments.contains("--verify-feedback") {
        let accessibility = await Task.detached { () -> String in
            let app = AXUIElementCreateApplication(getpid())
            let enhanced = AXUIElementSetAttributeValue(app, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
            var windows: CFTypeRef?
            let read = AXUIElementCopyAttributeValue(app, kAXWindowsAttribute as CFString, &windows)
            return "enhanced=\(enhanced.rawValue), read=\(read.rawValue)"
        }.value
        log("accessibility API " + accessibility, output)
        }
        try await auditAccessibility(window, name, output)
        // Allow the external native-window capture to finish before the next UI action.
        if desktopDebugArguments.contains("--verify-native-drag") { await pause(0.4) }
    }
    private static func auditAccessibility(_ window: NSWindow, _ name: String, _ output: URL) async throws {
        let title = window.sheetParent?.title ?? window.title
        let rows = await Task.detached { () -> [[String: String]] in
            let app = AXUIElementCreateApplication(getpid())
            AXUIElementSetMessagingTimeout(app, 0.5)
            func value(_ node: AXUIElement, _ key: String) -> CFTypeRef? {
                var result: CFTypeRef?
                return AXUIElementCopyAttributeValue(node, key as CFString, &result) == .success ? result : nil
            }
            func string(_ node: AXUIElement, _ key: String) -> String { value(node, key) as? String ?? "" }
            let windows = (value(app, "AXWindows") as? [AXUIElement]) ?? []
            let matching = title.isEmpty ? [] : windows.filter { string($0, "AXTitle").hasPrefix(title) }
            let roots = matching.isEmpty ? windows : matching
            var rows: [[String: String]] = [], seen = Set<CFHashCode>(), visited = 0
            func visit(_ node: AXUIElement, _ depth: Int, parentRole: String = "", nativeScrollPart: Bool = false) {
                guard depth < 30, visited < 1000, seen.insert(CFHash(node)).inserted else { return }
                visited += 1
                var row: [String: String] = [:]
                for (attribute, key) in [("AXRole", "accessibilityRole"), ("AXSubrole", "accessibilitySubrole"), ("AXTitle", "accessibilityTitle"), ("AXDescription", "accessibilityLabel"), ("AXHelp", "accessibilityHelp"), ("AXValue", "accessibilityValue"), ("AXIdentifier", "accessibilityIdentifier")] {
                    let text = string(node, attribute)
                    if !text.isEmpty { row[key] = text }
                }
                if let associated = value(node, "AXTitleUIElement"), CFGetTypeID(associated) == AXUIElementGetTypeID() {
                    let element = associated as! AXUIElement
                    row["associatedTitle"] = string(element, "AXValue") + string(element, "AXTitle")
                }
                let role = string(node, "AXRole")
                row["parentRole"] = parentRole
                if nativeScrollPart { row["nativeScrollPart"] = "true" }
                if let raw = value(node, "AXPosition"), CFGetTypeID(raw) == AXValueGetTypeID() {
                    var point = CGPoint.zero
                    if AXValueGetValue(raw as! AXValue, .cgPoint, &point) { row["x"] = String(Double(point.x)); row["y"] = String(Double(point.y)) }
                }
                if let raw = value(node, "AXSize"), CFGetTypeID(raw) == AXValueGetTypeID() {
                    var size = CGSize.zero
                    if AXValueGetValue(raw as! AXValue, .cgSize, &size) { row["width"] = String(Double(size.width)); row["height"] = String(Double(size.height)) }
                }
                rows.append(row)
                for child in (value(node, "AXChildren") as? [AXUIElement]) ?? [] {
                    visit(child, depth + 1, parentRole: role, nativeScrollPart: nativeScrollPart || role == "AXScrollBar")
                }
            }
            for root in roots { visit(root, 0) }
            return rows
        }.value
        if desktopLocked && desktopDebugArguments.contains("--verify") {
            await interactiveDesktop(output)
            try await auditAccessibility(window, name, output)
            return
        }
        let json = try JSONSerialization.data(withJSONObject: rows, options: [.prettyPrinted, .sortedKeys])
        try json.write(to: output.appendingPathComponent(name + "-accessibility.json"))
        let roles = Set(["AXButton", "AXMenuButton", "AXCheckBox", "AXRadioButton", "AXPopUpButton", "AXTextField", "AXComboBox"])
        // NSScroller exposes virtual implementation parts; the native scroll area owns their semantics.
        // Keep them in the evidence, while naming acceptance applies to app/window controls.
        let controls = rows.filter { roles.contains($0["accessibilityRole"] ?? "") && $0["nativeScrollPart"] != "true" }
        let nativeParts = rows.filter { $0["nativeScrollPart"] == "true" }.count
        if nativeParts > 0 { log("accessibility \(name): \(nativeParts) native scrollbar parts recorded separately", output) }
        let unnamed = controls.filter { row in
            ["accessibilityLabel", "accessibilityTitle", "accessibilityHelp", "associatedTitle", "accessibilitySubrole"].allSatisfy { row[$0]?.isEmpty ?? true }
        }
        log("accessibility \(name): \(controls.count) exposed controls, \(unnamed.count) without names", output)
        let phoneKeys = rows.filter { $0["accessibilityIdentifier"]?.hasPrefix("phone-key-") == true }
        if let controller = LibraryModel.shared.windows.values.first(where: { $0.window === window }), !phoneKeys.isEmpty {
            let commandIDs = Set(["emulator-power", "emulator-actions"])
            let commands = rows.filter { commandIDs.contains($0["accessibilityIdentifier"] ?? "") }
            try require(Set(commands.compactMap { $0["accessibilityIdentifier"] }) == commandIDs, "A primary toolbar command is missing or overflowed")
            let top = NSScreen.screens[0].frame.maxY - window.frame.maxY
            let chrome = window.frame.height - window.phoneContentSize.height
            for item in commands {
                let x = Double(item["x"] ?? "") ?? -1, y = Double(item["y"] ?? "") ?? -1
                let width = Double(item["width"] ?? "") ?? 0, height = Double(item["height"] ?? "") ?? 0
                try require(width > 0 && height > 0 && x >= window.frame.minX - 1 && x + width <= window.frame.maxX + 1 && y >= top - 1 && y + height <= top + chrome + 1, "A primary toolbar command is outside the visible title bar")
            }
            log("PASS two visible primary-action toolbar controls \(name)", output)
            let keys = controller.session.layout["keys"].array
            let digits = phoneKeys.filter { row in
                keys.contains { "phone-key-\($0["bit"].int)" == row["accessibilityIdentifier"] && (1...3).contains($0["column"].int) }
            }
            let widths = digits.compactMap { Double($0["width"] ?? "") }
            let heights = phoneKeys.compactMap { Double($0["height"] ?? "") }
            try require(widths.count == digits.count && !widths.isEmpty, "Missing keypad accessibility bounds")
            try require((widths.max()! - widths.min()!) < 1, "Keypad columns 1–3 have different widths")
            try require(heights.allSatisfy { abs($0 - Double(controller.session.keypad.rowHeight)) < 1 }, "Keypad buttons have different heights")
            log("PASS keypad bounds \(name): columns 1–3 width=\(widths[0]), button height=\(heights.first ?? 0)", output)
        }
        if !desktopDebugArguments.contains("--verify") { return }
        try require(!rows.isEmpty, "No exposed accessibility tree in " + name)
        try require(unnamed.isEmpty, "Unnamed exposed accessibility controls in " + name)
        if !name.hasPrefix("secondary") { try require(controls.count >= 3, "Accessibility traversal found no controls in " + name) }
    }
    private static func descendants(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(descendants) }
    private static var inputID = 0
    @discardableResult private static func nativeEvents(_ events: [JSON], output: URL) async throws -> JSON {
        await interactiveDesktop(output)
        inputID += 1
        let id = inputID
        let request = JSON.object(["id": .integer(id), "pid": .integer(Int(getpid())), "window_title": .string(NSApp.keyWindow?.sheetParent?.title ?? NSApp.keyWindow?.title ?? ""), "events": .array(events)])
        try JSONEncoder().encode(request).write(to: output.appendingPathComponent("input-request.json"), options: .atomic)
        log("NATIVE_INPUT_READY id=\(id)", output)
        var response: JSON = .null
        try await until("external native input driver", timeout: 1200) {
            guard let data = try? Data(contentsOf: output.appendingPathComponent("input-response.json")),
                  let value = try? JSONDecoder().decode(JSON.self, from: data), value["id"].int == id else { return false }
            response = value; return true
        }
        try require(response["error"].string.isEmpty, response["error"].string)
        return response
    }
    private static func pointer(_ type: String, _ point: CGPoint, flags: CGEventFlags = []) -> JSON {
        .object(["type": .string(type), "x": .number(Double(point.x)), "y": .number(Double(point.y)), "flags": .number(Double(flags.rawValue))])
    }
    private static func accessibleControl(_ identifier: String, press: Bool, output: URL) async throws -> CGPoint {
        let response = try await nativeEvents([.object(["type": .string(press ? "axPress" : "axLocate"), "identifier": .string(identifier)])], output: output)
        return CGPoint(x: Double(response["x"].int), y: Double(response["y"].int))
    }
    static func pressKey(_ session: SessionModel, bit: Int, output: URL) async throws {
        _ = try await accessibleControl("phone-key-\(bit)", press: true, output: output)
    }
    private static func keyPosition(_ bit: Int, output: URL) async throws -> CGPoint {
        try await accessibleControl("phone-key-\(bit)", press: false, output: output)
    }
    private static func settingsScene(_ library: LibraryModel, from source: NSWindow, device: EmulatorSceneModel? = nil, output: URL) async throws -> NSWindow {
        source.makeMain(); source.makeKeyAndOrderFront(nil); await pause(0.3)
        NSApp.mainMenu?.update()
        let shortcut = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command,
                                      timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: source.windowNumber,
                                      context: nil, characters: ",", charactersIgnoringModifiers: ",", isARepeat: false, keyCode: 43)!
        if desktopDebugArguments.contains("--verify") {
            try await nativeEvents([.object(["type": .string("keyDown"), "code": .integer(43), "flags": .number(Double(CGEventFlags.maskCommand.rawValue))]),
                                    .object(["type": .string("keyUp"), "code": .integer(43), "flags": .number(Double(CGEventFlags.maskCommand.rawValue))])], output: output)
        } else {
            try require(NSApp.mainMenu?.performKeyEquivalent(with: shortcut) == true, "Settings shortcut missing")
            library.settingsEmulator = device
        }
        try await until("Settings scene") { library.settingsWindow?.isVisible == true }
        try require(library.settingsEmulator === device, "Settings context does not match source=\(source.title), key=\(NSApp.keyWindow?.title ?? ""), main=\(NSApp.mainWindow?.title ?? ""), target=\(library.settingsEmulator?.session.title ?? "General")")
        await pause(1)
        return library.settingsWindow!
    }
    private static func checkOpening(_ controller: EmulatorSceneModel, _ output: URL, _ name: String) async throws {
        guard let window = controller.window else { throw BackendError(message: "Missing window") }
        let session = controller.session, size = window.phoneContentSize
        log("Geometry \(name): LCD=\(session.lcdSize), natural=\(controller.naturalContentWidth), content=\(size), opening=\(controller.openingContentSize), min=\(window.contentMinSize)", output)
        let scale = max(1, ceil(controller.naturalContentWidth / session.lcdSize.width))
        try require(abs(size.width - session.lcdSize.width * scale) < 1, "Opening scale is not the smallest natural whole scale")
        if ["x350.bin", "a640.bin"].contains(URL(fileURLWithPath: session.firmware.id).lastPathComponent.lowercased()) {
            try require(abs(size.width - 384) < 1, "Sample opening must remain 384 points wide in every language")
            let expectedHeight = session.lcdSize.height == 128 ? 784.0 : 880.0
            try require(abs(window.frame.height - expectedHeight) < 1, "Sample opening height differs from the required natural size")
        }
        try require(abs(size.height - size.width * session.lcdSize.height / session.lcdSize.width - session.keypad.height) < 1, "LCD does not meet keypad")
        try require(window.contentMinSize.width >= controller.openingContentSize.width && window.contentMinSize.height >= controller.openingContentSize.height, "Opening size is not the minimum")
        try require(window.titlebarAccessoryViewControllers.isEmpty, "Extra titlebar row")
        try require(window.subtitle.isEmpty, "Emulator title bar must contain the model only")
        let reduced = controller.constrainedFrameSize(NSSize(width: 200, height: 200))
        let reducedContent = window.contentRect(forFrameRect: NSRect(origin: .zero, size: reduced)).size
        try require(reducedContent.width >= size.width && reducedContent.height >= size.height, "Window can shrink below opening size")
        window.setContentSize(NSSize(width: 200, height: 300))
        try require(window.phoneContentSize.width >= controller.openingContentSize.width && window.phoneContentSize.height >= controller.openingContentSize.height, "setContentSize bypasses opening minimum")
        var tiny = window.frame; tiny.size = NSSize(width: 200, height: 300)
        window.setFrame(tiny, display: true)
        try require(window.phoneContentSize.width >= controller.openingContentSize.width && window.phoneContentSize.height >= controller.openingContentSize.height, "setFrame bypasses opening minimum")
        window.setFrame(tiny, display: true, animate: false)
        try require(window.phoneContentSize.width >= controller.openingContentSize.width && window.phoneContentSize.height >= controller.openingContentSize.height, "animated setFrame bypasses opening minimum")
        window.setPhoneContentSize(controller.openingContentSize)
        log("PASS 200×300 programmatic shrink requests: resulting content=\(window.phoneContentSize)", output)
        for button in descendants(window.contentView!).compactMap({ $0 as? NSButton }) where !button.isHidden {
            try require(button.bounds.width + 1 >= button.fittingSize.width, "Compressed button: " + button.title)
        }
        log("PASS natural opening \(name): LCD=\(session.lcdSize), natural=\(controller.naturalContentWidth), content=\(size), min=\(window.contentMinSize)", output)
        try await snapshot(window, name, output)
    }
    private static func checkSecondary(_ controller: EmulatorSceneModel, _ output: URL) async throws {
        guard let main = controller.window, let child = controller.secondaryWindow, let dock = controller.secondaryDock,
              let image = controller.session.secondary.frame else { throw BackendError(message: "Missing secondary") }
        let native = CGSize(width: image.width, height: image.height)
        try require(!child.styleMask.contains(.fullSizeContentView), "Secondary content aspect includes the title bar")
        try require(child.styleMask.contains(.resizable) && child.contentMinSize.width >= native.width && child.contentMinSize.height >= native.height && child.contentAspectRatio == native, "Secondary resize constraints")
        try require(child.phoneContentSize == CGSize(width: image.width * 3, height: image.height * 3), "Secondary opening is not 3×")
        child.setPhoneContentSize(CGSize(width: image.width * 4, height: image.height * 4))
        try await snapshot(child, "secondary-resized-en-light", output)
        for side in [DockSide.right, .left] {
            var near = dock.expectedFrame(side); near.origin.x += 8
            dock.dragForVerification(to: near); await pause(0.3)
            try require(dock.side == side && child.parent === main, "Secondary did not attach \(side)")
            let expected = dock.expectedFrame(side)
            try require(abs(child.frame.minX - expected.minX) < 1 && abs(child.frame.minY - expected.minY) < 1, "Secondary is not flush and content-top aligned")
            let before = child.frame.origin
            main.setFrameOrigin(NSPoint(x: main.frame.minX + 30, y: main.frame.minY - 10)); await pause(0.3)
            try require(abs(child.frame.minX - before.x - 30) < 1 && abs(child.frame.minY - before.y + 10) < 1, "Child did not follow main")
            try await snapshot(main, "docked-\(side)-en-light", output)
            main.miniaturize(nil); await pause(0.8)
            try require(main.isMiniaturized && !child.isVisible, "Child did not follow minimization")
            main.deminiaturize(nil); await pause(0.8)
            try require(child.isVisible && child.parent === main, "Child did not restore")
            var away = child.frame; away.origin.x += side == .right ? 60 : -60
            dock.dragForVerification(to: away); await pause(0.3)
            try require(child.parent == nil && dock.side == nil, "Secondary did not detach")
        }
        dock.attach(.right); await pause(0.4)
        try require(AppPreferences.shared.side(for: controller.session.firmware.id) == .right, "Dock side not saved")
        child.performClose(nil); await pause(0.5); controller.showSecondary()
        try await until("Secondary scene reopened") { controller.secondaryWindow?.isVisible == true }
        await pause(0.5)
        let visibleDisplays = NSApp.windows.filter { $0.isVisible && $0.identifier?.rawValue == "secondary:" + controller.session.firmware.id }
        try require(visibleDisplays.count == 1, "Reopening created duplicate secondary windows")
        try require(controller.secondaryWindow?.parent === main && controller.secondaryDock?.side == .right, "Remembered dock side did not reopen")
        let prefs = AppPreferences.shared
        try await prefs.setIcon(.simple)
        let simple = NSApp.applicationIconImage.tiffRepresentation
        try require(simple != nil, "Simple Dock icon missing")
        try await prefs.setIcon(.full)
        try require(NSApp.applicationIconImage.tiffRepresentation != simple, "Dock icon did not switch")
        if desktopDebugArguments.contains("--verify-native-drag") {
            log("NATIVE_DRAG_READY main=\(main.windowNumber) child=\(child.windowNumber)", output)
            let failed = output.appendingPathComponent("native-drag.failed")
            try await until("native drag verification", timeout: 1200) {
                FileManager.default.fileExists(atPath: output.appendingPathComponent("native-drag.done").path) || FileManager.default.fileExists(atPath: failed.path)
            }
            if FileManager.default.fileExists(atPath: failed.path) { throw BackendError(message: (try? String(contentsOf: failed, encoding: .utf8)) ?? "Native drag verification failed") }
        }
        log("PASS secondary 3×, 1× minimum, aspect ratio, resize, both snap sides, follow, minimize/restore, detach, remembered side and live Dock icon", output)
    }
    private static func runFeedback(_ library: LibraryModel, samples: URL, output: URL) async throws {
        NSApp.appearance = NSAppearance(named: .aqua)
        try await until("library initialized") { !library.settings.isEmpty && !library.scanning }
        guard let launcher = NSApp.windows.first(where: { $0.title == L("library_title") }) else { throw BackendError(message: "Missing library") }
        try await library.set("persistent_state", value: .bool(false))
        try await library.set("ui_language", value: .string("en"))
        try await library.set("virtual_network", value: .bool(true))
        for filename in ["x350.bin", "a640.bin"] {
            NSApp.appearance = NSAppearance(named: .aqua)
            try await library.set("ui_language", value: .string("en"))
            let path = samples.appendingPathComponent(filename).path
            await library.mutate("library.add_file", path: path)
            guard let firmware = library.entries.first(where: { $0.id == path }) else { throw BackendError(message: "Missing firmware") }
            library.open(firmware)
            try await until("emulator scene") { library.windows.values.contains { $0.session.firmware.id == path && $0.window != nil } }
            guard let controller = library.windows.values.first(where: { $0.session.firmware.id == path }), let window = controller.window else { throw BackendError(message: "Missing emulator") }
            let session = controller.session
            try await until("firmware display") { session.running && !session.busy && session.display.frame != nil || !session.error.isEmpty }
            try require(session.running && session.error.isEmpty, session.error)
            let expected = filename == "x350.bin" ? CGSize(width: 128, height: 128) : CGSize(width: 128, height: 160)
            try await until("real LCD") { session.lcdSize == expected }
            await pause(3)
            try await checkOpening(controller, output, filename + "-opening-en-light")
            if filename == "x350.bin" {
                if session.state["fold"].bool { await session.action("session.fold") }
                try await until("secondary display") { session.secondary.frame != nil }
                controller.showSecondary()
                try await until("secondary scene") { controller.secondaryWindow != nil }
                try await snapshot(controller.secondaryWindow!, "secondary-opening-en-light", output)
                try await checkSecondary(controller, output)
            }
            session.sheet = .info; await pause(0.8)
            if let info = window.sheets.first { try await snapshot(info, filename + "-info-en-light", output) }
            session.sheet = nil; await pause(0.3)
            var wider = window.frame
            wider.size = controller.constrainedFrameSize(NSSize(width: wider.width + 96, height: wider.height))
            window.setFrame(wider, display: true)
            try await snapshot(window, filename + "-wider-en-light", output)
            for language in ["en", "ko"] {
                try await library.set("ui_language", value: .string(language))
                for (theme, appearance) in [("light", NSAppearance.Name.aqua), ("dark", NSAppearance.Name.darkAqua)] {
                    NSApp.appearance = NSAppearance(named: appearance)
                    window.setPhoneContentSize(controller.openingContentSize)
                    try await checkOpening(controller, output, filename + "-opening-" + language + "-" + theme)
                    try await snapshot(launcher, "library-" + language + "-" + theme, output)
                    let hardware = try await settingsScene(library, from: window, device: controller, output: output)
                    try await snapshot(hardware, "settings-" + filename + "-" + language + "-" + theme, output)
                    hardware.performClose(nil); await pause(0.4)
                    let general = try await settingsScene(library, from: launcher, output: output)
                    try await snapshot(general, "general-settings-" + filename + "-" + language + "-" + theme, output)
                    general.performClose(nil)
                    if controller.secondaryWindow != nil {
                        controller.showSecondary()
                        try await snapshot(controller.secondaryWindow!, "secondary-" + language + "-" + theme, output)
                    }
                }
            }
            await session.close(); window.orderOut(nil); controller.secondaryWindow?.orderOut(nil)
            try require(!session.running && session.closed, "Guest did not close")
            log("PASS feedback firmware " + filename, output)
        }
        log("PASS feedback mechanics and snapshots; unlocked interactive acceptance remains separate", output)
    }
    private static func run(_ library: LibraryModel, samples: URL, output: URL) async throws {
        var announcedLock = false
        while ((CGSessionCopyCurrentDictionary() as? [String: Any])?["CGSSessionScreenIsLocked"] as? NSNumber)?.boolValue == true {
            if !announcedLock { log("Waiting for an unlocked Mac desktop before interactive verification", output); announcedLock = true }
            await pause(1)
        }
        try await until("library window at launch", timeout: 30) { NSApp.windows.contains { $0.isVisible } }
        try await until("library initialization") { !library.settings.isEmpty && !library.scanning }
        try require(library.entries.isEmpty, "Verification requires a fresh MSM5XXX_STATE_DIR")
        guard let launcher = NSApp.windows.first(where: { $0.isVisible }) else { throw BackendError(message: "Missing library window") }
        NSApp.appearance = NSAppearance(named: .aqua)
        try await library.set("ui_language", value: .string("en"))
        try await snapshot(launcher, "library-empty-en-light", output)
        let x350 = samples.appendingPathComponent("x350.bin").path
        let a640 = samples.appendingPathComponent("a640.bin").path
        for path in [x350, a640] { await library.mutate("library.add_file", path: path) }
        try require(library.entries.count == 2, "Import and scan must return two firmware entries")
        await library.mutate("library.add_folder", path: samples.path)
        try require(library.folders.contains(samples.path), "Folder import failed")
        await library.mutate("library.remove_folder", path: samples.path)
        try require(!library.folders.contains(samples.path), "Folder removal failed")
        try await library.set("persistent_state", value: .bool(false))
        try await library.set("virtual_network", value: .bool(true))
        try await library.set("experimental_rex", value: .bool(false))
        try await library.set("ui_language", value: .string("en"))
        try await library.set("network_start_time", value: .string("2005-01-02 03:04"))
        do { try await library.set("network_start_time", value: .string("invalid")); throw BackendError(message: "Invalid network time accepted") }
        catch { try require(error.localizedDescription != "Invalid network time accepted", error.localizedDescription) }
        try await snapshot(launcher, "library-en-light", output)
        log("PASS library import, folder add/remove, real scan, app-wide settings, network time validation", output)
        guard let firmware = library.entries.first(where: { $0.id == x350 }) else { throw BackendError(message: "Missing X350 entry") }
        library.open(firmware)
        try await until("emulator scene") { library.windows.values.contains { $0.window != nil } }
        guard let controller = library.windows.values.first, let window = controller.window else { throw BackendError(message: "Missing emulator window") }
        let session = controller.session
        try await until("X350 start and first LCD frame") { session.running && !session.busy && session.display.frame != nil || !session.error.isEmpty }
        try require(session.running && session.error.isEmpty, session.error)
        try await until("X350 real LCD geometry") { session.lcdSize == CGSize(width: 128, height: 128) }
        await pause(15)
        let originalCount = library.windows.count
        library.open(firmware)
        try require(library.windows.count == originalCount, "Repeated open created another session")
        let expectedScale = ceil(controller.naturalContentWidth / session.lcdSize.width)
        try require(abs((window.phoneContentSize.width) - session.lcdSize.width * expectedScale) < 1, "Opening width is not the minimum whole-number scale")
        try require(window.toolbar != nil && window.toolbar!.items.count >= 2, "Missing emulator toolbar")
        try await snapshot(window, "emulator-open-en-light", output)
        try await checkOpening(controller, output, "x350-opening-en-light")
        log("Opening native PNG save panel", output)
        let acceptCapture = Timer(timeInterval: 1.5, repeats: true) { timer in
            MainActor.assumeIsolated {
                if let panel = session.capturePanel, panel.isVisible, panel.url != nil {
                    log("NATIVE_SAVE_READY window=\(panel.windowNumber) pid=\(getpid())", output)
                    timer.invalidate()
                } else if session.capturePanel == nil { timer.invalidate() }
            }
        }
        RunLoop.main.add(acceptCapture, forMode: .common)
        RunLoop.main.add(acceptCapture, forMode: .modalPanel)
        session.capture(directory: output, filename: "phone-capture.png")
        let captureURL = output.appendingPathComponent("phone-capture.png")
        try await until("PNG capture saved", timeout: 1200) { FileManager.default.fileExists(atPath: captureURL.path) }
        let source = CGImageSourceCreateWithURL(captureURL as CFURL, nil)
        let properties = source.flatMap { CGImageSourceCopyPropertiesAtIndex($0, 0, nil) as? [CFString: Any] }
        try require(properties?[kCGImagePropertyPixelWidth] as? Int == Int(session.lcdSize.width), "PNG capture width differs from LCD")
        try require(properties?[kCGImagePropertyPixelHeight] as? Int == Int(session.lcdSize.height), "PNG capture height differs from LCD")
        log("PASS native PNG save panel and original LCD resolution", output)
        let target = controller.constrainedFrameSize(NSSize(width: window.frame.width + 96, height: window.frame.height))
        var frame = window.frame; frame.size = target; window.setFrame(frame, display: true)
        try await snapshot(window, "emulator-wider-en-light", output)
        frame.size.height += 80; window.setFrame(frame, display: true)
        try await snapshot(window, "emulator-taller-en-light", output)
        window.makeKeyAndOrderFront(nil)
        let screen = NSScreen.screens[0].frame.maxY
        let lcdPoint = window.convertToScreen(NSRect(x: window.contentLayoutRect.midX, y: window.contentLayoutRect.maxY - 40, width: 1, height: 1)).origin
        let click = CGPoint(x: lcdPoint.x, y: screen - lcdPoint.y)
        try await nativeEvents([pointer("leftDown", click), pointer("leftUp", click)], output: output)
        await pause(0.3)
        func key(_ down: Bool, flags: CGEventFlags = []) -> JSON {
            .object(["type": .string(down ? "keyDown" : "keyUp"), "code": .integer(18), "flags": .number(Double(flags.rawValue))])
        }
        let traceStart = session.backend.trace.snapshot.count
        try await nativeEvents([key(true), key(false)], output: output); await pause(0.5)
        let events = Array(session.backend.trace.snapshot.dropFirst(traceStart))
        log("Keyboard diagnostics: responder=\(String(describing: window.firstResponder)), handlers=\(session.keyboardObservations), backend=\(events.map { String(describing: $0.params) })", output)
        try require(events.count == 2 && events[0].params["pressed"]?.bool == true && events[1].params["pressed"]?.bool == false, "SwiftUI onKeyPress must send press and release")
        try require(events[1].time - events[0].time >= session.hold, "Key tap was shorter than key_hold_ms")
        try await nativeEvents([key(true)], output: output); await pause(0.1); launcher.makeKeyAndOrderFront(nil); await pause(0.4)
        try require(session.backend.trace.snapshot.last?.params["pressed"]?.bool == false, "Focus loss did not release held key")
        window.makeKeyAndOrderFront(nil); await pause(0.2)
        let beforeShortcut = session.backend.trace.snapshot.count
        try await nativeEvents([key(true, flags: .maskCommand), key(false, flags: .maskCommand)], output: output); await pause(0.2)
        try require(session.backend.trace.snapshot.count == beforeShortcut, "Command shortcut was captured")
        log("PASS SwiftUI keyboard event path, minimum hold, focus release and shortcut forwarding", output)
        window.makeKeyAndOrderFront(nil); await pause(0.2)
        let enabled = session.layout["keys"].array.first { session.enabled($0["bit"].int) }!["bit"].int
        try await pressKey(session, bit: enabled, output: output); await pause(0.3)
        let point = try await keyPosition(enabled, output: output)
        let begin = session.backend.trace.snapshot.count
        try await nativeEvents([pointer("leftDown", point)], output: output)
        await pause(0.4)
        let down = Array(session.backend.trace.snapshot.dropFirst(begin))
        try require(down.count == 1 && down[0].params["pressed"]?.bool == true, "SwiftUI pointer key must remain pressed")
        let outside = CGPoint(x: window.frame.minX - 8, y: screen - window.frame.minY + 8)
        try await nativeEvents([pointer("leftDrag", outside), pointer("leftUp", outside)], output: output)
        await pause(0.3)
        let completed = Array(session.backend.trace.snapshot.dropFirst(begin))
        try require(completed.count == 2 && completed[1].params["pressed"]?.bool == false, "Pointer drag-out/up did not release key")
        log("PASS SwiftUI Button accessibility press and pointer down/drag-out/up routing", output)
        let beforeMapping = session.backend.trace.snapshot.count
        try await nativeEvents([pointer("rightDown", point), pointer("rightUp", point)], output: output)
        try await until("secondary click opens key mapping") { session.sheet == .mapping && !window.sheets.isEmpty }
        try require(session.backend.trace.snapshot.count == beforeMapping, "Secondary click sent a guest key")
        try await snapshot(window.sheets[0], "secondary-click-mapping-en-light", output)
        session.sheet = nil; await pause(0.4)
        log("PASS immediate secondary-click mapping without a guest key event", output)
        try await nativeEvents([pointer("leftDown", point, flags: .maskControl), pointer("leftUp", point, flags: .maskControl)], output: output)
        try await until("Control-click opens key mapping") { session.sheet == .mapping && !window.sheets.isEmpty }
        try require(session.backend.trace.snapshot.count == beforeMapping, "Control-click sent a guest key")
        session.sheet = nil; await pause(0.4)
        log("PASS Control-click mapping without a guest key event", output)
        let bit = session.layout["keys"].array.first!["bit"].int
        let originalMapping = try await session.backend.call("session.key_mapping", ["bit": .integer(bit)])
        _ = try await session.backend.call("session.set_key_mapping", ["bit": .integer(bit), "value": .string("0x11")])
        let changedMapping = try await session.backend.call("session.key_mapping", ["bit": .integer(bit)])
        try require(changedMapping.int == 17, "Mapping was not saved")
        _ = try await session.backend.call("session.set_key_mapping", ["bit": .integer(bit), "value": .string(originalMapping.isNull ? "" : originalMapping.text)])
        do {
            _ = try await session.backend.call("session.set_key_mapping", ["bit": .integer(bit), "value": .string("0x100")])
            throw BackendError(message: "Invalid mapping accepted")
        } catch { try require(error.localizedDescription != "Invalid mapping accepted", error.localizedDescription) }
        if !session.state["fold"].isNull {
            let previous = session.state["fold"].bool
            await session.action("session.fold")
            try await until("lid toggle") { session.state["fold"].bool != previous }
        }
        try await until("qualified secondary display", timeout: 600) { session.secondary.frame != nil }
        controller.showSecondary()
        try await until("secondary scene") { controller.secondaryWindow != nil }
        if let secondary = NSApp.windows.first(where: { $0.identifier?.rawValue.hasPrefix("secondary:") == true }) {
            try require(secondary.styleMask.contains(.resizable), "Secondary window must resize")
            try await snapshot(secondary, "secondary-en-light", output)
            try await checkSecondary(controller, output)
        }
        if session.state["fold"].bool == false && !session.state["fold"].isNull { await session.action("session.fold") }
        let hardware = try await session.backend.call("session.settings")
        var values: [String: JSON] = [:]
        for section in hardware["sections"].array { for field in section["fields"].array { values[field["name"].string] = .string(field["value"].text) } }
        let validValues = values
        values["width"] = .string("0")
        do { _ = try await session.backend.call("session.apply_settings", ["values": .object(values)]); throw BackendError(message: "Invalid hardware values accepted") }
        catch { try require(error.localizedDescription != "Invalid hardware values accepted", error.localizedDescription) }
        _ = try await session.backend.call("session.apply_settings", ["values": .object(validValues)])
        await session.reboot()
        try await until("restart first frame") { session.display.frame != nil || !session.error.isEmpty }
        try require(session.running && session.error.isEmpty, session.error)
        let hardwareWindow = try await settingsScene(library, from: window, device: controller, output: output)
        try await snapshot(hardwareWindow, "settings-en-light", output)
        hardwareWindow.performClose(nil); await pause(0.5)
        try await library.set("network_host_time", value: .bool(false)); await session.action("session.network_time")
        try await library.set("network_host_time", value: .bool(true)); await session.action("session.network_time")
        session.editing = true; window.makeKeyAndOrderFront(nil); await pause(0.5)
        _ = try await accessibleControl("editing-done", press: false, output: output)
        try await snapshot(window, "key-layout-en-light", output)
        try await pressKey(session, bit: bit, output: output)
        try await until("key mapping sheet") { session.sheet == .mapping && !window.sheets.isEmpty }
        try await snapshot(window.sheets[0], "key-mapping-en-light", output)
        session.sheet = nil; await pause(0.4)
        window.makeKeyAndOrderFront(nil); await pause(0.2)
        _ = try await accessibleControl("editing-done", press: true, output: output)
        try await until("Done exits edit mode") { !session.editing }
        for language in ["en", "ko"] {
            try await library.set("ui_language", value: .string(language))
            for (theme, appearance) in [("light", NSAppearance.Name.aqua), ("dark", NSAppearance.Name.darkAqua)] {
                NSApp.appearance = NSAppearance(named: appearance); await pause(0.5)
                try await snapshot(launcher, "library-\(language)-\(theme)", output)
                try await snapshot(window, "emulator-\(language)-\(theme)", output)
                let hardware = try await settingsScene(library, from: window, device: controller, output: output)
                try await snapshot(hardware, "settings-\(language)-\(theme)", output)
                hardware.performClose(nil); await pause(0.4)
                controller.showSecondary()
                if let secondary = NSApp.windows.first(where: { $0.identifier?.rawValue.hasPrefix("secondary:") == true }) {
                    try await snapshot(secondary, "secondary-\(language)-\(theme)", output)
                }
                let general = try await settingsScene(library, from: launcher, output: output)
                try await snapshot(general, "general-settings-\(language)-\(theme)", output)
                general.performClose(nil)
            }
        }
        log("PASS mapping validation/save/restore, lid, secondary display, hardware validation/apply/reboot, network time, editing, themes and localized windows", output)
        await session.stop()
        try require(!session.running, "Power off failed")
        window.makeKeyAndOrderFront(nil)
        let disabledPoint = try await keyPosition(bit, output: output)
        try await nativeEvents([pointer("rightDown", disabledPoint), pointer("rightUp", disabledPoint)], output: output)
        try await until("disabled key mapping") { session.sheet == .mapping && !window.sheets.isEmpty }
        session.sheet = nil; await pause(0.4)
        log("PASS secondary click maps a disabled key", output)
        try require(!NSApp.windows.contains(where: { $0.identifier?.rawValue.hasPrefix("secondary:") == true && $0.isVisible }), "Secondary window stayed visible after power off")
        await library.scan()
        guard let second = library.entries.first(where: { $0.id == a640 }) else { throw BackendError(message: "Missing A640") }
        library.open(second)
        guard let other = library.windows.values.first(where: { $0 !== controller }) else { throw BackendError(message: "Missing second firmware window") }
        try await until("A640 start and display") { other.session.running && !other.session.busy && other.session.display.frame != nil || !other.session.error.isEmpty }
        try require(other.session.running && other.session.error.isEmpty, other.session.error)
        await pause(10)
        try await checkOpening(other, output, "a640-opening-ko-dark")
        try await snapshot(other.window!, "emulator-a640-ko-dark", output)
        other.window?.performClose(nil)
        try await until("window close stops backend") { !library.windows.values.contains(where: { $0 === other }) }
        try require(other.session.closed && !other.session.running, "Closing emulator did not stop its session")
        await library.mutate("library.remove", path: a640)
        try require(!library.entries.contains(where: { $0.id == a640 }), "Library removal failed")
        try require(FileManager.default.fileExists(atPath: a640), "Library removal changed original firmware")
        log("PASS second firmware window with one guest running at a time; power off, session close, library removal preserves firmware", output)
        await session.close()
        // A missing QEMU executable must show an error in the window rather than terminate the app.
        let invalid = Firmware(value: .object(["path": .string(samples.appendingPathComponent("missing.bin").path), "name": .string("Missing firmware"), "available": .bool(true)]))
        library.open(invalid)
        try await until("failure scene") { library.windows.values.contains { $0.session.firmware.id == invalid.id && $0.window != nil } }
        let failure = library.windows.values.first { $0.session.firmware.id == invalid.id }!
        try await until("firmware error banner") { !failure.session.error.isEmpty && !failure.session.busy }
        try await snapshot(failure.window!, "emulator-error-ko-dark", output)
        await failure.session.close(); failure.window?.orderOut(nil)
        log("PASS firmware failure displayed without crash", output)
    }
}
#endif
