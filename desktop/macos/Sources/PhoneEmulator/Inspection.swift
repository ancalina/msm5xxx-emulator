#if DEBUG
import AppKit

/// Optional file-driven UI inspection, excluded from release builds.
@MainActor enum InspectionHarness {
    static func startIfRequested(library: LibraryModel) {
        let args = desktopDebugArguments
        guard let i = args.firstIndex(of: "--inspect"), args.count > i + 1 else { return }
        let folder = URL(fileURLWithPath: args[i + 1])
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let requestURL = folder.appendingPathComponent("request.json")
        var last = -1
        let timer = Timer(timeInterval: 0.1, repeats: true) { _ in
            MainActor.assumeIsolated {
                guard let data = try? Data(contentsOf: requestURL), let request = try? JSONDecoder().decode(JSON.self, from: data), request["id"].int != last else { return }
                last = request["id"].int
                func reply(_ value: JSON) {
                    let result = JSON.object(["id": request["id"], "result": value])
                    if let data = try? JSONEncoder().encode(result) { try? data.write(to: folder.appendingPathComponent("response.json"), options: .atomic) }
                }
                switch request["action"].string {
                case "status": reply(status(library))
                case "cancel_import": importPanel?.cancel(nil); reply(status(library))
                case "accept_import":
                    if let panel = importPanel {
                        let url = URL(fileURLWithPath: request["path"].string)
                        panel.directoryURL = panel.canChooseDirectories ? url : url.deletingLastPathComponent()
                        panel.nameFieldStringValue = panel.canChooseDirectories ? "" : url.lastPathComponent
                        let accept = Timer(timeInterval: 0.8, repeats: false) { _ in MainActor.assumeIsolated { panel.ok(nil) } }
                        addModalTimer(accept)
                    }
                    reply(status(library))
                case "accept_capture": library.windows.values.first?.session.capturePanel?.ok(nil); reply(status(library))
                case "send_key":
                    let panel: NSSavePanel? = importPanel ?? library.windows.values.compactMap { $0.session.capturePanel }.first
                    if let window = panel ?? NSApp.keyWindow {
                        let flags: NSEvent.ModifierFlags = request["command"].bool ? (request["shift"].bool ? [.command, .shift] : [.command]) : []
                        let text = request["text"].string.isEmpty ? "\r" : request["text"].string
                        let code = request["code"].isNull ? UInt16(36) : UInt16(request["code"].int)
                        if let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                                                      windowNumber: window.windowNumber, context: nil, characters: text, charactersIgnoringModifiers: text.lowercased(), isARepeat: false, keyCode: code) { window.sendEvent(event) }
                    }
                    reply(status(library))
                default:
                    Task {
                        var response: [String: JSON] = ["id": request["id"]]
                        do { response["result"] = try await perform(request, library: library, folder: folder) }
                        catch { response["error"] = .string(error.localizedDescription) }
                        if let data = try? JSONEncoder().encode(JSON.object(response)) { try? data.write(to: folder.appendingPathComponent("response.json"), options: .atomic) }
                    }
                }
            }
        }
        addModalTimer(timer)
    }
    private static func addModalTimer(_ timer: Timer) {
        RunLoop.main.add(timer, forMode: .common)
        RunLoop.main.add(timer, forMode: .modalPanel)
        RunLoop.main.add(timer, forMode: .eventTracking)
    }

    private static var importPanel: NSOpenPanel? { NSApp.windows.compactMap { $0 as? NSOpenPanel }.first { $0.isVisible } }
    private static func views(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(views) }
    private static func perform(_ request: JSON, library: LibraryModel, folder: URL) async throws -> JSON {
        let controller = library.windows.values.first(where: { $0.window === NSApp.keyWindow || $0.secondaryWindow === NSApp.keyWindow }) ?? library.windows.values.first(where: { $0.session.running }) ?? library.windows.values.first(where: { !$0.session.closed })
        let session = controller?.session
        func requireSession() throws -> SessionModel {
            guard let session else { throw BackendError(message: "No inspection session") }; return session
        }
        switch request["action"].string {
        case "status": break
        case "choose_file": library.choose()
        case "choose_folder": library.choose(folder: true)
        case "accept_import":
            if let panel = importPanel {
                let url = URL(fileURLWithPath: request["path"].string)
                panel.directoryURL = url.deletingLastPathComponent(); panel.nameFieldStringValue = url.lastPathComponent
                try? await Task.sleep(nanoseconds: 700_000_000); panel.ok(nil)
            }
        case "cancel_import": importPanel?.cancel(nil)
        case "import": await library.mutate("library.add_file", path: request["path"].string)
        case "open":
            guard !library.windows.values.contains(where: { $0.session.running }) else { throw BackendError(message: "Stop the existing inspection guest first") }
            if let firmware = library.entries.first(where: { $0.id == request["path"].string }) { library.open(firmware) }
        case "stop": await (try requireSession()).stop()
        case "power": await (try requireSession()).start()
        case "preferences":
            return .object(["icon": .string(AppPreferences.shared.iconStyle.rawValue), "side": AppPreferences.shared.side(for: request["path"].string).map { .string($0.rawValue) } ?? .null])
        case "icon":
            guard let style = AppIconStyle(rawValue: request["value"].string) else { throw BackendError(message: "Invalid icon") }
            try await AppPreferences.shared.setIcon(style)
        case "general_settings", "settings":
            let source = request["action"].string == "general_settings"
                ? NSApp.windows.first(where: { $0.title == L("library_title") }) : controller?.window
            guard let window = source else { throw BackendError(message: "Missing settings context") }
            window.makeKeyAndOrderFront(nil)
            try? await Task.sleep(nanoseconds: 300_000_000)
            let key = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command,
                                      timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber,
                                      context: nil, characters: ",", charactersIgnoringModifiers: ",", isARepeat: false, keyCode: 43)!
            _ = NSApp.mainMenu?.performKeyEquivalent(with: key)
        case "time": (try requireSession()).sheet = .time
        case "edit": (try requireSession()).editing = request["value"].bool
        case "key":
            if let session, let key = session.layout["keys"].array.first(where: { $0["text"].string == request["text"].string }) { try await VerificationHarness.pressKey(session, bit: key["bit"].int, output: folder) }
        case "dismiss": (try requireSession()).sheet = nil
        case "capture": (try requireSession()).capture(directory: folder)
        case "accept_capture": session?.capturePanel?.ok(nil)
        case "input", "compose":
            guard let window = controller?.window?.sheets.first ?? NSApp.keyWindow, let content = window.contentView,
                  let field = views(content).compactMap({ $0 as? NSTextField }).first(where: { $0.isEditable }) else { throw BackendError(message: "No editable native field") }
            window.makeKeyAndOrderFront(nil); window.makeFirstResponder(field)
            guard let editor = window.fieldEditor(true, for: field) as? NSTextView else { throw BackendError(message: "No native field editor") }
            editor.selectAll(nil)
            if request["action"].string == "compose" {
                editor.setMarkedText("하", selectedRange: NSRange(location: 1, length: 0), replacementRange: NSRange(location: NSNotFound, length: 0))
                editor.setMarkedText(request["text"].string, selectedRange: NSRange(location: request["text"].string.utf16.count, length: 0), replacementRange: NSRange(location: NSNotFound, length: 0))
                editor.unmarkText()
            } else { editor.insertText(request["text"].string, replacementRange: NSRange(location: NSNotFound, length: 0)) }
        case "return":
            if let window = controller?.window?.sheets.first ?? NSApp.keyWindow, let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber, context: nil, characters: "\r", charactersIgnoringModifiers: "\r", isARepeat: false, keyCode: 36) { _ = window.performKeyEquivalent(with: event) }
        case "setting": try await library.set(request["key"].string, value: request["value"])
        case "language": try await library.set("ui_language", value: request["value"])
        case "theme": NSApp.appearance = NSAppearance(named: request["value"].string == "dark" ? .darkAqua : .aqua)
        case "snapshot":
            guard let window = request["window"].string == "library" ? NSApp.windows.first(where: { $0.title == L("library_title") }) : (controller?.window?.sheets.first ?? controller?.window ?? NSApp.keyWindow) else { throw BackendError(message: "No inspection window") }
            try await VerificationHarness.snapshot(window, request["name"].string, folder)
        case "quit": DispatchQueue.main.async { NSApp.terminate(nil) }
        default: throw BackendError(message: "Unknown inspection action")
        }
        return status(library)
    }
    private static func status(_ library: LibraryModel) -> JSON {
        let session = (library.windows.values.first(where: { $0.window === NSApp.keyWindow || $0.secondaryWindow === NSApp.keyWindow }) ?? library.windows.values.first(where: { $0.session.running }) ?? library.windows.values.first(where: { !$0.session.closed }))?.session
        let windows: [JSON] = NSApp.windows.map { window -> JSON in
            let size = window.phoneContentSize
            let row: [String: JSON] = [
                "number": .integer(window.windowNumber), "title": .string(window.title), "subtitle": .string(window.subtitle),
                "class": .string(NSStringFromClass(type(of: window))), "visible": .bool(window.isVisible),
                "width": .number(Double(size.width)), "height": .number(Double(size.height)),
                "x": .number(Double(window.frame.minX)), "y": .number(Double(window.frame.minY)),
                "frame_width": .number(Double(window.frame.width)), "frame_height": .number(Double(window.frame.height)),
                "minimum_width": .number(Double(window.phoneMinimumSize.width)), "minimum_height": .number(Double(window.phoneMinimumSize.height)),
                "parent": .integer(window.parent?.windowNumber ?? 0), "miniaturized": .bool(window.isMiniaturized)
            ]
            return .object(row)
        }
        let responder = NSApp.keyWindow?.firstResponder
        let responderName = responder.map { NSStringFromClass(type(of: $0)) } ?? ""
        let result: [String: JSON] = [
            "running": .bool(session?.running ?? false), "busy": .bool(session?.busy ?? false), "error": .string(session?.error ?? library.error),
            "import_panel": .bool(importPanel != nil), "capture_panel": .bool(session?.capturePanel != nil), "scanning": .bool(library.scanning),
            "entries": .array(library.entries.map { JSON.string($0.id) }), "folders": .array(library.folders.map(JSON.string)), "windows": .array(windows),
            "active": .bool(NSApp.isActive), "first_responder": .string(responderName),
            "capture_directory": .string(session?.capturePanel?.directoryURL?.path ?? ""), "capture_name": .string(session?.capturePanel?.nameFieldStringValue ?? ""),
            "capture_url": .string(session?.capturePanel?.url?.path ?? ""), "capture_visible": .bool(session?.capturePanel?.isVisible ?? false),
            "mapped": .array((session?.mapped.sorted() ?? []).map(JSON.integer)), "settings": .object(library.settings)
        ]
        return .object(result)
    }
}
#endif
