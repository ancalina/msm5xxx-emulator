#if DEBUG
import AppKit
import Foundation

/// Exercises Sparkle's real menu, windows and buttons; snapshots only this app's views.
@MainActor enum UpdateVerification {
    static func startIfRequested() {
        guard let path = Bundle.main.object(forInfoDictionaryKey: "MSM5xxxUpdateTestDirectory") as? String else { return }
        let directory = URL(fileURLWithPath: path)
        Task {
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                log("START: windows=" + NSApp.windows.map { $0.title }.joined(separator: "; "), directory)
                let library = try await until("library window") {
                    NSApp.windows.first { $0.title == L("library_title") && $0.isVisible }
                }
                guard applicationResources.bundleURL.path.hasPrefix(Bundle.main.bundleURL.path) else {
                    throw BackendError(message: "Installed app used build-tree resources")
                }
                let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""
                if version == "20000" {
                    guard !DesktopUpdates.shared.controller.updater.automaticallyChecksForUpdates else {
                        throw BackendError(message: "Automatic-check preference did not survive restart")
                    }
                    let marker = directory.appendingPathComponent("data/retention-test")
                    guard try String(contentsOf: marker, encoding: .utf8) == "library settings saved state",
                          FileManager.default.fileExists(atPath: directory.appendingPathComponent("awaiting-relaunch").path)
                    else { throw BackendError(message: "Update did not preserve the test state") }
                    try await capture(library, "updated", directory)
                    try "PASS\n".write(to: directory.appendingPathComponent("result.txt"), atomically: true, encoding: .utf8)
                    log("PASS: Sparkle replaced and relaunched version 20000; state retained", directory)
                    NSApp.terminate(nil)
                    return
                }
                guard version == "19999" else { throw BackendError(message: "Unexpected baseline version") }
                try await capture(library, "first-run", directory)
                let updater = DesktopUpdates.shared.controller.updater
                _ = try await until("updater ready") { updater.canCheckForUpdates ? true : nil }
                let original = updater.automaticallyChecksForUpdates
                updater.automaticallyChecksForUpdates = !original
                _ = try await until("automatic-check preference binding") {
                    DesktopUpdates.shared.automatic == !original ? true : nil
                }
                updater.automaticallyChecksForUpdates = original
                updater.automaticallyChecksForUpdates = false
                log("PASS: automatic-check preference round trip", directory)
                let menu = try await until("standard Check for Updates menu") {
                    NSApp.mainMenu.flatMap { findMenu(L("check_updates"), in: $0) }
                }
                menu.0.update()
                guard menu.0.item(at: menu.1)?.action != nil else { throw BackendError(message: "Update menu has no action") }
                // Exercise the standard menu’s controller action.
                DesktopUpdates.shared.controller.checkForUpdates(nil)
                log("PASS: standard update command wired; controller action invoked", directory)
                let install = try await until("Sparkle update offer") { button("installUpdate:") }
                guard let offer = install.window else { throw BackendError(message: "Update offer has no window") }
                try await capture(offer, "update-ready", directory)
                log("PASS: standard update menu and Sparkle offer", directory)
                install.performClick(nil)
                let restart = try await until("Sparkle install and restart") { button("installAndRestart:") }
                guard let ready = restart.window else { throw BackendError(message: "Restart button has no window") }
                try await capture(ready, "apply-on-restart", directory)
                try "ready\n".write(to: directory.appendingPathComponent("awaiting-relaunch"), atomically: true, encoding: .utf8)
                log("PASS: signed update downloaded; applying through Sparkle", directory)
                restart.performClick(nil)
            } catch {
                try? "FAIL: \(error.localizedDescription)\n".write(to: directory.appendingPathComponent("result.txt"), atomically: true, encoding: .utf8)
                log("FAIL: \(error)", directory)
                NSApp.terminate(nil)
            }
        }
    }

    private static func until<T>(_ description: String, _ operation: () -> T?) async throws -> T {
        let deadline = Date().addingTimeInterval(600)
        while Date() < deadline {
            if let result = operation() { return result }
            try await Task.sleep(for: .milliseconds(500))
        }
        throw BackendError(message: "Timed out waiting for " + description)
    }

    private static func findMenu(_ title: String, in menu: NSMenu) -> (NSMenu, Int)? {
        for (index, item) in menu.items.enumerated() {
            if item.title == title { return (menu, index) }
            if let submenu = item.submenu, let found = findMenu(title, in: submenu) { return found }
        }
        return nil
    }

    private static func button(_ action: String) -> NSButton? {
        func search(_ view: NSView) -> NSButton? {
            if let button = view as? NSButton, button.isEnabled, !button.isHidden,
               button.action.map(NSStringFromSelector) == action { return button }
            for child in view.subviews { if let found = search(child) { return found } }
            return nil
        }
        for window in NSApp.windows where window.isVisible {
            if let content = window.contentView, let found = search(content) { return found }
        }
        return nil
    }

    private static func capture(_ window: NSWindow, _ name: String, _ output: URL) async throws {
        window.displayIfNeeded()
        try await Task.sleep(for: .milliseconds(600))
        guard let view = window.contentView?.superview,
              let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw BackendError(message: "No snapshot view") }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else { throw BackendError(message: "No snapshot PNG") }
        try png.write(to: output.appendingPathComponent(name + ".png"))
    }

    private static func log(_ message: String, _ directory: URL) {
        let path = directory.appendingPathComponent("checks.txt")
        if !FileManager.default.fileExists(atPath: path.path) { FileManager.default.createFile(atPath: path.path, contents: nil) }
        if let file = try? FileHandle(forWritingTo: path) {
            _ = try? file.seekToEnd(); try? file.write(contentsOf: Data((message + "\n").utf8)); try? file.close()
        }
    }
}
#endif
