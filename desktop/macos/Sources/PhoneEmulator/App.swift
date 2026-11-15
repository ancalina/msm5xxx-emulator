import SwiftUI
import AppKit
import Darwin

@main struct EmulatorApp: App {
    @NSApplicationDelegateAdaptor(ApplicationDelegate.self) private var delegate
    @StateObject private var library = LibraryModel.shared
    var body: some Scene {
        Window("MSM5xxx", id: "library") {
            LibraryScene(library: library).focusedSceneValue(\.desktopScene, .library)
        }
        .defaultLaunchBehavior(.presented)
        .restorationBehavior(.disabled)
        .defaultSize(width: 640, height: 520)
        .windowToolbarStyle(.unified)
        .windowResizability(.contentMinSize)
        .commands { EmulatorCommands(library: library) }

        WindowGroup(id: "emulator", for: URL.self) { $url in
            if let url { EmulatorScene(url: url, library: library) }
        }
        .defaultSize(width: 384, height: 784)
        .windowToolbarStyle(.unified)
        .windowResizability(.contentMinSize)
        .windowIdealSize(.fitToContent)
        .restorationBehavior(.disabled)
        .defaultLaunchBehavior(.suppressed)

        WindowGroup(id: "secondary", for: URL.self) { $url in
            if let url { SecondaryScene(url: url, library: library) }
        }
        .windowToolbarStyle(.unified)
        .windowResizability(.contentMinSize)
        .windowIdealSize(.fitToContent)
        .defaultWindowPlacement { content, _ in WindowPlacement(size: content.sizeThatFits(.unspecified)) }
        .restorationBehavior(.disabled)
        .defaultLaunchBehavior(.suppressed)

        Settings { ApplicationSettings(library: library) }
    }
}

/// AppKit supplies the asynchronous application-quit handshake; scenes own all windows.
@MainActor final class ApplicationDelegate: NSObject, NSApplicationDelegate {
    private var terminating = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        signal(SIGPIPE, SIG_IGN)
        AppPreferences.shared.applyIcon()
        #if DEBUG
        VerificationHarness.armStartupCheckIfRequested()
        InspectionHarness.startIfRequested(library: .shared)
        #endif
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let library = LibraryModel.shared
        if library.shutdownComplete { return .terminateNow }
        guard !terminating else { return .terminateLater }
        terminating = true
        let sessions = library.prepareForApplicationQuit(), backend = library.backend
        Task.detached {
            for session in sessions { _ = try? await session.call("session.stop"); await session.close() }
            await backend.close()
            RunLoop.main.perform(inModes: [.default, .modalPanel, .common]) {
                MainActor.assumeIsolated {
                    library.shutdownComplete = true
                    sender.reply(toApplicationShouldTerminate: true)
                }
            }
        }
        return .terminateLater
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

enum DesktopSceneFocus {
    case library, emulator(EmulatorSceneModel), settings
}
private struct DesktopSceneFocusKey: FocusedValueKey { typealias Value = DesktopSceneFocus }
extension FocusedValues {
    var desktopScene: DesktopSceneFocus? {
        get { self[DesktopSceneFocusKey.self] }
        set { self[DesktopSceneFocusKey.self] = newValue }
    }
}

struct EmulatorCommands: Commands {
    @ObservedObject var library: LibraryModel
    @FocusedValue(\.desktopScene) private var scene
    private var emulator: EmulatorSceneModel? {
        if case .emulator(let model) = scene { return model }
        return nil
    }
    private var libraryScene: Bool {
        if case .library = scene { return true }
        return false
    }
    @Environment(\.openSettings) private var openSettings
    @Environment(\.openWindow) private var openWindow
    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button(L("library_import") + "…") { openWindow(id: "library"); library.choose() }.keyboardShortcut("o")
            Button(L("library_add_folder") + "…") { openWindow(id: "library"); library.choose(folder: true) }.keyboardShortcut("o", modifiers: [.command, .shift])
        }
        CommandGroup(replacing: .appSettings) {
            Button(L("settings") + "…") { showSettings() }.keyboardShortcut(",")
        }
        CommandMenu(L("emulator")) {
            if let emulator { EmulatorCommandItems(model: emulator, session: emulator.session, library: library) }
            else {
                UnavailableEmulatorCommands(library: library)
                Button(L("settings") + "…") { showSettings() }
            }
        }
        CommandMenu(L("view_library")) {
            Button(L("library_title")) { openWindow(id: "library") }.keyboardShortcut("0")
            Button(L("library_refresh")) { Task { await library.scan() } }.keyboardShortcut(libraryScene ? KeyboardShortcut("r") : nil).disabled(library.scanning || !libraryScene)
        }
    }
    private func showSettings() {
        switch scene {
        case .library: library.settingsEmulator = nil
        case .emulator(let model): library.settingsEmulator = model
        default: break
        }
        openSettings()
    }
}

struct UnavailableEmulatorCommands: View {
    @ObservedObject var library: LibraryModel
    var body: some View {
        Group {
            Button(L("power_on_action")) {}.keyboardShortcut("p", modifiers: [.command, .shift])
            Button(L("reboot_emulator")) {}.keyboardShortcut("r")
            Button(L("capture")) {}.keyboardShortcut("s", modifiers: [.command, .shift])
            Button(L("additional_display")) {}
            Button(L("library_info")) {}.keyboardShortcut("i")
            Divider()
            Toggle(L("virtual_network_menu"), isOn: .constant(library.settings["virtual_network"]?.bool ?? false))
            Menu(L("time")) { Button(L("host_time")) {}; Button(L("set_time")) {} }
            Toggle(L("edit_input"), isOn: .constant(false))
        }.disabled(true)
    }
}

struct EmulatorCommandItems: View {
    let model: EmulatorSceneModel
    @ObservedObject var session: SessionModel
    @ObservedObject var library: LibraryModel
    @Environment(\.openSettings) private var openSettings
    var body: some View {
        Group {
            Button(L(session.running ? "power_off_action" : "power_on_action")) { model.togglePower() }
                .keyboardShortcut("p", modifiers: [.command, .shift]).disabled(session.busy)
            Button(L("reboot_emulator")) { Task { await session.reboot() } }.keyboardShortcut("r").disabled(!session.running || session.busy)
            Button(L("capture")) { session.capture() }.keyboardShortcut("s", modifiers: [.command, .shift]).disabled(!session.running)
            Button(L("additional_display")) { model.showSecondary() }.disabled(session.secondary.frame == nil)
            Button(L("library_info")) { session.sheet = .info }.keyboardShortcut("i")
            Divider()
            Toggle(L("virtual_network_menu"), isOn: Binding(get: { library.settings["virtual_network"]?.bool ?? false }, set: { _ in model.toggleVirtualNetwork() })).disabled(session.busy)
            Menu(L("time")) {
                Button(L("host_time")) { model.useHostClock() }
                Button(L("set_time")) { session.sheet = .time }
            }
            Toggle(L("edit_input"), isOn: $session.editing).disabled(!session.running)
            Button(L("settings") + "…") { library.settingsEmulator = model; openSettings() }
        }.disabled(session.sheet != nil)
    }
}
