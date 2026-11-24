import SwiftUI
import Sparkle

/// Sparkle owns preferences, scheduling, signature checks and the standard update UI.
@MainActor final class DesktopUpdates: ObservableObject {
    static let shared = DesktopUpdates()
    let controller: SPUStandardUpdaterController
    @Published var canCheck = false
    @Published var automatic = false
    private init() {
        controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: nil, userDriverDelegate: nil)
        let updater = controller.updater
        updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheck)
        updater.publisher(for: \.automaticallyChecksForUpdates).assign(to: &$automatic)
        controller.startUpdater()
    }
}

struct UpdateCheckButton: View {
    @ObservedObject private var updates = DesktopUpdates.shared
    var body: some View {
        Button(L("check_updates")) { updates.controller.checkForUpdates(nil) }
            .disabled(!updates.canCheck)
    }
}

struct UpdatePreferences: View {
    @ObservedObject private var updates = DesktopUpdates.shared
    var body: some View {
        Section(L("updates")) {
            Toggle(L("automatic_updates"), isOn: Binding(get: { updates.automatic }, set: {
                updates.controller.updater.automaticallyChecksForUpdates = $0
            }))
            UpdateCheckButton()
        }
    }
}
