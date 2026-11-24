import Foundation

private final class LocalizationChoice: @unchecked Sendable {
    static let shared = LocalizationChoice()
    private let lock = NSLock()
    private var value = "auto"
    func set(_ language: String) { lock.lock(); value = language; lock.unlock() }
    func get() -> String { lock.lock(); defer { lock.unlock() }; return value }
}

func setInterfaceLanguage(_ language: String) { LocalizationChoice.shared.set(language) }

let applicationResources: Bundle = {
    if let url = Bundle.main.url(forResource: "MSM5xxx Emulator_MSM5xxxEmulator", withExtension: "bundle"),
       let bundle = Bundle(url: url) { return bundle }
    return Bundle.module
}()

func L(_ key: String) -> String {
    let choice = LocalizationChoice.shared.get()
    let language = choice == "auto" ? (Locale.preferredLanguages.first?.hasPrefix("ko") == true ? "ko" : "en") : choice
    let bundle = applicationResources.path(forResource: language, ofType: "lproj").flatMap(Bundle.init(path:)) ?? applicationResources
    return NSLocalizedString(key, bundle: bundle, comment: "")
}
