import Foundation

private final class LocalizationChoice: @unchecked Sendable {
    static let shared = LocalizationChoice()
    private let lock = NSLock()
    private var value = "auto"
    func set(_ language: String) { lock.lock(); value = language; lock.unlock() }
    func get() -> String { lock.lock(); defer { lock.unlock() }; return value }
}

func setInterfaceLanguage(_ language: String) { LocalizationChoice.shared.set(language) }

func L(_ key: String) -> String {
    let choice = LocalizationChoice.shared.get()
    let language = choice == "auto" ? (Locale.preferredLanguages.first?.hasPrefix("ko") == true ? "ko" : "en") : choice
    let bundle = Bundle.module.path(forResource: language, ofType: "lproj").flatMap(Bundle.init(path:)) ?? Bundle.module
    return NSLocalizedString(key, bundle: bundle, comment: "")
}
