import SwiftUI

func newerRelease(_ tag: String, than current: String) -> String? {
    let version = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
    let pattern = "^[0-9]+(\\.[0-9]+){1,2}$"
    guard version.range(of: pattern, options: .regularExpression) != nil,
          current.range(of: pattern, options: .regularExpression) != nil,
          version.compare(current, options: .numeric) == .orderedDescending else { return nil }
    return version
}

@main
struct MSM5xEmuApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}
