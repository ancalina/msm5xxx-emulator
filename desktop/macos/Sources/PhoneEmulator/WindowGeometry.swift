import AppKit
import SwiftUI

@MainActor struct KeypadMetrics {
    static let padding: CGFloat = 10
    static let verticalPadding: CGFloat = 14
    static let columnGap: CGFloat = 6
    static let rowGap: CGFloat = 4
    var columns: [CGFloat]
    let rowHeight: CGFloat = 32
    var width: CGFloat { columns.reduce(0, +) + 3 * Self.columnGap + 2 * Self.padding }
    var height: CGFloat { 9 * rowHeight + 8 * Self.rowGap + 2 * Self.verticalPadding }
    init(layout: JSON) {
        var columns = [CGFloat](repeating: 56, count: 4)
        let font = NSFont.systemFont(ofSize: NSFont.systemFontSize)
        for key in layout["keys"].array {
            let column = key["column"].int
            if columns.indices.contains(column) {
                columns[column] = max(columns[column], ceil((key["text"].string as NSString).size(withAttributes: [.font: font]).width) + 16)
            }
        }
        for title in [L("fold_short_open"), L("fold_short_close")] {
            columns[0] = max(columns[0], ceil((title as NSString).size(withAttributes: [.font: font]).width) + 16)
        }
        let keyWidth = columns[1...3].max()!
        columns.replaceSubrange(1...3, with: repeatElement(keyWidth, count: 3))
        self.columns = columns
    }
    func columnWidth(_ column: Int, available: CGFloat) -> CGFloat {
        let keyWidth = floor(columns[1] + max(0, available - width) / 4)
        if column == 0 {
            return max(columns[0], available - 3 * keyWidth - 3 * Self.columnGap - 2 * Self.padding)
        }
        return keyWidth
    }
}

/// Accesses a scene-owned window without replacing SwiftUI's content, delegate or toolbar.
struct WindowAccessor: NSViewRepresentable {
    let resolve: (NSWindow) -> Void
    func makeNSView(context: Context) -> AccessorView { let view = AccessorView(); view.resolve = resolve; return view }
    func updateNSView(_ view: AccessorView, context: Context) { view.resolve = resolve; view.resolveWindow() }
    static func dismantleNSView(_ view: AccessorView, coordinator: ()) { view.resolve = nil }
    final class AccessorView: NSView {
        var resolve: ((NSWindow) -> Void)?
        private weak var resolvedWindow: NSWindow?
        override func hitTest(_ point: NSPoint) -> NSView? { nil }
        override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); resolveWindow() }
        func resolveWindow() {
            DispatchQueue.main.async { [weak self] in
                guard let self, let resolve = self.resolve, let window = self.window, self.resolvedWindow !== window else { return }
                self.resolvedWindow = window
                resolve(window)
            }
        }
    }
}

extension NSWindow {
    /// SwiftUI's scene content view includes the title bar; the layout rect excludes it.
    var phoneContentSize: CGSize { contentLayoutRect.size }
    var phoneMinimumSize: CGSize {
        let chrome = styleMask.contains(.fullSizeContentView) ? CGSize(width: frame.width - phoneContentSize.width, height: frame.height - phoneContentSize.height) : .zero
        return CGSize(width: max(0, contentMinSize.width - chrome.width), height: max(0, contentMinSize.height - chrome.height))
    }
    func setPhoneContentSize(_ size: CGSize) {
        let chrome = CGSize(width: frame.width - phoneContentSize.width, height: frame.height - phoneContentSize.height)
        var target = frame
        target.origin.y += frame.height - size.height - chrome.height
        target.size = CGSize(width: size.width + chrome.width, height: size.height + chrome.height)
        setFrame(target, display: true)
    }
}

/// SwiftUI has no per-window dynamic refit or height-for-width resizing API.
/// This bridge handles that geometry and forwards parent notifications for docking.
@MainActor final class EmulatorGeometryBridge {
    weak var window: NSWindow?
    weak var model: EmulatorSceneModel?
    private var observers: [NSObjectProtocol] = []
    private var resizing = false
    private var previous = CGSize.zero
    private var previousTop: CGFloat = 0
    init(window: NSWindow, model: EmulatorSceneModel) {
        self.window = window; self.model = model
        previous = window.phoneContentSize; previousTop = window.frame.maxY
        for name in [NSWindow.didResizeNotification, NSWindow.didMoveNotification, NSWindow.willMiniaturizeNotification, NSWindow.didMiniaturizeNotification, NSWindow.didDeminiaturizeNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: window, queue: .main) { [weak self] note in
                MainActor.assumeIsolated { self?.received(note.name) }
            })
        }
    }
    func invalidate() { for observer in observers { NotificationCenter.default.removeObserver(observer) }; observers.removeAll() }
    func refit(_ size: CGSize) {
        guard let window else { return }
        resizing = true; window.setPhoneContentSize(size); previous = window.phoneContentSize; previousTop = window.frame.maxY; resizing = false
        model?.secondaryDock?.follow()
    }
    func constrained(_ frameSize: CGSize) -> CGSize {
        guard let window, let model else { return frameSize }
        let current = window.phoneContentSize
        let chrome = CGSize(width: window.frame.width - current.width, height: window.frame.height - current.height)
        let width = max(model.openingContentSize.width, frameSize.width - chrome.width)
        let ratio = model.session.lcdSize.height / model.session.lcdSize.width
        let needed = width * ratio + model.session.keypad.height
        let extra = max(0, current.height - current.width * ratio - model.session.keypad.height)
        let height = abs(width - current.width) > 0.5 ? needed + extra : max(needed, frameSize.height - chrome.height)
        return CGSize(width: width + chrome.width, height: max(model.openingContentSize.height, height) + chrome.height)
    }
    private func received(_ name: Notification.Name) {
        guard let model, let window else { return }
        switch name {
        case NSWindow.didResizeNotification:
            guard !resizing else { return }
            let size = window.phoneContentSize, floor = model.openingContentSize
            let ratio = model.session.lcdSize.height / model.session.lcdSize.width
            let width = max(floor.width, size.width)
            let needed = width * ratio + model.session.keypad.height
            let extra = max(0, previous.height - previous.width * ratio - model.session.keypad.height)
            let height = abs(size.width - previous.width) > 0.5 ? needed + extra : max(needed, size.height)
            let target = CGSize(width: width, height: max(floor.height, height))
            if abs(size.width - target.width) > 0.5 || abs(size.height - target.height) > 0.5 {
                resizing = true
                window.setPhoneContentSize(target)
                if size.width < floor.width || size.height < floor.height {
                    window.setFrameTopLeftPoint(NSPoint(x: window.frame.minX, y: previousTop))
                }
                resizing = false
            }
            previous = window.phoneContentSize; previousTop = window.frame.maxY; model.secondaryDock?.follow()
        case NSWindow.willMiniaturizeNotification: model.secondaryDock?.mainWillMinimize()
        case NSWindow.didMiniaturizeNotification: model.secondaryDock?.mainDidMinimize()
        case NSWindow.didDeminiaturizeNotification: model.secondaryDock?.mainDidRestore()
        default: if !resizing { previousTop = window.frame.maxY }; model.secondaryDock?.follow()
        }
    }
}
