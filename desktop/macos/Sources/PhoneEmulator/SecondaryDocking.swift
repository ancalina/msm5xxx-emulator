import AppKit

/// Native child-window attachment, with a magnetic edge during secondary-window drags.
@MainActor final class SecondaryDocking: NSObject {
    static let snapDistance: CGFloat = 16
    weak var main: NSWindow?
    let display: NSWindow
    let firmware: String
    private(set) var side: DockSide?
    var onError: ((String) -> Void)?
    private var positioning = false
    private var dragging = false
    private var suppressSnap = false
    private var pendingSide: DockSide?
    private var dragEndTimer: Timer?
    private var dragGeneration = 0
    private var visibleBeforeMinimize = false
    private var observers: [NSObjectProtocol] = []
    var attached: Bool { display.parent === main && side != nil }

    init(main: NSWindow, display: NSWindow, firmware: String) {
        self.main = main; self.display = display; self.firmware = firmware
        side = AppPreferences.shared.side(for: firmware)
        super.init()
        for name in [NSWindow.willMoveNotification, NSWindow.didMoveNotification, NSWindow.didResizeNotification, NSWindow.willCloseNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: display, queue: .main) { [weak self] note in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    switch note.name {
                    case NSWindow.willMoveNotification: self.windowWillMove(note)
                    case NSWindow.didMoveNotification: self.windowDidMove(note)
                    case NSWindow.willCloseNotification: self.cancelDrag(); self.display.parent?.removeChildWindow(self.display)
                    default: self.windowDidResize(note)
                    }
                }
            })
        }
    }
    private func contentTop(_ window: NSWindow) -> CGFloat {
        window.convertToScreen(window.contentLayoutRect).maxY
    }
    func removeObservers() {
        cancelDrag()
        for observer in observers { NotificationCenter.default.removeObserver(observer) }
        observers.removeAll()
    }
    func expectedFrame(_ side: DockSide) -> NSRect {
        guard let main else { return display.frame }
        var frame = display.frame
        frame.origin.x = side == .right ? main.frame.maxX : main.frame.minX - frame.width
        frame.origin.y += contentTop(main) - contentTop(display)
        return frame
    }
    func present() {
        if let side { attach(side, persist: false) }
        display.orderFront(nil)
    }
    func follow() {
        guard attached, let side else { return }
        let frame = expectedFrame(side)
        guard abs(frame.minX - display.frame.minX) > 0.1 || abs(frame.minY - display.frame.minY) > 0.1 else { return }
        positioning = true
        display.setFrame(frame, display: true)
        positioning = false
    }
    func attach(_ side: DockSide, persist: Bool = true) {
        guard let main else { return }
        self.side = side
        if display.parent !== main { display.parent?.removeChildWindow(display); main.addChildWindow(display, ordered: .above) }
        follow()
        if persist { saveSide() }
    }
    func detach() {
        display.parent?.removeChildWindow(display)
        side = nil; saveSide()
    }
    private func saveSide() {
        let side = self.side, firmware = self.firmware
        Task { do { try await AppPreferences.shared.setSide(side, for: firmware) } catch { onError?(error.localizedDescription) } }
    }
    func windowWillMove(_ notification: Notification) {
        guard !positioning else { return }
        dragGeneration += 1
        dragging = true; suppressSnap = false; pendingSide = nil
        dragEndTimer?.invalidate()
        let timer = Timer(timeInterval: 0.03, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                if NSEvent.pressedMouseButtons & 1 == 0 { self?.endDrag() }
            }
        }
        dragEndTimer = timer
        RunLoop.main.add(timer, forMode: .common)
        RunLoop.main.add(timer, forMode: .eventTracking)
    }
    func windowDidMove(_ notification: Notification) {
        guard dragging, !positioning, main != nil else { return }
        if let side {
            let expected = expectedFrame(side)
            if abs(display.frame.minX - expected.minX) > Self.snapDistance || abs(display.frame.minY - expected.minY) > Self.snapDistance {
                detach(); suppressSnap = true
            }
        } else if !suppressSnap { pendingSide = nearbySide() }
    }
    private func nearbySide() -> DockSide? {
        guard let main, display.frame.maxY >= main.frame.minY, display.frame.minY <= main.frame.maxY else { return nil }
        if abs(display.frame.minX - main.frame.maxX) <= Self.snapDistance { return .right }
        if abs(display.frame.maxX - main.frame.minX) <= Self.snapDistance { return .left }
        return nil
    }
    func endDrag() {
        guard dragging else { return }
        let allowSnap = !suppressSnap, generation = dragGeneration
        dragging = false; suppressSnap = false
        dragEndTimer?.invalidate(); dragEndTimer = nil
        // The last move notification can arrive after mouse up. Read the settled frame.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.08) { [weak self] in
            guard let self, generation == self.dragGeneration, !self.dragging, self.display.isVisible else { return }
            if self.attached { self.follow() }
            else if allowSnap {
                self.pendingSide = self.nearbySide()
                if let side = self.pendingSide { self.attach(side) }
            }
            self.pendingSide = nil
        }
    }
    func windowDidResize(_ notification: Notification) { follow() }
    private func cancelDrag() {
        dragGeneration += 1
        dragging = false; suppressSnap = false; pendingSide = nil
        dragEndTimer?.invalidate(); dragEndTimer = nil
    }
    func hide() { cancelDrag(); visibleBeforeMinimize = false; display.orderOut(nil) }
    func mainWillMinimize() { visibleBeforeMinimize = display.isVisible }
    func mainDidMinimize() { if attached { display.orderOut(nil) } }
    func mainDidRestore() {
        guard visibleBeforeMinimize, let side else { return }
        visibleBeforeMinimize = false
        // AppKit removes the native parent relationship when ordering a child out.
        attach(side, persist: false)
        display.orderFront(nil); follow()
    }
    #if DEBUG
    func dragForVerification(to frame: NSRect) {
        dragging = true; suppressSnap = false
        display.setFrame(frame, display: true)
        windowDidMove(Notification(name: NSWindow.didMoveNotification, object: display))
        endDrag()
    }
    #endif
}
