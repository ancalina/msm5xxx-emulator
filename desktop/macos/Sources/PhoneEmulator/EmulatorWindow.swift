import SwiftUI
import AppKit

/// One backend/session per firmware value. SwiftUI scenes own the actual windows.
@MainActor final class EmulatorSceneModel: ObservableObject {
    let session: SessionModel
    unowned let library: LibraryModel
    weak var window: NSWindow?
    weak var secondaryWindow: NSWindow?
    private(set) var secondaryDock: SecondaryDocking?
    private var mainGeometry: EmulatorGeometryBridge?
    private var secondaryGeometry = CGSize.zero
    private var secondaryPresentation: UUID?
    private var lastClosedSecondaryPresentation: UUID?
    private var closing = false
    var openingContentSize: CGSize { session.openingMinimum }
    var naturalContentWidth: CGFloat { session.keypad.width }
    var url: URL { URL(fileURLWithPath: session.firmware.id).resolvingSymlinksInPath() }

    init(firmware: Firmware, library: LibraryModel) {
        self.library = library; session = SessionModel(firmware: firmware)
        session.onGeometry = { [weak self] in self?.fitLCD() }
        session.onSecondary = { [weak self] in self?.showSecondary() }
        session.onStopped = { [weak self] in self?.hideSecondary() }
        fitLCD()
    }
    func attachMain(_ window: NSWindow) {
        guard self.window !== window else { return }
        self.window = window
        mainGeometry = EmulatorGeometryBridge(window: window, model: self)
        window.identifier = NSUserInterfaceItemIdentifier("emulator:" + session.firmware.id)
        fitLCD(force: true)
    }
    func attachSecondary(_ window: NSWindow, presentation: UUID) {
        guard let main = self.window, lastClosedSecondaryPresentation != presentation, !closing else { return }
        let isNew = secondaryWindow !== window || secondaryPresentation != presentation
        secondaryPresentation = presentation
        if isNew {
            // AppKit's content aspect ratio must describe the LCD below the title bar.
            window.styleMask.remove(.fullSizeContentView)
            secondaryDock?.removeObservers()
            secondaryWindow = window
            window.identifier = NSUserInterfaceItemIdentifier("secondary:" + session.firmware.id)
            secondaryDock = SecondaryDocking(main: main, display: window, firmware: session.firmware.id)
            secondaryDock?.onError = { [weak self] in self?.session.error = $0 }
            window.setFrameTopLeftPoint(NSPoint(x: main.frame.maxX + 16, y: main.frame.maxY))
        }
        if let frame = session.secondary.frame {
            let size = CGSize(width: frame.width, height: frame.height)
            if secondaryGeometry != size {
                secondaryGeometry = size
                window.contentAspectRatio = size
                window.setPhoneContentSize(CGSize(width: size.width * 3, height: size.height * 3))
            }
        }
        if isNew {
            secondaryDock?.present()
            let initialFrame = window.frame
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [weak self, weak window] in
                guard let self, let window, self.secondaryWindow === window, self.secondaryPresentation == presentation, self.lastClosedSecondaryPresentation != presentation, let frame = self.session.secondary.frame else { return }
                if !window.inLiveResize && NSEvent.pressedMouseButtons == 0 && abs(window.frame.width - initialFrame.width) < 1 {
                    window.setPhoneContentSize(CGSize(width: frame.width * 3, height: frame.height * 3))
                    self.secondaryDock?.follow()
                }
            }
        }
    }
    func fitLCD(force: Bool = false) {
        let size = session.lcdSize, scale = max(1, ceil(naturalContentWidth / size.width))
        let opening = CGSize(width: size.width * scale, height: size.height * scale + session.keypad.height)
        let changed = session.openingMinimum != opening
        if changed { session.openingMinimum = opening }
        if changed || force { mainGeometry?.refit(opening) }
    }
    func showSecondary() {
        guard session.running, session.secondary.frame != nil else { return }
        secondaryDock?.present()
        library.presentSecondary?(url)
    }
    func hideSecondary() {
        secondaryDock?.hide()
        library.dismissSecondary?(url)
        secondaryGeometry = .zero
    }
    func secondaryClosed(presentation: UUID) {
        lastClosedSecondaryPresentation = presentation
        guard secondaryPresentation == presentation else { return }
        secondaryDock?.removeObservers()
        secondaryDock = nil; secondaryWindow = nil; secondaryGeometry = .zero; secondaryPresentation = nil
    }
    func mainClosed() {
        guard !closing else { return }; closing = true
        session.releaseAll(); hideSecondary()
        mainGeometry?.invalidate(); mainGeometry = nil
        library.didClose(self)
    }
    func togglePower() { Task { if session.running { await session.stop() } else { await session.start() } } }
    func toggleVirtualNetwork() {
        Task {
            do {
                try await library.set("virtual_network", value: .bool(!(library.settings["virtual_network"]?.bool ?? false)))
                if session.running { await session.reboot() }
            } catch { session.error = error.localizedDescription }
        }
    }
    func useHostClock() {
        Task {
            do { try await library.set("network_host_time", value: .bool(true)) }
            catch { session.error = error.localizedDescription }
        }
    }
    func constrainedFrameSize(_ frameSize: NSSize) -> NSSize {
        mainGeometry?.constrained(frameSize) ?? frameSize
    }
}

struct EmulatorScene: View {
    @StateObject private var model: EmulatorSceneModel
    @ObservedObject var library: LibraryModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow
    init(url: URL, library: LibraryModel) {
        self.library = library
        _model = StateObject(wrappedValue: library.model(for: url))
    }
    var body: some View {
        EmulatorView(session: model.session, library: library, model: model)
            .focusedSceneValue(\.desktopScene, .emulator(model))
            .background(WindowAccessor { model.attachMain($0) }.frame(width: 0, height: 0).allowsHitTesting(false))
            .task {
                library.presentSecondary = { openWindow(id: "secondary", value: $0) }
                library.dismissSecondary = { dismissWindow(id: "secondary", value: $0) }
                await model.session.start()
            }
            .onDisappear { model.mainClosed() }
    }
}

struct SecondaryScene: View {
    @ObservedObject private var model: EmulatorSceneModel
    @ObservedObject private var session: SessionModel
    @ObservedObject var library: LibraryModel
    @State private var presentation = UUID()
    init(url: URL, library: LibraryModel) {
        let model = library.model(for: url)
        self.model = model; self.session = model.session; self.library = library
    }
    var body: some View {
        let size = session.secondary.frame.map { CGSize(width: $0.width, height: $0.height) } ?? CGSize(width: 96, height: 64)
        LCDView(display: session.secondary, secondary: true)
            .frame(minWidth: size.width, idealWidth: size.width * 3, minHeight: size.height, idealHeight: size.height * 3)
            .navigationTitle(L("additional_display"))
            .navigationSubtitle(session.secondaryStatus)
            .focusedSceneValue(\.desktopScene, .emulator(model))
            .background(WindowAccessor { model.attachSecondary($0, presentation: presentation) }.frame(width: 0, height: 0).allowsHitTesting(false))
            .onChange(of: size) { _, _ in if let window = model.secondaryWindow { model.attachSecondary(window, presentation: presentation) } }
            .onDisappear { model.secondaryClosed(presentation: presentation) }
    }
}

struct EmulatorView: View {
    @ObservedObject var session: SessionModel
    @ObservedObject var library: LibraryModel
    let model: EmulatorSceneModel
    @Environment(\.controlActiveState) private var activeState
    @FocusState private var phoneFocused: Bool
    @State private var mappingBit = 0
    @State private var mappingTitle = ""
    var body: some View {
        VStack(spacing: 0) {
            ZStack(alignment: .top) {
                ZStack { LCDView(display: session.display, secondary: false).allowsHitTesting(false) }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .contentShape(Rectangle())
                    .onTapGesture { phoneFocused = true }
                    .focusable().focused($phoneFocused)
                    .onKeyPress(phases: [.down, .repeat, .up]) { session.handleKeyPress($0) }
                    .accessibilityLabel(L("phone_screen"))
                VStack(spacing: 0) {
                    ErrorBanner(message: session.error)
                    if session.busy { ProgressView(L("detecting")).padding(10).background(.regularMaterial) }
                    if session.editing { Text(L("key_editing")).font(.callout).padding(8).background(.regularMaterial) }
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
            KeypadView(session: session) { key in
                mappingBit = key["bit"].int; mappingTitle = key["text"].string
                session.releaseAll(); session.sheet = .mapping
            }.frame(height: session.keypad.height)
        }
        .frame(minWidth: session.openingMinimum.width, idealWidth: session.openingMinimum.width,
               minHeight: session.openingMinimum.height, idealHeight: session.openingMinimum.height)
        .navigationTitle(session.title)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { model.togglePower() } label: { Label(L(session.running ? "power_off_action" : "power_on_action"), systemImage: "power").labelStyle(.iconOnly) }
                    .accessibilityLabel(L(session.running ? "power_off_action" : "power_on_action")).accessibilityIdentifier("emulator-power")
                    .disabled(session.busy).help(L(session.running ? "power_off_action" : "power_on_action"))
            }
            ToolbarItem(placement: .primaryAction) {
                Menu { EmulatorCommandItems(model: model, session: session, library: library) }
                label: { Label(L("emulator_menu"), systemImage: "ellipsis.circle").labelStyle(.iconOnly) }
                .accessibilityLabel(L("emulator_menu")).accessibilityIdentifier("emulator-actions")
                .help(L("emulator_menu")).menuIndicator(.hidden)
            }
        }
        .sheet(item: $session.sheet, onDismiss: { phoneFocused = true }) { sheet in
            switch sheet {
            case .info: SessionInfo(session: session)
            case .time: NetworkTimeView(session: session, library: library)
            case .mapping: MappingView(session: session, bit: mappingBit, title: mappingTitle)
            }
        }
        .fileExporter(isPresented: $session.exporting, document: session.captureDocument, contentType: .png, defaultFilename: session.captureName) { result in
            if case .failure(let error) = result, (error as? CocoaError)?.code != .userCancelled { session.error = error.localizedDescription }
        }
        .fileDialogDefaultDirectory(session.captureDirectory)
        .onAppear { phoneFocused = true }
        .onChange(of: session.exporting) { _, value in if !value { phoneFocused = true } }
        .onChange(of: session.sheet) { _, value in if value != nil { session.releaseKeyboard(); session.releaseAll() } }
        .onChange(of: activeState) { _, value in if value != .key { session.releaseKeyboard(); session.releaseAll() } }
        .onChange(of: session.editing) { _, _ in session.releaseKeyboard(); session.releaseAll() }
    }
}

struct LCDView: NSViewRepresentable {
    @ObservedObject var display: DisplayModel
    let secondary: Bool
    func makeNSView(context: Context) -> LCDCanvas {
        let view = LCDCanvas()
        view.setAccessibilityElement(true); view.setAccessibilityRole(.image)
        return view
    }
    func updateNSView(_ view: LCDCanvas, context: Context) {
        view.frameImage = display.frame; view.needsDisplay = true
        view.setAccessibilityValue(display.frame.map { "\($0.width)×\($0.height)" } ?? L("waiting_display"))
        view.setAccessibilityLabel(L(secondary ? "secondary_title" : "phone_screen"))
        view.setAccessibilityHelp(L(secondary ? "secondary_title" : "phone_screen_help"))
    }
}

final class LCDCanvas: NSView {
    var frameImage: LCDFrame?
    override var isFlipped: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        NSColor.black.setFill(); bounds.fill()
        guard let frame = frameImage, let context = NSGraphicsContext.current?.cgContext else { return }
        let scale = min(bounds.width / CGFloat(frame.width), bounds.height / CGFloat(frame.height))
        let size = CGSize(width: CGFloat(frame.width) * scale, height: CGFloat(frame.height) * scale)
        let rect = CGRect(x: (bounds.width - size.width) / 2, y: (bounds.height - size.height) / 2, width: size.width, height: size.height)
        context.saveGState(); context.interpolationQuality = .none
        context.translateBy(x: 0, y: bounds.height); context.scaleBy(x: 1, y: -1)
        context.draw(frame.image, in: rect); context.restoreGState()
    }
}

struct KeypadView: View {
    @ObservedObject var session: SessionModel
    let edit: (JSON) -> Void
    var body: some View {
        GeometryReader { area in
            Grid(horizontalSpacing: KeypadMetrics.columnGap, verticalSpacing: KeypadMetrics.rowGap) {
                ForEach(0..<9) { row in
                    GridRow {
                        ForEach(0..<4) { column in
                            cell(row, column)
                                .frame(width: session.keypad.columnWidth(column, available: area.size.width), height: session.keypad.rowHeight)
                        }
                    }
                }
            }.padding(.horizontal, KeypadMetrics.padding).padding(.vertical, KeypadMetrics.verticalPadding)
        }.background(.background)
    }
    @ViewBuilder func cell(_ row: Int, _ column: Int) -> some View {
        if let key = session.layout["keys"].array.first(where: { $0["row"].int == row && $0["column"].int == column }) {
            PhoneKey(session: session, key: key, edit: { edit(key) })
        } else if row == 3 && column == 0 {
            let fold = session.state["fold"]
            Button(L(fold.bool ? "fold_short_close" : "fold_short_open")) { Task { await session.action("session.fold") } }
                .buttonStyle(PhoneKeyStyle { _ in })
                .disabled(fold.isNull || !session.running).frame(maxWidth: .infinity)
                .accessibilityLabel(L(fold.bool ? "fold_access_close" : "fold_access_open"))
                .help(fold.isNull ? L("fold_not_supported") : L(fold.bool ? "fold_access_close" : "fold_access_open"))
        } else if column == 0 && row >= 4 && row <= 7 {
            let metrics = session.layout["metrics"].array
            if metrics.indices.contains(row - 4) {
                let metric = metrics[row - 4], value = session.running ? session.state["metrics"][metrics[row - 4]["key"].string].text : "—"
                VStack(alignment: .leading, spacing: 0) {
                    Text(metric["title"].string).font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).minimumScaleFactor(0.75)
                    Text(value.isEmpty ? "—" : value).font(.system(size: NSFont.smallSystemFontSize, design: .monospaced)).monospacedDigit()
                        .lineLimit(1).minimumScaleFactor(8 / NSFont.smallSystemFontSize)
                }.frame(maxWidth: .infinity, alignment: .leading).help(metric["description"].string)
                    .accessibilityElement(children: .combine)
            }
        } else if column == 0 && row == 8 && session.editing {
            Button(L("done")) { session.editing = false }
                .buttonStyle(PhoneKeyStyle { _ in })
                .disabled(session.sheet != nil || session.busy)
                .accessibilityIdentifier("editing-done")
        } else { Color.clear.accessibilityHidden(true) }
    }
}

struct PhoneKey: View {
    @ObservedObject var session: SessionModel
    let key: JSON
    let edit: () -> Void
    var body: some View {
        let bit = key["bit"].int
        let directions = ["▲": "key_up", "▼": "key_down", "◀": "key_left", "▶": "key_right"]
        let name = directions[key["text"].string].map(L) ?? key["text"].string
        Button {
            if session.editing { edit() } else { session.tap(bit) }
        } label: { Text(key["text"].string).fixedSize().frame(maxWidth: .infinity) }
        .buttonStyle(PhoneKeyStyle { pressed in
            guard !session.editing else { return }
            if pressed { session.press(bit) } else { session.release(bit) }
        })
        .disabled(!session.enabled(bit) && !(session.editing && !session.busy && session.running))
        .accessibilityLabel(name).accessibilityIdentifier("phone-key-\(bit)")
        .help(session.enabled(bit) ? name : L("key_unavailable"))
        .overlay {
            SecondaryClickBridge(edit: edit)
                .accessibilityHidden(true)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// Routes only secondary clicks to mapping; primary clicks and focus stay with SwiftUI Button.
struct SecondaryClickBridge: NSViewRepresentable {
    let edit: () -> Void
    func makeNSView(context: Context) -> SecondaryClickView {
        let view = SecondaryClickView(); view.edit = edit
        view.setAccessibilityElement(false)
        return view
    }
    func updateNSView(_ view: SecondaryClickView, context: Context) { view.edit = edit }
    final class SecondaryClickView: NSView {
        var edit: (() -> Void)?
        override func hitTest(_ point: NSPoint) -> NSView? {
            guard let event = NSApp.currentEvent,
                  event.type == .rightMouseDown || (event.type == .leftMouseDown && event.modifierFlags.contains(.control)) else { return nil }
            return super.hitTest(point)
        }
        override func rightMouseDown(with event: NSEvent) { edit?() }
        override func mouseDown(with event: NSEvent) { if event.modifierFlags.contains(.control) { edit?() } }

    }
}

struct PhoneKeyStyle: ButtonStyle {
    let pressed: (Bool) -> Void
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 8).padding(.vertical, 5)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(configuration.isPressed ? AnyShapeStyle(.selection) : AnyShapeStyle(.quaternary), in: Rectangle())
            .contentShape(Rectangle())
            .onChange(of: configuration.isPressed) { _, value in pressed(value) }
            .onDisappear { pressed(false) }
    }
}

struct SessionInfo: View {
    @ObservedObject var session: SessionModel
    @Environment(\.dismiss) var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(session.title).font(.title2)
            Text(session.subtitle).foregroundStyle(.secondary)
            Form {
                ForEach(session.layout["metrics"].array, id: \.selfID) { metric in
                    LabeledContent(metric["title"].string, value: session.running ? session.state["metrics"][metric["key"].string].text : "—")
                        .help(metric["description"].string)
                }
                LabeledContent(L("library_path")) { Text(session.firmware.id).lineLimit(3).textSelection(.enabled) }
            }.textSelection(.enabled)
            HStack { Spacer(); Button(L("done")) { dismiss() }.keyboardShortcut(.defaultAction) }
        }.padding(24).frame(width: 440)
    }
}

extension JSON { var selfID: String { self["name"].string.isEmpty ? (self["key"].string.isEmpty ? self["title"].string : self["key"].string) : self["name"].string } }
