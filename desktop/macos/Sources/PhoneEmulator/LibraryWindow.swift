import SwiftUI
import UniformTypeIdentifiers

struct LibraryScene: View {
    @ObservedObject var library: LibraryModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow
    var body: some View {
        LibraryView(model: library)
            .toolbar {
                ToolbarItem {
                    Button { library.choose() } label: { Label(L("library_import"), systemImage: "plus") }
                        .help(L("library_import"))
                }
                ToolbarItem {
                    Menu {
                        Button(L("library_add_folder")) { library.choose(folder: true) }
                        Menu(L("library_remove_folder")) {
                            ForEach(library.folders, id: \.self) { path in
                                Button(path) { Task { await library.mutate("library.remove_folder", path: path) } }
                            }
                        }.disabled(library.folders.isEmpty)
                        Button(L("library_refresh")) { Task { await library.scan() } }.disabled(library.scanning)
                        Divider()
                        SettingsLink { Text(L("settings") + "…") }
                    } label: { Label(L("library_menu"), systemImage: "ellipsis.circle") }
                    .help(L("library_menu"))
                }
            }
            .fileImporter(isPresented: $library.importing, allowedContentTypes: library.importFolder ? [.folder] : [.data], allowsMultipleSelection: !library.importFolder) { result in
                library.imported(result)
            }
            .task {
                library.presentFirmware = { openWindow(id: "emulator", value: $0) }
                library.presentSecondary = { openWindow(id: "secondary", value: $0) }
                library.dismissSecondary = { dismissWindow(id: "secondary", value: $0) }
                #if DEBUG
                VerificationHarness.startIfRequested(library: library)
                #endif
                await library.initialize()
            }
    }
}
