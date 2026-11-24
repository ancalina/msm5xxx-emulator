"""Run the actual store filesystem methods against disposable native files."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def program(source):
    def method(signature):
        start = source.index(signature)
        end = source.index("\n    }", start) + len("\n    }")
        return source[start:end]

    types = source[source.index("struct LibraryFolder:"):source.index("final class FirmwareLibraryStore:")]
    # shortcut: filesystem-only harness, replace when the app gains an iOS unit-test target.
    return "import Foundation\n" + types + r'''
private final class StoreFixture {
    var index = LibraryIndex()
    var entries: [LibraryEntry] = []
    var indexReadable = true
    var scanning = false
    var error: String?
    let support: URL
    let importsURL: URL
    let indexURL: URL
    func nextGeneration() -> Int { 0 }
    init(_ root: URL) throws {
        support = root.appendingPathComponent("support")
        importsURL = support.appendingPathComponent("FirmwareLibrary")
        indexURL = support.appendingPathComponent("firmware-library.json")
        try FileManager.default.createDirectory(at: importsURL, withIntermediateDirectories: true)
    }
''' + method("    @discardableResult private func save()") + "\n" + method("    func remove(_ entry: LibraryEntry)") + r'''
}
let fm = FileManager.default
let root = URL(fileURLWithPath: CommandLine.arguments[1])
private let store = try StoreFixture(root)
let owned = store.importsURL.appendingPathComponent("owned.bin")
let external = root.appendingPathComponent("external.bin")
let bytes = Data("firmware preservation fixture".utf8)
func entry(_ id: String, _ url: URL) -> LibraryEntry {
    LibraryEntry(id: id, name: url.lastPathComponent, path: url.path, folder: nil,
                 imported: true, model: nil, display: nil, chipset: nil, sha256: "same",
                 size: Int64(bytes.count), lastBooted: nil, thumbnail: nil, available: true)
}
func seed(_ items: [LibraryEntry]) throws {
    store.index = LibraryIndex(entries: items)
    store.entries = items
    store.error = nil
    try JSONEncoder().encode(store.index).write(to: store.indexURL, options: .atomic)
}
try bytes.write(to: owned)
let item = entry("owned", owned)
try seed([item])
let saved = try Data(contentsOf: store.indexURL)
try fm.setAttributes([.posixPermissions: 0o555], ofItemAtPath: store.support.path)
store.remove(item)
try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: store.support.path)
precondition(store.error == "Library error")
guard fm.fileExists(atPath: owned.path) else {
    print("FAIL: failed index save deleted firmware"); exit(1)
}
let retained = try Data(contentsOf: owned)
precondition(retained == bytes, "Failed index save deleted firmware")
let unchanged = try Data(contentsOf: store.indexURL)
precondition(unchanged == saved, "Failed save changed index")
precondition(store.entries.count == 1 && store.index.entries.count == 1 && store.index.excluded.isEmpty)
store.remove(item)
precondition(!fm.fileExists(atPath: owned.path) && store.entries.isEmpty)
private let removedIndex = try JSONDecoder().decode(LibraryIndex.self, from: Data(contentsOf: store.indexURL))
precondition(removedIndex.entries.isEmpty)
try bytes.write(to: owned)
try bytes.write(to: external)
try seed([item, entry("outside", external)])
store.remove(item)
precondition(store.error == "Library removal incomplete")
precondition(!fm.fileExists(atPath: owned.path))
let externalBytes = try Data(contentsOf: external)
precondition(externalBytes == bytes)
private let partial = try JSONDecoder().decode(LibraryIndex.self, from: Data(contentsOf: store.indexURL))
precondition(partial.entries.count == 2 && !partial.entries[0].available && partial.entries[1].available)
print("PASS: failed index save preserves firmware/index/draft; successful removal; partial deletion/path boundary")
'''


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("swiftc") and os.geteuid() != 0,
                     "requires non-root macOS Swift/Foundation")
class LibraryRemovalTests(unittest.TestCase):
    def test_native_save_failure_and_partial_deletion(self):
        source = (ROOT / "ios/app/MSM5xEmu/FirmwareLibrary.swift").read_text()
        with tempfile.TemporaryDirectory(prefix="library-removal-", dir=os.environ.get("TMPDIR")) as folder:
            folder = Path(folder)
            swift = folder / "main.swift"
            swift.write_text(program(source))
            executable = folder / "test"
            subprocess.run(["swiftc", "-module-cache-path", str(folder / "module-cache"), str(swift), "-o", str(executable)], check=True)
            subprocess.run([str(executable), str(folder / "data")], check=True)


if __name__ == "__main__":
    unittest.main()
