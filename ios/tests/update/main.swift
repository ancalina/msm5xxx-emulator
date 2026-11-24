import Foundation

precondition(newerRelease("v0.2.0", than: "0.1.99") == "0.2.0")
precondition(newerRelease("0.1.9", than: "0.1.99") == nil)
precondition(newerRelease("0.2.0-rc", than: "0.1.99") == nil)
print("release comparison passed")
