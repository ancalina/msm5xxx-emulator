/// Combines independent input sources into handset edges. A release uses the
/// event code admitted at press time, even if the mapping changes while held.
struct HandsetInputState {
    struct Edge: Equatable {
        let bit: Int
        let pressed: Bool
        let eventCode: Int?
    }
    private struct Held {
        var sources: Set<String>
        let eventCode: Int?
    }
    private var held: [Int: Held] = [:]

    mutating func transition(_ bit: Int, pressed: Bool, source: String, eventCode: Int?) -> Edge? {
        if pressed {
            if var key = held[bit] {
                key.sources.insert(source)
                held[bit] = key
                return nil
            }
            held[bit] = Held(sources: [source], eventCode: eventCode)
            return Edge(bit: bit, pressed: true, eventCode: eventCode)
        }
        guard var key = held[bit], key.sources.remove(source) != nil else { return nil }
        if key.sources.isEmpty {
            held.removeValue(forKey: bit)
            return Edge(bit: bit, pressed: false, eventCode: key.eventCode)
        }
        held[bit] = key
        return nil
    }

    mutating func releaseAll() -> [Edge] {
        let edges = held.map { Edge(bit: $0.key, pressed: false, eventCode: $0.value.eventCode) }
        held.removeAll()
        return edges.sorted { $0.bit < $1.bit }
    }

    static func keyboardBit(usage: Int, characters: String) -> Int? {
        // USB HID usages cover arrows and numeric pads independently of layout.
        switch usage {
        case 82: return 1
        case 81: return 9
        case 80: return 4
        case 79: return 6
        case 40, 88: return 5
        case 41: return 7
        case 87: return 10
        case 86: return 8
        case 89...97: return 11 + usage - 89
        case 98: return 21
        default: break
        }
        guard characters.count == 1 else { return nil }
        switch characters {
        case "+": return 10
        case "-": return 8
        case "0": return 21
        case "1"..."9": return Int(characters).map { 10 + $0 }
        default: return nil
        }
    }
}
