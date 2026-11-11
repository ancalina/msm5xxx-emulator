// Run on a Mac without firmware or an iOS SDK:
// swiftc ios/app/MSM5xEmu/HandsetInputState.swift ios/tests/input/main.swift -o /tmp/handset-input-tests
// /tmp/handset-input-tests

func expect(_ value: @autoclosure () -> Bool, _ message: String) {
    precondition(value(), message)
}

let fixed = [82: 1, 81: 9, 80: 4, 79: 6, 40: 5, 88: 5, 41: 7, 87: 10, 86: 8, 98: 21]
for (usage, bit) in fixed {
    expect(HandsetInputState.keyboardBit(usage: usage, characters: "") == bit, "fixed key")
}
for digit in 0...9 {
    let bit = digit == 0 ? 21 : digit + 10
    expect(HandsetInputState.keyboardBit(usage: 0, characters: String(digit)) == bit, "digit")
    let usage = digit == 0 ? 98 : 88 + digit
    expect(HandsetInputState.keyboardBit(usage: usage, characters: "") == bit, "numeric pad")
}
expect(HandsetInputState.keyboardBit(usage: 0, characters: "+") == 10, "volume up")
expect(HandsetInputState.keyboardBit(usage: 0, characters: "-") == 8, "volume down")
expect(HandsetInputState.keyboardBit(usage: 0, characters: "x") == nil, "unmapped key")
expect(HandsetInputState.keyboardBit(usage: 0, characters: "12") == nil, "multiple characters")

var state = HandsetInputState()
let down = HandsetInputState.Edge(bit: 5, pressed: true, eventCode: 37)
let up = HandsetInputState.Edge(bit: 5, pressed: false, eventCode: 37)
expect(state.transition(5, pressed: true, source: "keyboard.40", eventCode: 37) == down, "manual mapping")
expect(state.transition(5, pressed: true, source: "keyboard.40", eventCode: 37) == nil, "repeat")
expect(state.transition(5, pressed: true, source: "touch", eventCode: 38) == nil, "overlapping touch")
expect(state.transition(5, pressed: true, source: "keyboard.88", eventCode: 38) == nil, "two physical keys")
expect(state.transition(5, pressed: false, source: "keyboard.40", eventCode: nil) == nil, "first release")
expect(state.transition(5, pressed: false, source: "unknown", eventCode: nil) == nil, "unmatched release")
expect(state.transition(5, pressed: false, source: "touch", eventCode: nil) == nil, "still held")
expect(state.transition(5, pressed: false, source: "keyboard.88", eventCode: 38) == up, "original mapping on release")
expect(state.releaseAll().isEmpty, "already released")
_ = state.transition(1, pressed: true, source: "keyboard.82", eventCode: nil)
_ = state.transition(5, pressed: true, source: "touch", eventCode: 37)
expect(state.releaseAll() == [HandsetInputState.Edge(bit: 1, pressed: false, eventCode: nil), up], "focus loss")
expect(state.releaseAll().isEmpty, "repeated focus loss")
expect(state.transition(5, pressed: false, source: "touch", eventCode: 37) == nil, "late touch release")
expect(state.transition(5, pressed: true, source: "touch", eventCode: 38)?.eventCode == 38, "new mapping after release")
print("Input tests passed")
