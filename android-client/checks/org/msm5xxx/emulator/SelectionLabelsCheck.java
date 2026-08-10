package org.msm5xxx.emulator;

public final class SelectionLabelsCheck {
    public static void main(String[] args) {
        require("Unnamed firmware".equals(SelectionLabels.displayName(" \n")));
        require("a\uFFFDb".equals(SelectionLabels.displayName("a\u202Eb")));
        require(SelectionLabels.displayName("x".repeat(121)).length() == 120);
        require("Size unavailable".equals(SelectionLabels.size(-1)));
        require("4096 bytes".equals(SelectionLabels.size(4096)));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError();
        }
    }
}
