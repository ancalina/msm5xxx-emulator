package org.msm5xxx.emulator;

public final class SelectionLabelsCheck {
    public static void main(String[] args) {
        require(SelectionLabels.cleanName(" \n") == null);
        require("a\uFFFDb".equals(SelectionLabels.cleanName("a\u202Eb")));
        require(SelectionLabels.cleanName("x".repeat(121)).length() == 120);
        require("\uFFFD".equals(SelectionLabels.cleanName("\u200e")));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError();
    }
}
