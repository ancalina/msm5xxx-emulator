package org.msm5xxx.emulator;

public final class KeyPressDurationCheck {
    public static void main(String[] args) {
        Object session = new Object();
        KeyPressDuration duration = new KeyPressDuration();
        duration.pressed(session, 1, 1_000_000_000L);
        require(duration.releaseDelayMillis(session, 1, 1_005_000_000L) == 145);
        duration.pressed(session, 1, 2_000_000_000L);
        require(duration.releaseDelayMillis(session, 1, 2_200_000_000L) == 0);
        duration.pressed(session, 1, 3_000_000_000L);
        require(duration.releaseDelayMillis(new Object(), 1, 3_001_000_000L) == 0);
        require(duration.releaseDelayMillis(session, 2, 3_001_000_000L) == 0);
        require(duration.releaseDelayMillis(session, 1, 3_149_999_999L) == 1);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError();
    }
}
