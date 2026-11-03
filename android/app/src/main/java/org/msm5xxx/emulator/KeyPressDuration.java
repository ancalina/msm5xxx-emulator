package org.msm5xxx.emulator;

/** Keeps quick taps visible to firmware which scans its keypad periodically. */
final class KeyPressDuration {
    private static final long MINIMUM_NANOS = 150_000_000L;
    private long downNanos;
    private int downBit = -1;
    private Object downSession;

    void pressed(Object session, int bit, long nowNanos) {
        downSession = session;
        downBit = bit;
        downNanos = nowNanos;
    }

    long releaseDelayMillis(Object session, int bit, long nowNanos) {
        if (downSession != session || downBit != bit) {
            return 0;
        }
        downSession = null;
        downBit = -1;
        long remaining = MINIMUM_NANOS - Math.max(0, nowNanos - downNanos);
        return remaining > 0 ? (remaining + 999_999L) / 1_000_000L : 0;
    }
}
