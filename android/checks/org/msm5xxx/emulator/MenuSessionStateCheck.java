package org.msm5xxx.emulator;

public final class MenuSessionStateCheck {
    public static void main(String[] args) {
        check(false, false, false, false, false, false);
        check(false, false, true, true, false, false);
        check(false, true, true, false, true, false);
        check(true, false, true, false, true, true);
    }

    private static void check(boolean running, boolean starting, boolean ready,
                              boolean start, boolean stop, boolean reboot) {
        MenuSessionState state = new MenuSessionState(running, starting, ready);
        if (state.start != start || state.stop != stop || state.reboot != reboot)
            throw new AssertionError("incorrect action state");
    }
}
