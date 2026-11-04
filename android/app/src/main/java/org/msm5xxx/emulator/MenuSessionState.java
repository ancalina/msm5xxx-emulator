package org.msm5xxx.emulator;

/** Session action availability while a session is starting or running. */
final class MenuSessionState {
    final boolean start;
    final boolean stop;
    final boolean reboot;

    MenuSessionState(boolean running, boolean starting, boolean ready) {
        start = !running && !starting && ready;
        stop = running || starting;
        reboot = running && !starting;
    }
}
