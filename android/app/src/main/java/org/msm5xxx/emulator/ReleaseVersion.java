package org.msm5xxx.emulator;

/** Stable releases outrank prereleases of the same version. */
final class ReleaseVersion {
    static boolean newer(String candidate, String current) {
        if (!candidate.matches("[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}")) throw new IllegalArgumentException("Invalid release version");
        String[] next = candidate.split("\\.");
        String[] previous = current.split("[-+]",2)[0].split("\\.");
        if (previous.length != 3) throw new IllegalArgumentException("Invalid installed version");
        for (int i=0;i<3;i++) {
            int comparison = Integer.compare(Integer.parseInt(next[i]),Integer.parseInt(previous[i]));
            if (comparison != 0) return comparison > 0;
        }
        return current.contains("-");
    }
}
