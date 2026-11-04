package org.msm5xxx.emulator;

import java.io.File;
import java.io.IOException;

/** Rules for deleting a copy owned by the app library. */
final class LibraryPolicy {
    private LibraryPolicy() {}

    static java.util.List<File> migrationFiles(File[] roots) {
        java.util.List<File> result = new java.util.ArrayList<>();
        for (File root : roots) {
            File[] files = root == null ? null : root.listFiles();
            if (files == null) continue;
            java.util.Arrays.sort(files);
            for (File file : files) {
                if (!file.getName().startsWith(".") && file.isFile() && file.canRead()) result.add(file);
            }
        }
        return result;
    }

    static String asciiJson(String value) {
        StringBuilder result = new StringBuilder(value.length());
        final char[] hex = "0123456789abcdef".toCharArray();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= 0x7f) result.append(c);
            else {
                result.append('\\').append('u');
                result.append(hex[(c >> 12) & 15]).append(hex[(c >> 8) & 15]);
                result.append(hex[(c >> 4) & 15]).append(hex[c & 15]);
            }
        }
        return result.toString();
    }

    static boolean sameEntry(String id, String hash, String candidateId, String candidateHash) {
        return id.equals(candidateId) || (hash != null && !hash.isEmpty() && hash.equals(candidateHash));
    }

    static boolean canDelete(File root, File candidate, boolean imported) {
        if (!imported || root == null || candidate == null) return false;
        try {
            return root.getCanonicalFile().equals(candidate.getCanonicalFile().getParentFile());
        } catch (IOException error) {
            return false;
        }
    }
}
