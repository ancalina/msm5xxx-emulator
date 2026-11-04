package org.msm5xxx.emulator;

import java.io.File;
import java.nio.file.Files;

public final class LibraryPolicyCheck {
    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("library-check").toFile();
        File copy = new File(root, "copy.bin");
        File outside = new File(root.getParentFile(), "source.bin");
        if (!LibraryPolicy.canDelete(root, copy, true)) throw new AssertionError();
        if (LibraryPolicy.canDelete(root, copy, false)) throw new AssertionError();
        if (LibraryPolicy.canDelete(root, outside, true)) throw new AssertionError();
        if (LibraryPolicy.canDelete(root, new File(root, "../source.bin"), true)) throw new AssertionError();
        File external = Files.createTempFile("library-original", ".bin").toFile();
        File link = new File(root, "link.bin");
        Files.createSymbolicLink(link.toPath(), external.toPath());
        if (LibraryPolicy.canDelete(root, link, true)) throw new AssertionError();
        Files.delete(link.toPath());
        Files.delete(external.toPath());
        if (!LibraryPolicy.sameEntry("a", "hash", "b", "hash")) throw new AssertionError();
        if (LibraryPolicy.sameEntry("a", "", "b", "")) throw new AssertionError();
        if (!LibraryPolicy.sameEntry("a", null, "a", null)) throw new AssertionError();
        String escaped = LibraryPolicy.asciiJson("{\"name\":\"\uD83D\uDCF1\"}");
        if (!escaped.equals("{\"name\":\"\\ud83d\\udcf1\"}")) throw new AssertionError();
        root.delete();
    }
}
