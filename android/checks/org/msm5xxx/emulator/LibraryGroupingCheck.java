package org.msm5xxx.emulator;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public final class LibraryGroupingCheck {
    public static void main(String[] args) {
        List<LibraryGrouping.Group> groups = LibraryGrouping.group(Arrays.asList(
            new LibraryGrouping.Entry("u2", "X350", "b.bin", 12, 20),
            new LibraryGrouping.Entry("u1", "x350", "a.bin", 10, 40),
            new LibraryGrouping.Entry("unknown", "", "z.bin", 7, 0),
            new LibraryGrouping.Entry("other", "X100", "c.bin", 3, 0)));
        if (groups.size() != 3 || !groups.get(0).key.equals("model:x100")) throw new AssertionError("model order");
        LibraryGrouping.Group group = groups.get(1);
        if (group.files.size() != 2 || group.size() != 22 || !group.recent().uri.equals("u1")) throw new AssertionError("group contents");
        if (!group.files.get(0).name.equals("a.bin") || !groups.get(2).key.startsWith("file:")) throw new AssertionError("file order");
        if (LibraryGrouping.group(Arrays.asList(new LibraryGrouping.Entry("missing", "M", "m", -1, 0))).get(0).size() != -1)
            throw new AssertionError("unknown size");
        if (group.stableId() != LibraryGrouping.group(Arrays.asList(group.files.get(0))).get(0).stableId()) throw new AssertionError("stable id");
        if (NetworkTimeValue.parse("1979-12-31 23:59") != null || NetworkTimeValue.parse("2101-01-01 00:00") != null
                || NetworkTimeValue.parse("1980-01-05 00:00") != null || NetworkTimeValue.parse("2025-02-29 12:00") != null)
            throw new AssertionError("time bounds");
        if (LibraryGrouping.needsMetadata("sha", "sha", true)
                || !LibraryGrouping.needsMetadata("sha", "other", true)
                || !LibraryGrouping.needsMetadata("sha", "sha", false)) throw new AssertionError("metadata cache");
        if (NetworkTimeValue.parse("1980-01-06 09:00") == null || NetworkTimeValue.parse("2100-12-31 23:59") == null)
            throw new AssertionError("valid boundaries");
        String value = "2024-02-29 15:07";
        if (!value.equals(NetworkTimeValue.stored(NetworkTimeValue.parse(value)))) throw new AssertionError("time round trip");
        if (NetworkTimeValue.display(NetworkTimeValue.parse(value), Locale.KOREAN).isEmpty()) throw new AssertionError("display");
    }
}
