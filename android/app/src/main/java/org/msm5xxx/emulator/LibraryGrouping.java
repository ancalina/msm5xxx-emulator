package org.msm5xxx.emulator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

/** Model grouping and stable ordering, independent of Android widgets. */
final class LibraryGrouping {
    static final class Entry {
        final String uri, model, name;
        final long size, lastBoot;
        Entry(String uri, String model, String name, long size, long lastBoot) {
            this.uri = uri; this.model = model == null ? "" : model.trim();
            this.name = name == null ? "" : name; this.size = size; this.lastBoot = lastBoot;
        }
        String key() { return model.isEmpty() ? "file:" + uri : "model:" + model.toLowerCase(Locale.ROOT); }
    }
    static final class Group {
        final String key;
        final List<Entry> files = new ArrayList<>();
        Group(String key) { this.key = key; }
        long size() {
            long total = 0;
            for (Entry entry : files) {
                if (entry.size < 0 || Long.MAX_VALUE - total < entry.size) return -1;
                total += entry.size;
            }
            return total;
        }
        Entry recent() {
            Entry result = files.get(0);
            for (Entry e : files) if (e.lastBoot > result.lastBoot) result = e;
            return result;
        }
        long stableId() {
            long hash = 0xcbf29ce484222325L;
            for (int i = 0; i < key.length(); i++) { hash ^= key.charAt(i); hash *= 0x100000001b3L; }
            return hash;
        }
    }
    static boolean needsMetadata(String storedHash, String currentHash, boolean hasModel) {
        return !hasModel || currentHash == null || currentHash.isEmpty() || !currentHash.equals(storedHash);
    }
    static List<Group> group(List<Entry> source) {
        List<Entry> sorted = new ArrayList<>(source);
        Collections.sort(sorted, Comparator.comparing((Entry e) -> e.model.isEmpty())
                .thenComparing(e -> e.model.toLowerCase(Locale.ROOT))
                .thenComparing(e -> e.name.toLowerCase(Locale.ROOT))
                .thenComparing(e -> e.uri));
        LinkedHashMap<String, Group> result = new LinkedHashMap<>();
        for (Entry entry : sorted) {
            Group g = result.get(entry.key());
            if (g == null) { g = new Group(entry.key()); result.put(entry.key(), g); }
            g.files.add(entry);
        }
        return new ArrayList<>(result.values());
    }
}
