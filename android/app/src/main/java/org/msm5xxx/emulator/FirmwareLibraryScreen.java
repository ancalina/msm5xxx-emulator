package org.msm5xxx.emulator;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.provider.DocumentsContract;
import android.util.LruCache;
import android.os.Handler;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/** Private library index and platform document access; never starts a session. */
final class FirmwareLibraryScreen {
    interface Listener {
        void chooseFolder();
        void importFile();
        void boot(Uri uri, String name, long size);
        void openSettings();
    }
    private static final String PREFS = "firmware-library";
    private final Activity activity;
    private final Listener listener;
    private final SharedPreferences preferences;
    private final Object stateLock = new Object();
    private static ExecutorService backgroundExecutor(String name) {
        return Executors.newSingleThreadExecutor(task -> new Thread(() -> {
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
            task.run();
        }, name));
    }
    private final ExecutorService scanner = backgroundExecutor("library-scan");
    private final ArrayList<JSONObject> visible = new ArrayList<>();
    private boolean showing;
    private LibraryContent content;
    private boolean loading;
    private String pendingMessage;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private long lastListUpdate;
    private Runnable listUpdate;
    private final AtomicLong revision = new AtomicLong();
    private String previousCopy;
    private String previousName;

    void setPreviousCopy(String path, String name) {
        previousCopy = path;
        previousName = name;
    }

    FirmwareLibraryScreen(Activity activity, Listener listener) {
        this.activity = activity;
        this.listener = listener;
        preferences = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private JSONArray read(String key) {
        try { return new JSONArray(preferences.getString(key, "[]")); }
        catch (JSONException ignored) { return new JSONArray(); }
    }

    void addFolder(Uri uri) {
        synchronized (stateLock) {
            JSONArray folders = read("folders");
            for (int i = 0; i < folders.length(); i++) if (uri.toString().equals(folders.optString(i))) return;
            folders.put(uri.toString());
            revision.incrementAndGet();
            preferences.edit().putString("folders", folders.toString()).apply();
        }
        refresh();
    }

    void importFile(Uri source, String name) {
        loading = true;
        publishRows();
        scanner.execute(() -> {
            File directory = new File(activity.getFilesDir(), "firmware-library");
            File target = new File(directory, java.util.UUID.randomUUID() + ".bin");
            try {
                if (!directory.isDirectory() && !directory.mkdirs()) throw new IOException("directory");
                long limit = PythonRuntime.librarySizeLimit(activity, name);
                try (InputStream input = activity.getContentResolver().openInputStream(source);
                     FileOutputStream output = new FileOutputStream(target)) {
                    if (input == null) throw new IOException("source");
                    byte[] buffer = new byte[65536];
                    long total = 0;
                    int count;
                    while ((count = input.read(buffer)) != -1) {
                        total += count;
                        if (total > limit) throw new IOException("size");
                        output.write(buffer, 0, count);
                    }
                }
                JSONObject metadata = new JSONObject(PythonRuntime.describeLibrary(activity, target, name));
                String sha = metadata.optString("sha256", "");
                synchronized (stateLock) {
                    JSONArray entries = read("entries");
                    for (int i = 0; i < entries.length(); i++) {
                        JSONObject existing = entries.optJSONObject(i);
                        if (existing != null && existing.optBoolean("available", false)
                                && !sha.isEmpty() && sha.equals(existing.optString("sha256"))) {
                            target.delete();
                            activity.runOnUiThread(this::refresh);
                            return;
                        }
                    }
                    JSONObject entry = new JSONObject().put("uri", Uri.fromFile(target).toString())
                            .put("name", name).put("size", target.length()).put("imported", true).put("available", true)
                            .put("source_stamp", target.lastModified()).put("source_size", target.length())
                            .put("sha256", sha).put("model", metadata.isNull("model") ? "" : metadata.optString("model", ""))
                            .put("display", metadata.optString("name", name))
                            .put("chipset", metadata.isNull("chipset") ? "—" : metadata.optString("chipset", "—"));
                    entries.put(entry);
                    revision.incrementAndGet();
                    preferences.edit().putString("entries", entries.toString()).apply();
                }
                activity.runOnUiThread(this::refresh);
            } catch (IOException | JSONException | RuntimeException error) {
                target.delete();
                activity.runOnUiThread(() -> {
                    loading = false;
                    publishRows();
                    showMessage(activity.getString(R.string.error_unreadable_document));
                });
            }
        });
    }

    void show() {
        if (showing) { refresh(); return; }
        showing = true;
        if (content == null) content = LibraryContent.install(activity, this);
        if (pendingMessage != null) showMessage(pendingMessage);
        visible.clear();
        JSONArray cached = read("entries");
        for (int i = 0; i < cached.length(); i++) {
            JSONObject entry = cached.optJSONObject(i);
            if (entry != null) visible.add(entry);
        }
        publishRows();
        refresh();
    }

    void showMessage(String message) {
        pendingMessage = message;
        if (content != null) {
            content.showMessage(message);
            pendingMessage = null;
        }
    }

    void chooseFolder() { listener.chooseFolder(); }
    void chooseImport() { listener.importFile(); }
    void openSettings() { listener.openSettings(); }

    private void schedulePublish() {
        if (listUpdate != null) ui.removeCallbacks(listUpdate);
        long delay = Math.max(0, 250 - (android.os.SystemClock.uptimeMillis() - lastListUpdate));
        listUpdate = () -> { if (showing) publishRows(); };
        ui.postDelayed(listUpdate, delay);
    }

    private void publishRows() {
        if (content != null) content.publish(new ArrayList<>(visible), loading);
        lastListUpdate = android.os.SystemClock.uptimeMillis();
    }

    static void removeFolder(Context context, String folder) {
        android.content.SharedPreferences preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        JSONArray folders, entries;
        try {
            folders = new JSONArray(preferences.getString("folders", "[]"));
            entries = new JSONArray(preferences.getString("entries", "[]"));
        } catch (JSONException error) { return; }
        JSONArray kept = new JSONArray(), remaining = new JSONArray();
        for (int i = 0; i < folders.length(); i++) if (!folder.equals(folders.optString(i))) kept.put(folders.optString(i));
        String prefix = folder + "/document/";
        for (int i = 0; i < entries.length(); i++) {
            JSONObject entry = entries.optJSONObject(i);
            if (entry != null && !entry.optBoolean("imported") && entry.optString("uri").startsWith(prefix)) continue;
            remaining.put(entry);
        }
        preferences.edit().putString("folders", kept.toString()).putString("entries", remaining.toString()).apply();
        try {
            context.getContentResolver().releasePersistableUriPermission(Uri.parse(folder),
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (RuntimeException ignored) { }
    }

    static String[] folders(Context context) {
        try {
            JSONArray folders = new JSONArray(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("folders", "[]"));
            String[] out = new String[folders.length()];
            for (int i = 0; i < out.length; i++) out[i] = folders.optString(i);
            return out;
        } catch (JSONException error) { return new String[0]; }
    }

    boolean isShowing() { return showing; }

    void dismiss() {
        revision.incrementAndGet();
        if (showing) {
            showing = false;

        }
    }

    void close() { dismiss(); scanner.shutdown(); }

    void select(JSONObject entry) {
        if (!entry.optBoolean("available", false)) return;
        String value = entry.optString("uri");
        String name = entry.optString("name");
        long size = entry.optLong("size", -1);
        boolean imported = entry.optBoolean("imported");
        long selectedRevision = revision.get();
        new Thread(() -> {
            boolean readable;
            Uri uri = Uri.parse(value);
            try {
                if (imported) {
                    File file = new File(uri.getPath());
                    readable = file.isFile() && file.canRead();
                } else {
                    try (ParcelFileDescriptor descriptor = activity.getContentResolver().openFileDescriptor(uri, "r")) {
                        readable = descriptor != null;
                    }
                }
            } catch (IOException | RuntimeException error) { readable = false; }
            boolean available = readable;
            activity.runOnUiThread(() -> {
                if (!showing || revision.get() != selectedRevision) return;
                boolean stillPresent = false;
                for (JSONObject row : visible) if (value.equals(row.optString("uri"))) stillPresent = true;
                if (!stillPresent) return;
                if (!available) {
                    updateEntry(value, "available", false);
                    content.showMessage(activity.getString(R.string.library_unavailable));
                    refresh();
                } else {
                    listener.boot(uri, name, size);
                }
            });
        }, "library-selection").start();
    }

    void info(JSONObject entry) {
        String detail = activity.getString(R.string.library_info_body,
                entry.optString("display", entry.optString("name")), entry.optString("chipset", "—"),
                entry.optString("sha256", "—"), entry.optString("uri"));
        detail += "\n" + SelectionLabels.size(activity, entry.optLong("size", -1))
                + "\n" + (entry.optLong("last_booted", 0) == 0 ? activity.getString(R.string.library_never)
                : DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, activity.getResources().getConfiguration().getLocales().get(0)).format(new Date(entry.optLong("last_booted"))));
        content.showInfo(activity.getString(R.string.library_info), detail);
    }

    void requestRemove(JSONObject entry) {
        content.confirm(activity.getString(R.string.library_remove),
                activity.getString(R.string.library_remove_confirm, entry.optString("display", entry.optString("name"))),
                () -> remove(entry));
    }

    private void remove(JSONObject entry) {
        synchronized (stateLock) {
        revision.incrementAndGet();
        String uri = entry.optString("uri");
        String hash = entry.optString("sha256", "");
        JSONArray entries = read("entries"), kept = new JSONArray(), excluded = read("excluded");
        for (int i = 0; i < entries.length(); i++) {
            JSONObject item = entries.optJSONObject(i);
            if (item == null) continue;
            String candidate = item.optString("uri");
            if (!LibraryPolicy.sameEntry(uri, hash, candidate, item.optString("sha256", ""))) {
                kept.put(item);
                continue;
            }
            if (item.optBoolean("imported")) {
                try {
                    File root = new File(activity.getFilesDir(), "firmware-library").getCanonicalFile();
                    File file = new File(Uri.parse(candidate).getPath()).getCanonicalFile();
                    if (LibraryPolicy.canDelete(root, file, true) && file.exists() && !file.delete()) return;
                } catch (IOException | NullPointerException error) { return; }
            }
            excluded.put(candidate);
        }
        preferences.edit().putString("entries", kept.toString()).putString("excluded", excluded.toString()).apply();
        }
        refresh();
    }

    void ensureEntry(Uri uri, String name, long size) {
        synchronized (stateLock) {
        JSONArray entries = read("entries");
        for (int i = 0; i < entries.length(); i++) {
            JSONObject item = entries.optJSONObject(i);
            if (item != null && uri.toString().equals(item.optString("uri"))) return;
        }
        try {
            entries.put(new JSONObject().put("uri", uri.toString()).put("name", name)
                    .put("size", size).put("imported", false));
            revision.incrementAndGet();
            preferences.edit().putString("entries", entries.toString()).apply();
        } catch (JSONException ignored) { }
        }
    }

    void recordBoot(String uri, String sha, String sessionPath, String name) {
        boolean needsMetadata = true;
        synchronized (stateLock) {
            JSONArray entries = read("entries");
            for (int i = 0; i < entries.length(); i++) {
                JSONObject item = entries.optJSONObject(i);
                if (item != null && uri != null && uri.equals(item.optString("uri"))) {
                    needsMetadata = LibraryGrouping.needsMetadata(item.optString("sha256", ""), sha, item.has("model"));
                    break;
                }
            }
        }
        updateEntry(uri, "sha256", sha);
        updateEntry(uri, "last_booted", System.currentTimeMillis());
        if (!needsMetadata || uri == null || sessionPath == null || name == null) return;
        scanner.execute(() -> {
            try {
                JSONObject metadata = new JSONObject(PythonRuntime.describeLibrary(activity, new File(sessionPath), name));
                updateEntry(uri, "display", metadata.optString("name", name));
                updateEntry(uri, "model", metadata.isNull("model") ? "" : metadata.optString("model", ""));
                updateEntry(uri, "chipset", metadata.isNull("chipset") ? "—" : metadata.optString("chipset", "—"));
                updateEntry(uri, "preview_deferred", false);
            } catch (IOException | JSONException | RuntimeException ignored) { }
        });
    }

    void recordFrame(String uri, Bitmap frame) {
        if (uri == null || frame == null || frame.isRecycled()) return;
        try {
            File directory = new File(activity.getFilesDir(), "library-thumbnails");
            if (!directory.isDirectory() && !directory.mkdirs()) return;
            String key = null;
            JSONArray entries = read("entries");
            for (int i = 0; i < entries.length(); i++) {
                JSONObject entry = entries.optJSONObject(i);
                if (entry != null && uri.equals(entry.optString("uri"))) {
                    key = entry.optString("sha256", "");
                    break;
                }
            }
            if (key == null || !key.matches("[0-9a-f]{64}")) return;
            File target = new File(directory, key + ".png");
            float scale = Math.min(1f, 160f / Math.max(frame.getWidth(), frame.getHeight()));
            Bitmap small = Bitmap.createScaledBitmap(frame, Math.max(1, Math.round(frame.getWidth() * scale)),
                    Math.max(1, Math.round(frame.getHeight() * scale)), false);
            try (FileOutputStream output = new FileOutputStream(target)) { small.compress(Bitmap.CompressFormat.PNG, 100, output); }
            if (small != frame) small.recycle();
            updateEntry(uri, "thumbnail", target.getPath());
        } catch (IOException | RuntimeException ignored) { }
    }

    private void updateEntry(String uri, String key, Object value) {
        synchronized (stateLock) {
        revision.incrementAndGet();
        JSONArray entries = read("entries");
        try {
            for (int i = 0; i < entries.length(); i++) {
                JSONObject item = entries.optJSONObject(i);
                if (item != null && uri != null && uri.equals(item.optString("uri"))) item.put(key, value);
            }
            preferences.edit().putString("entries", entries.toString()).apply();
        } catch (JSONException ignored) { }
        }
    }

    private JSONObject describeDocument(Uri uri, String name, long token) throws IOException, JSONException {
        try (ParcelFileDescriptor source = activity.getContentResolver().openFileDescriptor(uri, "r")) {
            if (source == null) throw new IOException("source unavailable");
            try {
                if (OsConstants.S_ISREG(Os.fstat(source.getFileDescriptor()).st_mode)) {
                    return new JSONObject(PythonRuntime.describeLibrary(activity,
                            new File("/proc/self/fd/" + source.getFd()), name));
                }
                // API 30 exposes an anonymous in-memory file descriptor; no source file is copied to storage.
                if (Build.VERSION.SDK_INT < 30) return null;
                FileDescriptor raw = Os.memfd_create("firmware-library", OsConstants.MFD_CLOEXEC);
                try {
                    try (ParcelFileDescriptor memory = ParcelFileDescriptor.dup(raw);
                         InputStream input = new ParcelFileDescriptor.AutoCloseInputStream(
                                 ParcelFileDescriptor.dup(source.getFileDescriptor()))) {
                        long limit = PythonRuntime.librarySizeLimit(activity, name);
                        long total = 0;
                        byte[] buffer = new byte[65536];
                        int count;
                        while ((count = input.read(buffer)) != -1) {
                            if (token != revision.get()) throw new IOException("cancelled");
                            total += count;
                            if (total > limit) throw new IOException("size");
                            int offset = 0;
                            while (offset < count) {
                                int written = Os.write(memory.getFileDescriptor(), buffer, offset, count - offset);
                                if (written <= 0) throw new IOException("write");
                                offset += written;
                            }
                        }
                        return new JSONObject(PythonRuntime.describeLibrary(activity,
                                new File("/proc/self/fd/" + memory.getFd()), name));
                    }
                } finally { Os.close(raw); }
            } catch (ErrnoException error) {
                return null;
            }
        }
    }

    /** Show each newly described file at once; known rows not yet rescanned stay listed meanwhile. */
    private void publishPartial(long token, ArrayList<JSONObject> rows, JSONArray entries, int next, HashSet<String> hashes) {
        ArrayList<JSONObject> snapshot = new ArrayList<>();
        HashSet<String> listed = new HashSet<>(hashes);
        try {
            for (JSONObject row : rows) snapshot.add(new JSONObject(row.toString()));
            for (int j = next; j < entries.length(); j++) {
                JSONObject pending = entries.optJSONObject(j);
                if (pending == null || !pending.optBoolean("available") || !pending.has("model")) continue;
                String sha = pending.optString("sha256", "");
                if (sha.isEmpty() || !listed.add(sha)) continue;
                snapshot.add(new JSONObject(pending.toString()));
            }
        } catch (JSONException error) { return; }
        activity.runOnUiThread(() -> {
            if (token != revision.get() || !showing) return;
            visible.clear(); visible.addAll(snapshot); schedulePublish();
        });
    }

    private Cursor queryChildren(Uri children, String[] columns) {
        try { return activity.getContentResolver().query(children, columns, null, null, null); }
        catch (IllegalArgumentException error) {
            return activity.getContentResolver().query(children, java.util.Arrays.copyOf(columns, 4), null, null, null);
        }
    }

    void refresh() {
        if (!showing) return;
        final long token = revision.incrementAndGet();
        loading = true;
        publishRows();
        scanner.execute(() -> {
            JSONArray entries = read("entries"), folders = read("folders"), excluded = read("excluded");
            if (!preferences.getBoolean("private_migrated", false)) {
                if (previousCopy != null && previousName != null) {
                    File old = new File(previousCopy);
                    File sessions = new File(activity.getNoBackupFilesDir(), "session");
                    File target = new File(new File(activity.getFilesDir(), "firmware-library"), "migrated.bin");
                    try {
                        if (old.getCanonicalPath().startsWith(sessions.getCanonicalPath() + File.separator)
                                && old.isFile() && old.canRead()
                                && old.length() <= PythonRuntime.librarySizeLimit(activity, previousName)) {
                            if (!target.getParentFile().isDirectory() && !target.getParentFile().mkdirs()) throw new IOException("directory");
                            try (InputStream input = new FileInputStream(old); FileOutputStream output = new FileOutputStream(target)) {
                                byte[] buffer = new byte[65536]; int count;
                                while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
                            }
                            entries.put(new JSONObject().put("uri", Uri.fromFile(target).toString())
                                    .put("name", previousName).put("size", target.length())
                                    .put("imported", true).put("available", true));
                        }
                    } catch (IOException | JSONException ignored) { target.delete(); }
                }
                File external = activity.getExternalFilesDir(null);
                File[] roots = {new File(activity.getFilesDir(), "firmware"),
                        external == null ? null : new File(external, "firmware")};
                for (File file : LibraryPolicy.migrationFiles(roots)) {
                    if (token != revision.get()) return;
                    String uri = Uri.fromFile(file).toString();
                    boolean exists = false;
                    for (int n = 0; n < entries.length(); n++) {
                        JSONObject old = entries.optJSONObject(n);
                        if (old != null && uri.equals(old.optString("uri"))) { exists = true; break; }
                    }
                    if (!exists) try {
                        if (file.length() <= PythonRuntime.librarySizeLimit(activity, file.getName()))
                            entries.put(new JSONObject().put("uri", uri).put("name", file.getName())
                                    .put("size", file.length()).put("imported", true).put("available", true));
                    } catch (IOException | JSONException ignored) { }
                }
            }
            HashSet<String> seenUris = new HashSet<>(), excludedUris = new HashSet<>(), oversizedUris = new HashSet<>();
            for (int i = 0; i < excluded.length(); i++) excludedUris.add(excluded.optString(i));
            for (int i = 0; i < entries.length(); i++) {
                JSONObject item = entries.optJSONObject(i);
                if (item != null) { seenUris.add(item.optString("uri")); try { item.put("available", false); } catch (JSONException ignored) {} }
            }
            for (int i = 0; i < folders.length(); i++) {
                if (token != revision.get()) return;
                Uri tree = Uri.parse(folders.optString(i));
                try {
                    Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree));
                    String[] columns = {DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                            DocumentsContract.Document.COLUMN_SIZE, DocumentsContract.Document.COLUMN_MIME_TYPE,
                            DocumentsContract.Document.COLUMN_LAST_MODIFIED};
                    try (Cursor cursor = queryChildren(children, columns)) {
                        if (cursor == null) continue;
                        while (cursor.moveToNext()) {
                            if (token != revision.get()) return;
                            if (DocumentsContract.Document.MIME_TYPE_DIR.equals(cursor.getString(3))) continue;
                            String displayName = SelectionLabels.displayName(activity, cursor.getString(1));
                            long fileSize = cursor.isNull(2) ? -1 : cursor.getLong(2);
                            Uri document = DocumentsContract.buildDocumentUriUsingTree(tree, cursor.getString(0));
                            String uri = document.toString();
                            if (fileSize >= 0 && fileSize > PythonRuntime.librarySizeLimit(activity, displayName)) {
                                oversizedUris.add(uri);
                                continue;
                            }
                            if (excludedUris.contains(uri)) continue;
                            JSONObject entry = null;
                            for (int n = 0; n < entries.length(); n++) {
                                JSONObject candidate = entries.optJSONObject(n);
                                if (candidate != null && uri.equals(candidate.optString("uri"))) { entry = candidate; break; }
                            }
                            if (entry == null && seenUris.add(uri)) {
                                entry = new JSONObject().put("uri", uri).put("name", displayName)
                                        .put("size", cursor.isNull(2) ? -1 : cursor.getLong(2)).put("imported", false);
                                entries.put(entry);
                            }
                            if (entry != null) {
                                int stampColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED);
                                long stamp = stampColumn < 0 || cursor.isNull(stampColumn) ? 0 : cursor.getLong(stampColumn);
                                entry.put("observed_stamp", stamp).put("observed_size", fileSize)
                                        .put("available", true).put("name", displayName).put("size", fileSize);
                            }
                        }
                    }
                } catch (IOException | RuntimeException | JSONException ignored) { }
            }
            ArrayList<JSONObject> rows = new ArrayList<>();
            HashSet<String> hashes = new HashSet<>();
            for (int i = 0; i < entries.length(); i++) {
                if (token != revision.get()) return;
                JSONObject entry = entries.optJSONObject(i);
                if (entry == null || oversizedUris.contains(entry.optString("uri"))) continue;
                Uri uri = Uri.parse(entry.optString("uri"));
                try {
                    JSONObject metadata = null;
                    File file = entry.optBoolean("imported") ? new File(uri.getPath()) : null;
                    if (file != null) {
                        entry.put("available", file.isFile() && file.canRead());
                        entry.put("observed_stamp", file.lastModified()).put("observed_size", file.length());
                    }
                    if (!entry.optBoolean("available")) { rows.add(entry); continue; }
                    long stamp = entry.optLong("observed_stamp", 0);
                    long actualSize = entry.optLong("observed_size", -1);
                    boolean cacheHit = stamp > 0 && actualSize >= 0 && entry.has("model")
                            && !entry.optString("sha256", "").isEmpty()
                            && stamp == entry.optLong("source_stamp", -1)
                            && actualSize == entry.optLong("source_size", -2);
                    if (!cacheHit) {
                        if (file != null) metadata = new JSONObject(PythonRuntime.describeLibrary(activity, file, entry.optString("name")));
                        else metadata = describeDocument(uri, entry.optString("name"), token);
                    }
                    if (!cacheHit && metadata == null) entry.put("preview_deferred", entry.optString("sha256", "").isEmpty());
                    else if (metadata != null) {
                        entry.put("source_stamp", stamp).put("source_size", actualSize);
                        entry.remove("preview_deferred");
                        entry.put("sha256", metadata.optString("sha256"));
                        entry.put("model", metadata.isNull("model") ? "" : metadata.optString("model", ""));
                        entry.put("display", metadata.optString("name", entry.optString("name")));
                        entry.put("chipset", metadata.isNull("chipset") ? "—" : metadata.optString("chipset", "—"));
                        entry.put("size", metadata.optLong("size", entry.optLong("size", -1)));
                    }
                    String sha = entry.optString("sha256", "");
                    if (!sha.isEmpty() && !hashes.add(sha)) continue;
                    rows.add(entry);
                    if (!cacheHit) publishPartial(token, rows, entries, i + 1, hashes);
                } catch (IOException | RuntimeException | JSONException ignored) { }
            }
            HashSet<String> availableHashes = new HashSet<>();
            for (JSONObject row : rows) {
                String sha = row.optString("sha256", "");
                if (row.optBoolean("available", false) && !sha.isEmpty()) availableHashes.add(sha);
            }
            rows.removeIf(row -> !row.optBoolean("available", false)
                    && availableHashes.contains(row.optString("sha256", "")));
            synchronized (stateLock) {
                if (token != revision.get()) return;
                preferences.edit().putString("entries", entries.toString()).putBoolean("private_migrated", true).apply();
            }
            activity.runOnUiThread(() -> {
                if (token != revision.get() || !showing) return;
                visible.clear(); visible.addAll(rows); loading = false; schedulePublish();
            });
        });
    }
}
