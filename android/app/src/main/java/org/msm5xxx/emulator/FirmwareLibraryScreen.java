package org.msm5xxx.emulator;

import android.app.Activity;
import android.app.AlertDialog;
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
import android.view.View;
import android.view.Gravity;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.BaseAdapter;
import android.util.LruCache;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

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
    private final int infoAction = View.generateViewId();
    private final int removeAction = View.generateViewId();
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
    private ListView list;
    private TextView empty;
    private LinearLayout emptyArea;
    private LibraryAdapter adapter;
    private final ArrayList<LibraryGrouping.Group> groups = new ArrayList<>();
    private final java.util.Map<String, JSONObject> indexed = new java.util.HashMap<>();
    private final java.util.Map<String, String> renderFingerprints = new java.util.HashMap<>();
    private final LruCache<String, Bitmap> thumbnails = new LruCache<>(4 * 1024 * 1024) {
        @Override protected int sizeOf(String key, Bitmap value) { return value.getByteCount(); }
    };
    private final ExecutorService imageLoader = backgroundExecutor("library-images");
    private final java.util.Set<String> loadingImages = java.util.Collections.synchronizedSet(new java.util.HashSet<>());
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
                activity.runOnUiThread(() -> new AlertDialog.Builder(activity)
                        .setMessage(R.string.error_unreadable_document).setPositiveButton(android.R.string.ok, null).show());
            }
        });
    }

    void show() {
        if (showing) { refresh(); return; }
        showing = true;
        LinearLayout body = new LinearLayout(activity);
        body.setOrientation(LinearLayout.VERTICAL);
        int pad = Math.round(12 * activity.getResources().getDisplayMetrics().density);
        body.setFitsSystemWindows(true);
        body.setBackgroundColor(android.graphics.Color.rgb(18, 18, 18));
        LinearLayout titleBar = new LinearLayout(activity);
        titleBar.setGravity(Gravity.CENTER_VERTICAL);
        titleBar.setPadding(Math.round(16 * activity.getResources().getDisplayMetrics().density), 0, 0, 0);
        TextView title = new TextView(activity);
        title.setText(R.string.library_title);
        title.setTextSize(20);
        title.setTextColor(android.graphics.Color.WHITE);
        titleBar.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        int square = Math.round(48 * activity.getResources().getDisplayMetrics().density);
        android.widget.ImageButton add = iconButton(R.drawable.ic_add, R.string.library_add);
        add.setOnClickListener(v -> {
            android.widget.PopupMenu menu = new android.widget.PopupMenu(activity, v);
            menu.getMenu().add(0, 1, 0, R.string.library_add_folder);
            menu.getMenu().add(0, 2, 1, R.string.library_import);
            menu.setOnMenuItemClickListener(item -> {
                if (item.getItemId() == 1) listener.chooseFolder(); else listener.importFile();
                return true;
            });
            menu.show();
        });
        android.widget.ImageButton reload = iconButton(R.drawable.ic_refresh, R.string.library_refresh);
        reload.setOnClickListener(v -> refresh());
        android.widget.ImageButton settings = iconButton(R.drawable.ic_settings, R.string.settings_title);
        settings.setOnClickListener(v -> listener.openSettings());
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(square, square);
        titleBar.addView(add, iconParams);
        titleBar.addView(reload, new LinearLayout.LayoutParams(iconParams));
        titleBar.addView(settings, new LinearLayout.LayoutParams(iconParams));
        body.addView(titleBar, new LinearLayout.LayoutParams(-1, -2));
        empty = new TextView(activity);
        empty.setText(R.string.library_empty);
        empty.setGravity(Gravity.CENTER);
        list = new ListView(activity);
        adapter = new LibraryAdapter(pad);
        list.setAdapter(adapter);
        JSONArray cached = read("entries");
        visible.clear();
        HashSet<String> cachedHashes = new HashSet<>();
        for (int pass = 0; pass < 2; pass++) {
            for (int i = 0; i < cached.length(); i++) {
                JSONObject entry = cached.optJSONObject(i);
                if (entry == null || entry.optBoolean("available", false) != (pass == 0)) continue;
                String hash = entry.optString("sha256", "");
                if (!hash.isEmpty() && !cachedHashes.add(hash)) continue;
                visible.add(entry);
            }
        }
        publishRows();
        list.setOnItemClickListener((parent, view, position, id) -> choose(groups.get(position), 0));
        list.setOnItemLongClickListener((parent, view, position, id) -> {
            LibraryGrouping.Group group = groups.get(position);
            new AlertDialog.Builder(activity).setItems(new String[]{activity.getString(R.string.library_info), activity.getString(R.string.library_remove)},
                    (which, item) -> choose(group, item == 0 ? 1 : 2)).show();
            return true;
        });
        android.widget.FrameLayout listArea = new android.widget.FrameLayout(activity);
        listArea.addView(list, new android.widget.FrameLayout.LayoutParams(-1, -1));
        emptyArea = new LinearLayout(activity);
        emptyArea.setOrientation(LinearLayout.VERTICAL);
        emptyArea.setGravity(Gravity.CENTER);
        emptyArea.addView(empty);
        for (int id : new int[]{R.string.library_add_folder, R.string.library_import}) {
            Button action = flatButton(activity.getString(id), id);
            LinearLayout.LayoutParams actionParams = new LinearLayout.LayoutParams(-1, square);
            actionParams.topMargin = pad / 2;
            action.setOnClickListener(v -> {
                if (id == R.string.library_add_folder) listener.chooseFolder();
                else listener.importFile();
            });
            emptyArea.addView(action, actionParams);
        }
        listArea.addView(emptyArea, new android.widget.FrameLayout.LayoutParams(-1, -1));
        body.addView(listArea, new LinearLayout.LayoutParams(-1, 0, 1));
        activity.setContentView(body);
        refresh();
    }

    private void schedulePublish() {
        if (listUpdate != null) ui.removeCallbacks(listUpdate);
        long delay = Math.max(0, 250 - (android.os.SystemClock.uptimeMillis() - lastListUpdate));
        listUpdate = () -> { if (showing) publishRows(); };
        ui.postDelayed(listUpdate, delay);
    }

    private void publishRows() {
        ArrayList<LibraryGrouping.Entry> entries = new ArrayList<>();
        java.util.ArrayList<String> oldKeys = new java.util.ArrayList<>();
        for (LibraryGrouping.Group group : groups) oldKeys.add(group.key);
        java.util.Map<String, String> oldFingerprints = new java.util.HashMap<>(renderFingerprints);
        indexed.clear();
        for (JSONObject row : visible) {
            String uri = row.optString("uri"), name = row.optString("name");
            String model = row.optString("model", "");
            String display = row.optString("display", name);
            if (model.isEmpty() && !display.equals(name) && !row.optString("sha256").isEmpty()) model = display;
            indexed.put(uri, row);
            entries.add(new LibraryGrouping.Entry(uri, model, name, row.optLong("size", -1), row.optLong("last_booted", 0)));
        }
        int first = list.getFirstVisiblePosition();
        View top = list.getChildAt(0);
        int offset = top == null ? 0 : top.getTop();
        groups.clear(); groups.addAll(LibraryGrouping.group(entries));
        renderFingerprints.clear();
        java.util.ArrayList<String> newKeys = new java.util.ArrayList<>();
        for (LibraryGrouping.Group group : groups) {
            newKeys.add(group.key);
            StringBuilder value = new StringBuilder();
            for (LibraryGrouping.Entry file : group.files) value.append(indexed.get(file.uri).toString());
            renderFingerprints.put(group.key, value.toString());
        }
        if (!oldKeys.equals(newKeys)) {
            adapter.notifyDataSetChanged();
            if (first < groups.size()) list.setSelectionFromTop(first, offset);
        } else {
            for (int i = 0; i < list.getChildCount(); i++) {
                int position = first + i;
                if (position < groups.size() && !java.util.Objects.equals(
                        oldFingerprints.get(groups.get(position).key), renderFingerprints.get(groups.get(position).key))) {
                    adapter.getView(position, list.getChildAt(i), list);
                }
            }
        }
        lastListUpdate = android.os.SystemClock.uptimeMillis();
    }

    private String size(long value) {
        return value < 0 ? activity.getString(R.string.size_unavailable)
                : String.format(java.util.Locale.US, "%.1f MiB", value / 1048576.0);
    }
    private String bootTime(long value) {
        return value == 0 ? activity.getString(R.string.library_never)
                : DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(value));
    }
    private void choose(LibraryGrouping.Group group, int action) {
        if (group.files.size() == 1) { act(group.files.get(0), action); return; }
        String[] labels = new String[group.files.size()];
        for (int i = 0; i < labels.length; i++) {
            LibraryGrouping.Entry file = group.files.get(i);
            labels[i] = file.name + " · " + size(file.size) + "\n" + bootTime(file.lastBoot);
        }
        new AlertDialog.Builder(activity).setTitle(R.string.library_files)
                .setItems(labels, (dialog, which) -> act(group.files.get(which), action))
                .setNegativeButton(R.string.cancel, null).show();
    }
    private void act(LibraryGrouping.Entry file, int action) {
        JSONObject entry = indexed.get(file.uri);
        if (entry == null) return;
        if (action == 0) select(entry); else if (action == 1) info(entry); else remove(entry);
    }

    private final class LibraryAdapter extends BaseAdapter {
        private final int pad;
        LibraryAdapter(int pad) { this.pad = pad; }
        @Override public int getCount() { return groups.size(); }
        @Override public Object getItem(int position) { return groups.get(position); }
        @Override public long getItemId(int position) { return groups.get(position).stableId(); }
        @Override public boolean hasStableIds() { return true; }
        @Override public View getView(int position, View convert, ViewGroup parent) {
            RowHolder holder;
            if (convert == null) {
                LinearLayout row = new LinearLayout(activity);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setPadding(pad, pad * 3 / 4, pad, pad * 3 / 4);
                row.setGravity(Gravity.CENTER_VERTICAL);
                ImageView image = new ImageView(activity);
                image.setBackgroundColor(android.graphics.Color.rgb(28, 28, 30));
                LinearLayout.LayoutParams imageParams = new LinearLayout.LayoutParams(pad * 5, pad * 5);
                imageParams.rightMargin = pad; row.addView(image, imageParams);
                LinearLayout labels = new LinearLayout(activity); labels.setOrientation(LinearLayout.VERTICAL);
                TextView model = new TextView(activity); model.setTextSize(18); model.setTextColor(android.graphics.Color.WHITE);
                model.setTypeface(android.graphics.Typeface.DEFAULT_BOLD); model.setSingleLine(true);
                model.setEllipsize(android.text.TextUtils.TruncateAt.END);
                TextView detail = new TextView(activity); detail.setTextSize(13);
                detail.setTextColor(android.graphics.Color.rgb(160, 160, 166));
                labels.addView(model); labels.addView(detail); row.addView(labels, new LinearLayout.LayoutParams(0, -2, 1));
                labels.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
                image.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
                holder = new RowHolder(row, image, model, detail); row.setTag(holder); convert = row;
                row.setAccessibilityDelegate(new View.AccessibilityDelegate() {
                    @Override public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfo info) {
                        super.onInitializeAccessibilityNodeInfo(host, info);
                        info.setClassName(Button.class.getName()); info.setClickable(true);
                        info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_CLICK);
                        info.addAction(new AccessibilityNodeInfo.AccessibilityAction(infoAction, activity.getString(R.string.library_info)));
                        info.addAction(new AccessibilityNodeInfo.AccessibilityAction(removeAction, activity.getString(R.string.library_remove)));
                    }
                    @Override public boolean performAccessibilityAction(View host, int action, android.os.Bundle args) {
                        LibraryGrouping.Group current = ((RowHolder) host.getTag()).group;
                        if (action == AccessibilityNodeInfo.ACTION_CLICK) { choose(current, 0); return true; }
                        if (action == infoAction) { choose(current, 1); return true; }
                        if (action == removeAction) { choose(current, 2); return true; }
                        return super.performAccessibilityAction(host, action, args);
                    }
                });
            } else holder = (RowHolder) convert.getTag();
            LibraryGrouping.Group group = groups.get(position);
            holder.group = group;
            LibraryGrouping.Entry recent = group.recent();
            JSONObject entry = indexed.get(recent.uri);
            String name = recent.model.isEmpty() ? entry.optString("display", recent.name) : recent.model;
            String chipset = entry.optString("chipset", "—");
            String booted = bootTime(recent.lastBoot);
            String summary = group.files.size() > 1
                    ? activity.getString(R.string.library_file_count, group.files.size()) + " · " + size(group.size())
                    : size(recent.size);
            holder.model.setText(name);
            holder.detail.setText(chipset + " · " + summary + "\n" + booted
                    + (entry.optBoolean("available", false) ? "" : " · " + activity.getString(R.string.library_unavailable)));
            holder.row.setContentDescription(activity.getString(R.string.library_row, name, chipset, booted));
            String path = entry.optString("thumbnail", "");
            String key = path.isEmpty() ? "" : path + ":" + new File(path).lastModified();
            holder.image.setTag(key);
            Bitmap bitmap = thumbnails.get(key);
            if (bitmap != null) { holder.image.setImageBitmap(bitmap); holder.image.setScaleType(ImageView.ScaleType.FIT_CENTER); holder.image.setAlpha(1f); }
            else {
                holder.image.setImageResource(R.drawable.ic_phone); holder.image.setScaleType(ImageView.ScaleType.CENTER); holder.image.setAlpha(0.35f);
                if (!path.isEmpty() && loadingImages.add(key)) {
                    long requestRevision = revision.get();
                    imageLoader.execute(() -> {
                        if (requestRevision != revision.get()) { loadingImages.remove(key); return; }
                        Bitmap decoded = BitmapFactory.decodeFile(path);
                        if (decoded != null) thumbnails.put(key, decoded);
                        loadingImages.remove(key);
                        if (decoded != null) ui.post(() -> {
                            if (!showing) return;
                            for (int i = 0; i < list.getChildCount(); i++) {
                                RowHolder visibleHolder = (RowHolder) list.getChildAt(i).getTag();
                                if (key.equals(visibleHolder.image.getTag())) {
                                    visibleHolder.image.setImageBitmap(decoded);
                                    visibleHolder.image.setScaleType(ImageView.ScaleType.FIT_CENTER);
                                    visibleHolder.image.setAlpha(1f);
                                }
                            }
                        });
                    });
                }
            }
            return convert;
        }
    }
    private static final class RowHolder {
        final LinearLayout row; final ImageView image; final TextView model, detail;
        LibraryGrouping.Group group;
        RowHolder(LinearLayout row, ImageView image, TextView model, TextView detail) {
            this.row = row; this.image = image; this.model = model; this.detail = detail;
        }
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

    private android.widget.ImageButton iconButton(int icon, int description) {
        android.widget.ImageButton button = new android.widget.ImageButton(activity);
        button.setImageResource(icon);
        button.setScaleType(android.widget.ImageView.ScaleType.CENTER);
        button.setStateListAnimator(null);
        button.setElevation(0);
        android.graphics.drawable.StateListDrawable background = new android.graphics.drawable.StateListDrawable();
        background.addState(new int[]{android.R.attr.state_pressed},
                new android.graphics.drawable.ColorDrawable(android.graphics.Color.rgb(46, 46, 48)));
        background.addState(new int[]{}, new android.graphics.drawable.ColorDrawable(android.graphics.Color.TRANSPARENT));
        button.setBackground(background);
        button.setContentDescription(activity.getString(description));
        return button;
    }

    private Button flatButton(String text, int description) {
        Button button = new Button(activity);
        button.setText(text);
        button.setAllCaps(false);
        button.setTextColor(android.graphics.Color.WHITE);
        button.setTextSize(18);
        button.setPadding(0, 0, 0, 0);
        button.setMinHeight(0);
        button.setMinimumHeight(0);
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setStateListAnimator(null);
        button.setElevation(0);
        android.graphics.drawable.StateListDrawable background = new android.graphics.drawable.StateListDrawable();
        android.graphics.drawable.ColorDrawable pressed = new android.graphics.drawable.ColorDrawable(android.graphics.Color.rgb(112, 112, 116));
        background.addState(new int[]{android.R.attr.state_pressed}, pressed);
        background.addState(new int[]{}, new android.graphics.drawable.ColorDrawable(android.graphics.Color.rgb(46, 46, 48)));
        button.setBackground(background);
        button.setContentDescription(activity.getString(description));
        return button;
    }

    boolean isShowing() { return showing; }

    void dismiss() {
        revision.incrementAndGet();
        if (showing) {
            showing = false;

        }
    }

    void close() { dismiss(); scanner.shutdown(); imageLoader.shutdown(); }

    private void select(JSONObject entry) {
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
                stillPresent = indexed.containsKey(value);
                if (!stillPresent) return;
                if (!available) {
                    updateEntry(value, "available", false);
                    new AlertDialog.Builder(activity).setMessage(R.string.library_unavailable)
                            .setPositiveButton(android.R.string.ok, null).show();
                    refresh();
                } else {
                    listener.boot(uri, name, size);
                }
            });
        }, "library-selection").start();
    }

    private void info(JSONObject entry) {
        String detail = activity.getString(R.string.library_info_body,
                entry.optString("display", entry.optString("name")), entry.optString("chipset", "—"),
                entry.optString("sha256", "—"), entry.optString("uri"));
        new AlertDialog.Builder(activity).setTitle(R.string.library_info).setMessage(detail)
                .setPositiveButton(android.R.string.ok, null).show();
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

    private Cursor queryChildren(Uri children, String[] columns) {
        try { return activity.getContentResolver().query(children, columns, null, null, null); }
        catch (IllegalArgumentException error) {
            return activity.getContentResolver().query(children, java.util.Arrays.copyOf(columns, 4), null, null, null);
        }
    }

    void refresh() {
        if (!showing) return;
        final long token = revision.incrementAndGet();
        emptyArea.setVisibility(visible.isEmpty() ? View.VISIBLE : View.GONE);
        empty.setText(R.string.library_loading);
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
                visible.clear(); visible.addAll(rows); schedulePublish();
                empty.setText(R.string.library_empty);
                emptyArea.setVisibility(rows.isEmpty() ? View.VISIBLE : View.GONE);
            });
        });
    }
}
