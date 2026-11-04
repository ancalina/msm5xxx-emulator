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
import android.widget.ArrayAdapter;
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
    }
    private static final String PREFS = "firmware-library";
    private final int infoAction = View.generateViewId();
    private final int removeAction = View.generateViewId();
    private final Activity activity;
    private final Listener listener;
    private final SharedPreferences preferences;
    private final Object stateLock = new Object();
    private final ExecutorService scanner = Executors.newSingleThreadExecutor();
    private final ArrayList<JSONObject> visible = new ArrayList<>();
    private boolean showing;
    private ListView list;
    private TextView empty;
    private LinearLayout emptyArea;
    private ArrayAdapter<JSONObject> adapter;
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
                            .put("sha256", sha).put("display", metadata.optString("name", name))
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
        body.setPadding(pad, pad, pad, pad);
        body.setBackgroundColor(android.graphics.Color.rgb(18, 18, 18));
        LinearLayout titleBar = new LinearLayout(activity);
        titleBar.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = new TextView(activity);
        title.setText(R.string.library_title);
        title.setTextSize(20);
        title.setTextColor(android.graphics.Color.WHITE);
        titleBar.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        int square = Math.round(48 * activity.getResources().getDisplayMetrics().density);
        android.widget.ImageButton add = iconButton(android.R.drawable.ic_menu_add, R.string.library_add);
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
        android.widget.ImageButton reload = iconButton(android.R.drawable.ic_popup_sync, R.string.library_refresh);
        reload.setOnClickListener(v -> refresh());
        android.widget.ImageButton settings = iconButton(android.R.drawable.ic_menu_preferences, R.string.settings_title);
        settings.setOnClickListener(v -> showSettings());
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(square, square);
        titleBar.addView(add, iconParams);
        titleBar.addView(reload, new LinearLayout.LayoutParams(iconParams));
        titleBar.addView(settings, new LinearLayout.LayoutParams(iconParams));
        body.addView(titleBar, new LinearLayout.LayoutParams(-1, -2));
        empty = new TextView(activity);
        empty.setText(R.string.library_empty);
        empty.setGravity(Gravity.CENTER);
        list = new ListView(activity);
        adapter = new ArrayAdapter<JSONObject>(activity, android.R.layout.simple_list_item_1, visible) {
            @Override public View getView(int position, View convert, ViewGroup parent) {
                LinearLayout row = new LinearLayout(activity);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setPadding(pad / 2, pad * 3 / 4, pad / 2, pad * 3 / 4);
                row.setGravity(Gravity.CENTER_VERTICAL);
                JSONObject entry = getItem(position);
                ImageView image = new ImageView(activity);
                Bitmap thumbnail = BitmapFactory.decodeFile(entry.optString("thumbnail", ""));
                if (thumbnail != null) {
                    image.setImageBitmap(thumbnail);
                    image.setScaleType(ImageView.ScaleType.FIT_CENTER);
                    image.setAdjustViewBounds(true);
                    LinearLayout.LayoutParams imageParams = new LinearLayout.LayoutParams(pad * 5, pad * 5);
                    imageParams.rightMargin = pad;
                    row.addView(image, imageParams);
                }
                String name = entry.optString("display", entry.optString("name"));
                String chipset = entry.optString("chipset", "—");
                long last = entry.optLong("last_booted", 0);
                String booted = last == 0 ? activity.getString(R.string.library_never)
                        : DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(last));
                String spoken = activity.getString(R.string.library_row, name, chipset, booted);
                LinearLayout label = new LinearLayout(activity);
                label.setOrientation(LinearLayout.VERTICAL);
                TextView model = new TextView(activity);
                model.setText(name);
                model.setTextSize(18);
                model.setTextColor(android.graphics.Color.WHITE);
                model.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
                model.setSingleLine(true);
                model.setEllipsize(android.text.TextUtils.TruncateAt.END);
                TextView detail = new TextView(activity);
                detail.setText(chipset + " · " + (entry.optLong("size", -1) < 0 ? activity.getString(R.string.size_unavailable) :
                        String.format(java.util.Locale.US, "%.1f MiB", entry.optLong("size") / 1048576.0)) + "\n" + booted
                        + (entry.optBoolean("available", false) ? "" : " · " + activity.getString(R.string.library_unavailable))
                        + (entry.optBoolean("preview_deferred", false) ? " · " + activity.getString(R.string.library_preview_after_boot) : ""));
                detail.setTextSize(13);
                detail.setTextColor(android.graphics.Color.rgb(160, 160, 166));
                label.addView(model);
                label.addView(detail);
                row.addView(label, new LinearLayout.LayoutParams(0, -2, 1));
                if (entry.optBoolean("available", false) && entry.optString("sha256", "").isEmpty()) {
                    android.widget.ProgressBar spinner = new android.widget.ProgressBar(activity, null, android.R.attr.progressBarStyleSmall);
                    spinner.setIndeterminate(true);
                    spinner.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
                    row.addView(spinner, new LinearLayout.LayoutParams(pad * 2, pad * 2));
                    spoken += ", " + activity.getString(R.string.library_loading);
                }
                row.setContentDescription(spoken);
                label.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
                image.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
                row.setAccessibilityDelegate(new View.AccessibilityDelegate() {
                    @Override public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfo info) {
                        super.onInitializeAccessibilityNodeInfo(host, info);
                        info.setClassName(Button.class.getName());
                        info.setClickable(true);
                        info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_CLICK);
                        info.addAction(new AccessibilityNodeInfo.AccessibilityAction(infoAction, activity.getString(R.string.library_info)));
                        info.addAction(new AccessibilityNodeInfo.AccessibilityAction(removeAction, activity.getString(R.string.library_remove)));
                    }
                    @Override public boolean performAccessibilityAction(View host, int action, android.os.Bundle args) {
                        if (action == AccessibilityNodeInfo.ACTION_CLICK) {
                            select(entry);
                            return true;
                        }
                        if (action == infoAction) { info(entry); return true; }
                        if (action == removeAction) { remove(entry); return true; }
                        return super.performAccessibilityAction(host, action, args);
                    }
                });
                return row;
            }
        };
        list.setAdapter(adapter);
        JSONArray cached = read("entries");
        HashSet<String> cachedHashes = new HashSet<>();
        visible.clear();
        for (int pass = 0; pass < 2; pass++) {
            for (int i = 0; i < cached.length(); i++) {
                JSONObject entry = cached.optJSONObject(i);
                if (entry == null || entry.optBoolean("available", false) != (pass == 0)) continue;
                String sha = entry.optString("sha256", "");
                if (!sha.isEmpty() && !cachedHashes.add(sha)) continue;
                visible.add(entry);
            }
        }
        adapter.notifyDataSetChanged();
        list.setOnItemClickListener((parent, view, position, id) -> {
            select(visible.get(position));
        });
        list.setOnItemLongClickListener((parent, view, position, id) -> {
            JSONObject entry = visible.get(position);
            new AlertDialog.Builder(activity).setItems(new String[]{activity.getString(R.string.library_info), activity.getString(R.string.library_remove)},
                    (which, item) -> { if (item == 0) info(entry); else remove(entry); }).show();
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

    private void removeFolder(String folder) {
        synchronized (stateLock) {
            JSONArray folders = read("folders"), kept = new JSONArray();
            for (int i = 0; i < folders.length(); i++) if (!folder.equals(folders.optString(i))) kept.put(folders.optString(i));
            JSONArray entries = read("entries"), remaining = new JSONArray();
            String prefix = folder + "/document/";
            for (int i = 0; i < entries.length(); i++) {
                JSONObject entry = entries.optJSONObject(i);
                if (entry != null && !entry.optBoolean("imported") && entry.optString("uri").startsWith(prefix)) continue;
                remaining.put(entry);
            }
            revision.incrementAndGet();
            preferences.edit().putString("folders", kept.toString()).putString("entries", remaining.toString()).apply();
        }
        try {
            activity.getContentResolver().releasePersistableUriPermission(Uri.parse(folder),
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (RuntimeException ignored) { }
        refresh();
    }

    private void showSettings() {
        android.content.SharedPreferences session = activity.getSharedPreferences("launcher", android.content.Context.MODE_PRIVATE);
        int pad = Math.round(16 * activity.getResources().getDisplayMetrics().density);
        LinearLayout body = new LinearLayout(activity);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(pad, pad / 2, pad, 0);
        TextView foldersTitle = new TextView(activity);
        foldersTitle.setText(R.string.library_folders);
        foldersTitle.setTextSize(15);
        foldersTitle.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        body.addView(foldersTitle);
        JSONArray folders = read("folders");
        android.app.AlertDialog[] holder = new android.app.AlertDialog[1];
        if (folders.length() == 0) {
            TextView none = new TextView(activity);
            none.setText(R.string.library_no_folders);
            body.addView(none);
        }
        for (int i = 0; i < folders.length(); i++) {
            String folder = folders.optString(i);
            LinearLayout line = new LinearLayout(activity);
            line.setGravity(Gravity.CENTER_VERTICAL);
            TextView name = new TextView(activity);
            String path = Uri.decode(Uri.parse(folder).getLastPathSegment() == null ? folder : Uri.parse(folder).getLastPathSegment());
            name.setText(path.contains(":") ? path.substring(path.indexOf(':') + 1) : path);
            line.addView(name, new LinearLayout.LayoutParams(0, -2, 1));
            Button remove = new Button(activity);
            remove.setText(R.string.library_remove_folder);
            remove.setOnClickListener(v -> { removeFolder(folder); if (holder[0] != null) holder[0].dismiss(); showSettings(); });
            line.addView(remove);
            body.addView(line);
        }
        LinearLayout addLine = new LinearLayout(activity);
        Button addFolder = new Button(activity);
        addFolder.setText(R.string.library_add_folder);
        addFolder.setOnClickListener(v -> { if (holder[0] != null) holder[0].dismiss(); listener.chooseFolder(); });
        Button importFile = new Button(activity);
        importFile.setText(R.string.library_import);
        importFile.setOnClickListener(v -> { if (holder[0] != null) holder[0].dismiss(); listener.importFile(); });
        addLine.addView(addFolder, new LinearLayout.LayoutParams(0, -2, 1));
        addLine.addView(importFile, new LinearLayout.LayoutParams(0, -2, 1));
        body.addView(addLine);
        TextView sessionTitle = new TextView(activity);
        sessionTitle.setText(R.string.library_session_settings);
        sessionTitle.setTextSize(15);
        sessionTitle.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        sessionTitle.setPadding(0, pad, 0, 0);
        body.addView(sessionTitle);
        android.widget.Switch network = new android.widget.Switch(activity);
        network.setText(R.string.virtual_network);
        network.setChecked(session.getBoolean("virtual_network", false));
        android.widget.Switch hostTime = new android.widget.Switch(activity);
        hostTime.setText(R.string.network_host_time);
        hostTime.setChecked(session.getBoolean("network_host_time", true));
        TextView startLabel = new TextView(activity);
        startLabel.setText(R.string.network_start_time);
        android.widget.EditText start = new android.widget.EditText(activity);
        start.setSingleLine(true);
        start.setHint("YYYY-MM-DD HH:MM");
        start.setText(session.getString("network_start_time", ""));
        android.widget.Switch persistent = new android.widget.Switch(activity);
        persistent.setText(R.string.persistent_state);
        persistent.setChecked(session.getBoolean("persistent_state", true));
        for (View view : new View[]{network, hostTime, startLabel, start, persistent}) body.addView(view);
        android.widget.ScrollView scroll = new android.widget.ScrollView(activity);
        scroll.addView(body);
        android.app.AlertDialog dialog = new android.app.AlertDialog.Builder(activity)
                .setTitle(R.string.settings_title).setView(scroll)
                .setNegativeButton(R.string.cancel, null).setPositiveButton(R.string.save, null).create();
        holder[0] = dialog;
        dialog.setOnShowListener(ignored -> dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String value = start.getText().toString().trim();
            try {
                MainActivity.parseNetworkStartTime(value);
            } catch (IllegalArgumentException error) {
                start.setError(activity.getString(R.string.network_time_error));
                return;
            }
            session.edit().putBoolean("virtual_network", network.isChecked())
                    .putBoolean("network_host_time", hostTime.isChecked())
                    .putString("network_start_time", value)
                    .putBoolean("persistent_state", persistent.isChecked()).apply();
            dialog.dismiss();
        }));
        dialog.show();
    }

    private android.widget.ImageButton iconButton(int icon, int description) {
        android.widget.ImageButton button = new android.widget.ImageButton(activity);
        button.setImageResource(icon);
        button.setColorFilter(android.graphics.Color.WHITE);
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

    void close() { dismiss(); scanner.shutdown(); }

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
                for (JSONObject row : visible) if (value.equals(row.optString("uri"))) { stillPresent = true; break; }
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
        updateEntry(uri, "sha256", sha);
        updateEntry(uri, "last_booted", System.currentTimeMillis());
        if (uri == null || sessionPath == null || name == null) return;
        scanner.execute(() -> {
            try {
                JSONObject metadata = new JSONObject(PythonRuntime.describeLibrary(activity, new File(sessionPath), name));
                updateEntry(uri, "display", metadata.optString("name", name));
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
                            DocumentsContract.Document.COLUMN_SIZE, DocumentsContract.Document.COLUMN_MIME_TYPE};
                    try (Cursor cursor = activity.getContentResolver().query(children, columns, null, null, null)) {
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
                            if (entry != null) entry.put("available", true).put("name", displayName).put("size", fileSize);
                        }
                    }
                } catch (IOException | RuntimeException | JSONException ignored) { }
            }
            ArrayList<JSONObject> pending = new ArrayList<>();
            for (int i = 0; i < entries.length(); i++) {
                JSONObject entry = entries.optJSONObject(i);
                if (entry == null || oversizedUris.contains(entry.optString("uri"))) continue;
                try {
                    JSONObject copy = new JSONObject(entry.toString());
                    if (copy.optBoolean("imported")) {
                        String path = Uri.parse(copy.optString("uri")).getPath();
                        copy.put("available", path != null && new File(path).isFile());
                    }
                    pending.add(copy);
                } catch (JSONException ignored) { }
            }
            activity.runOnUiThread(() -> {
                if (token != revision.get() || !showing) return;
                visible.clear(); visible.addAll(pending); adapter.notifyDataSetChanged();
            });
            ArrayList<JSONObject> rows = new ArrayList<>();
            HashSet<String> hashes = new HashSet<>();
            for (int i = 0; i < entries.length(); i++) {
                if (token != revision.get()) return;
                JSONObject entry = entries.optJSONObject(i);
                if (entry == null || oversizedUris.contains(entry.optString("uri"))) continue;
                Uri uri = Uri.parse(entry.optString("uri"));
                try {
                    JSONObject metadata = null;
                    if (entry.optBoolean("imported")) {
                        File file = new File(uri.getPath());
                        entry.put("available", file.isFile() && file.canRead());
                        if (entry.optBoolean("available"))
                            metadata = new JSONObject(PythonRuntime.describeLibrary(activity, file, entry.optString("name")));
                    } else {
                        if (!entry.optBoolean("available")) { rows.add(entry); continue; }
                        metadata = describeDocument(uri, entry.optString("name"), token);
                    }
                    if (metadata == null) entry.put("preview_deferred", entry.optString("sha256", "").isEmpty());
                    else {
                        entry.remove("preview_deferred");
                        entry.put("sha256", metadata.optString("sha256"));
                        entry.put("display", metadata.optString("name", entry.optString("name")));
                        entry.put("chipset", metadata.isNull("chipset") ? "—" : metadata.optString("chipset", "—"));
                        entry.put("size", metadata.optLong("size", entry.optLong("size", -1)));
                    }
                    String sha = entry.optString("sha256", "");
                    JSONObject done = new JSONObject(entry.toString());
                    activity.runOnUiThread(() -> {
                        if (token != revision.get() || !showing) return;
                        for (int row = 0; row < visible.size(); row++)
                            if (done.optString("uri").equals(visible.get(row).optString("uri"))) { visible.set(row, done); break; }
                        adapter.notifyDataSetChanged();
                    });
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
                visible.clear(); visible.addAll(rows); adapter.notifyDataSetChanged();
                empty.setText(R.string.library_empty);
                emptyArea.setVisibility(rows.isEmpty() ? View.VISIBLE : View.GONE);
            });
        });
    }
}
