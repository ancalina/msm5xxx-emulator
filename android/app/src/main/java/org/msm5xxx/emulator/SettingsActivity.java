package org.msm5xxx.emulator;

import android.app.Activity;
import android.content.Intent;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

/** Full-screen settings for the firmware library and the next boot; changes apply immediately. */
public final class SettingsActivity extends Activity {
    static final String EXTRA_ACTION = "action";
    static final String ACTION_ADD_FOLDER = "folder";
    static final String ACTION_IMPORT_FILE = "file";
    private static final int BACKGROUND = Color.rgb(18, 18, 18);
    private static final int SECONDARY_TEXT = Color.rgb(160, 160, 166);
    private LinearLayout body;

    @Override protected void attachBaseContext(Context base) {
        String language = base.getSharedPreferences("launcher", MODE_PRIVATE).getString("ui_language", "auto");
        if (!"auto".equals(language)) {
            android.content.res.Configuration config = new android.content.res.Configuration(base.getResources().getConfiguration());
            config.setLocale(java.util.Locale.forLanguageTag(language));
            base = base.createConfigurationContext(config);
        }
        super.attachBaseContext(base);
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BACKGROUND);
        root.setFitsSystemWindows(true);
        LinearLayout bar = new LinearLayout(this);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        ImageButton back = icon(R.drawable.ic_arrow_back, getString(R.string.back));
        back.setOnClickListener(v -> finish());
        bar.addView(back, new LinearLayout.LayoutParams(dp(56), dp(56)));
        TextView title = new TextView(this);
        title.setText(R.string.settings_title);
        title.setTextSize(20);
        title.setTextColor(Color.WHITE);
        bar.addView(title);
        root.addView(bar);
        ScrollView scroll = new ScrollView(this);
        body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(body);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root);
        build();
    }

    private void build() {
        body.removeAllViews();
        header(R.string.library_folders);
        String[] folders = FirmwareLibraryScreen.folders(this);
        if (folders.length == 0) note(getString(R.string.library_no_folders));
        for (String folder : folders) {
            LinearLayout row = row(R.drawable.ic_folder, folderLabel(folder), null);
            ImageButton remove = icon(R.drawable.ic_close, getString(R.string.library_remove_folder));
            remove.setOnClickListener(v -> { FirmwareLibraryScreen.removeFolder(this, folder); build(); });
            row.addView(remove, new LinearLayout.LayoutParams(dp(48), dp(48)));
        }
        action(R.drawable.ic_add, R.string.library_add_folder, ACTION_ADD_FOLDER);
        action(R.drawable.ic_file, R.string.library_import, ACTION_IMPORT_FILE);

        SharedPreferences session = getSharedPreferences("launcher", MODE_PRIVATE);
        header(R.string.library_session_settings);
        toggle(session, "virtual_network", false, R.string.virtual_network);
        toggle(session, "network_host_time", true, R.string.network_host_time);
        startTime(session);
        toggle(session, "persistent_state", true, R.string.persistent_state);
    }

    private void header(int text) {
        TextView header = new TextView(this);
        header.setText(text);
        header.setTextSize(13);
        header.setTypeface(Typeface.DEFAULT_BOLD);
        header.setTextColor(SECONDARY_TEXT);
        header.setPadding(dp(16), dp(20), dp(16), dp(6));
        body.addView(header);
    }

    private void note(String text) {
        TextView note = new TextView(this);
        note.setText(text);
        note.setTextColor(SECONDARY_TEXT);
        note.setPadding(dp(16), dp(8), dp(16), dp(8));
        body.addView(note);
    }

    private LinearLayout row(int iconResource, String text, View.OnClickListener click) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(dp(56));
        row.setPadding(dp(16), 0, dp(8), 0);
        if (iconResource != 0) {
            ImageView image = new ImageView(this);
            image.setImageResource(iconResource);
            image.setAlpha(0.8f);
            image.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            LinearLayout.LayoutParams imageParams = new LinearLayout.LayoutParams(dp(24), dp(24));
            imageParams.rightMargin = dp(16);
            row.addView(image, imageParams);
        }
        TextView label = new TextView(this);
        label.setText(text);
        label.setTextSize(16);
        label.setTextColor(Color.WHITE);
        row.addView(label, new LinearLayout.LayoutParams(0, -2, 1));
        if (click != null) {
            row.setOnClickListener(click);
            row.setBackground(pressable());
        }
        body.addView(row, new LinearLayout.LayoutParams(-1, -2));
        return row;
    }

    private void action(int iconResource, int text, String action) {
        row(iconResource, getString(text), v -> {
            setResult(RESULT_OK, new Intent().putExtra(EXTRA_ACTION, action));
            finish();
        });
    }

    private void toggle(SharedPreferences session, String key, boolean fallback, int text) {
        Switch toggle = new Switch(this);
        toggle.setText(text);
        toggle.setTextSize(16);
        toggle.setTextColor(Color.WHITE);
        toggle.setChecked(session.getBoolean(key, fallback));
        toggle.setMinHeight(dp(56));
        toggle.setPadding(dp(16), 0, dp(16), 0);
        toggle.setBackground(null);
        toggle.setOnCheckedChangeListener((view, checked) -> session.edit().putBoolean(key, checked).apply());
        body.addView(toggle, new LinearLayout.LayoutParams(-1, -2));
    }

    private void startTime(SharedPreferences session) {
        body.addView(NetworkTimePicker.row(this, session.getString("network_start_time", ""),
                value -> session.edit().putString("network_start_time", value).apply()));
    }

    private ImageButton icon(int resource, String description) {
        ImageButton button = new ImageButton(this);
        button.setImageResource(resource);
        button.setScaleType(ImageView.ScaleType.CENTER);
        button.setBackground(pressable());
        button.setStateListAnimator(null);
        button.setContentDescription(description);
        return button;
    }

    private android.graphics.drawable.Drawable pressable() {
        android.graphics.drawable.StateListDrawable background = new android.graphics.drawable.StateListDrawable();
        background.addState(new int[]{android.R.attr.state_pressed},
                new android.graphics.drawable.ColorDrawable(Color.rgb(46, 46, 48)));
        background.addState(new int[]{}, new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT));
        return background;
    }

    private String folderLabel(String folder) {
        String segment = Uri.parse(folder).getLastPathSegment();
        String path = Uri.decode(segment == null ? folder : segment);
        return path.contains(":") ? path.substring(path.indexOf(':') + 1) : path;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
