package org.msm5xxx.emulator;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;

import java.io.File;

/** Launch screen for selecting firmware before opening the emulator. */
public final class LibraryActivity extends Activity {
    private static final int PICK_FILE = 1;
    private static final int PICK_FOLDER = 2;
    private static final int SETTINGS = 3;
    private FirmwareLibraryScreen library;

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
        File external = getExternalFilesDir(null);
        if (!getIntent().getBooleanExtra("returning", false)
                && external != null && new File(external, "autorun").isFile()) {
            startActivity(new Intent(this, MainActivity.class));
            finish();
            return;
        }
        library = new FirmwareLibraryScreen(this, new FirmwareLibraryScreen.Listener() {
            @Override public void chooseFolder() { pick(true); }
            @Override public void importFile() { pick(false); }
            @Override public void openSettings() {
                startActivityForResult(new Intent(LibraryActivity.this, SettingsActivity.class), SETTINGS);
            }
            @Override public void boot(Uri uri, String name, long size) {
                library.ensureEntry(uri, name, size);
                library.dismiss();
                startActivity(new Intent(LibraryActivity.this, MainActivity.class)
                        .setData(uri).putExtra("name", name).putExtra("size", size));
            }
        });
        android.content.SharedPreferences previous = getSharedPreferences("launcher", MODE_PRIVATE);
        library.setPreviousCopy(previous.getString("copy", null), previous.getString("name", null));
    }

    @Override protected void onResume() {
        super.onResume();
        if (library != null) library.show();
    }

    @Override protected void onPause() {
        if (library != null) library.dismiss();
        super.onPause();
    }

    @Override protected void onDestroy() {
        if (library != null) library.close();
        super.onDestroy();
    }

    private void pick(boolean folder) {
        Intent intent = new Intent(folder ? Intent.ACTION_OPEN_DOCUMENT_TREE : Intent.ACTION_OPEN_DOCUMENT)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        if (!folder) intent.addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
        try { startActivityForResult(intent, folder ? PICK_FOLDER : PICK_FILE); }
        catch (ActivityNotFoundException error) { showError(R.string.error_no_picker); }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == SETTINGS) {
            String action = data == null ? null : data.getStringExtra(SettingsActivity.EXTRA_ACTION);
            if (SettingsActivity.ACTION_ADD_FOLDER.equals(action)) pick(true);
            else if (SettingsActivity.ACTION_IMPORT_FILE.equals(action)) pick(false);
            return;
        }
        if (library == null || result != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        try {
            getContentResolver().takePersistableUriPermission(uri,
                    data.getFlags() & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION));
        } catch (SecurityException ignored) { }
        if (request == PICK_FOLDER) {
            library.addFolder(uri);
        } else if (request == PICK_FILE) {
            String name = null;
            try (Cursor cursor = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
                if (cursor != null && cursor.moveToFirst() && !cursor.isNull(0)) name = cursor.getString(0);
                library.importFile(uri, SelectionLabels.displayName(this, name));
            } catch (RuntimeException error) { showError(R.string.error_unreadable_document); }
        }
    }

    private void showError(int message) {
        new AlertDialog.Builder(this).setMessage(message).setPositiveButton(android.R.string.ok, null).show();
    }
}
