package org.msm5xxx.emulator;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.media.AudioAttributes;
import android.media.AudioFormat;
import android.media.AudioTrack;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class MainActivity extends Activity {
    private static final int PICK_FIRMWARE = 1;
    private static final int MORE_CHOOSE = 1;
    private static final int MORE_SETTINGS = 2;
    private static final int MORE_RUN_STOP = 3;
    private static final String PREFS = "launcher";
    private static final String KEY_URI = "uri";
    private static final String KEY_NAME = "name";
    private static final String KEY_SIZE = "size";
    private static final String KEY_TOKEN = "token";
    private static final String KEY_COPY = "copy";
    private static final String KEY_STATE = "state";
    private static final String KEY_ERROR = "error";
    private static final String KEY_DETECTION = "detection";
    private static final String KEY_DETECTION_TOKEN = "detection_token";
    private static final String KEY_PROFILE = "profile";
    private static final String KEY_REJECT = "reject";
    private static final String KEY_PERSISTENT_STATE = "persistent_state";
    private static final String KEY_EXPERIMENTAL_REX = "experimental_rex";
    private static final String KEYMAP_PREFS = "manual-keymaps";
    private static final String STATE_NONE = "none";
    private static final String STATE_COPYING = "copying";
    private static final String STATE_READY = "ready";
    private static final String STATE_ERROR = "error";
    private static final String DETECTION_NONE = "none";
    private static final String DETECTION_RUNNING = "running";
    private static final String DETECTION_ACCEPTED = "accepted";
    private static final String DETECTION_REJECTED = "rejected";
    private static final String DETECTION_ERROR = "error";
    private static final long FRAME_UPDATE_INTERVAL_NS = 100_000_000L;
    private static final long METRIC_UPDATE_INTERVAL_NS = 1_000_000_000L;
    private static final KeySpec[] KEY_LAYOUT = {
            new KeySpec(R.string.key_menu, 0, 0, 0),
            new KeySpec(R.string.key_up, 1, 0, 1),
            new KeySpec(R.string.key_cancel, 2, 0, 2),
            new KeySpec(R.string.key_left, 4, 1, 0),
            new KeySpec(R.string.key_ok, 5, 1, 1),
            new KeySpec(R.string.key_right, 6, 1, 2),
            new KeySpec(R.string.key_call, 3, 2, 0),
            new KeySpec(R.string.key_down, 9, 2, 1),
            new KeySpec(R.string.key_end, 7, 2, 2),
            new KeySpec(R.string.key_1, 11, 3, 0),
            new KeySpec(R.string.key_2, 12, 3, 1),
            new KeySpec(R.string.key_3, 13, 3, 2),
            new KeySpec(R.string.key_4, 14, 4, 0),
            new KeySpec(R.string.key_5, 15, 4, 1),
            new KeySpec(R.string.key_6, 16, 4, 2),
            new KeySpec(R.string.key_7, 17, 5, 0),
            new KeySpec(R.string.key_8, 18, 5, 1),
            new KeySpec(R.string.key_9, 19, 5, 2),
            new KeySpec(R.string.key_star, 20, 6, 0),
            new KeySpec(R.string.key_0, 21, 6, 1),
            new KeySpec(R.string.key_hash, 22, 6, 2),
            new KeySpec(R.string.key_volume_up, 10, -1, -1),
            new KeySpec(R.string.key_volume_down, 8, -1, -1),
    };

    private static String activeDetectionToken;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService inputExecutor =
            Executors.newSingleThreadExecutor();
    private final AtomicReference<FrameUpdate> pendingFrame =
            new AtomicReference<>();
    private final AtomicBoolean framePosted = new AtomicBoolean();
    private final InputTiming inputTiming = new InputTiming();
    private TextView profileView;
    private TextView sessionView;
    private TextView pcView;
    private TextView runView;
    private TextView lcdView;
    private TextView frameMetricView;
    private TextView inputView;
    private TextView rejectView;
    private TextView jniView;
    private TextView ackView;
    private FrameView frameView;
    private Button moreButton;
    private final Button[] keyButtons = new Button[23];
    private final View[] keyTargets = new View[23];
    private boolean backendProbeStarted;
    private boolean qemuReady;
    private boolean detectorRuntimeReady;
    private boolean activityResumed;
    private boolean sessionStarting;
    private boolean canStartSession;
    private int heldKeyBit = -1;
    private Integer heldEventCode;
    private int mappingTapBit = -1;
    private String autoStartToken;
    private String lastErrorMessage;
    private volatile BackendBridge.Session session;
    private volatile int sessionGeneration;

    private final Runnable refreshWhileCopying = new Runnable() {
        @Override
        public void run() {
            refreshSelection();
            SharedPreferences preferences = preferences();
            if (STATE_COPYING.equals(preferences.getString(KEY_STATE, STATE_NONE))
                    || DETECTION_RUNNING.equals(preferences.getString(
                    KEY_DETECTION, DETECTION_NONE))) {
                handler.postDelayed(this, 250);
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildContent());
        refreshSelection();
        probeBackend();
        if (savedInstanceState == null) {
            frameView.post(this::chooseFirmware);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        activityResumed = true;
        handler.removeCallbacks(refreshWhileCopying);
        refreshWhileCopying.run();
    }

    @Override
    protected void onPause() {
        activityResumed = false;
        handler.removeCallbacks(refreshWhileCopying);
        releaseHeldKey(false);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        stopSession(false);
        inputExecutor.shutdown();
        super.onDestroy();
    }

    private View buildContent() {
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setBackgroundColor(Color.rgb(18, 18, 18));
        int padding = dp(2);
        content.setPadding(padding, padding, padding, padding);

        frameView = new FrameView(this);
        frameView.setBackgroundColor(Color.BLACK);
        content.addView(frameView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        frameView.setMinimumHeight(dp(120));

        GridLayout keypad = new GridLayout(this);
        keypad.setColumnCount(3);
        keypad.setRowCount(7);
        LinearLayout side = new LinearLayout(this);
        side.setOrientation(LinearLayout.VERTICAL);
        for (KeySpec key : KEY_LAYOUT) {
            Button button = new Button(this);
            button.setText(key.labelResource);
            button.setTextSize(11);
            button.setTextColor(Color.WHITE);
            button.setMinHeight(0);
            button.setMinimumHeight(0);
            button.setMinWidth(0);
            button.setMinimumWidth(0);
            button.setPadding(0, 0, 0, 0);
            button.setBackground(handsetButtonBackground());
            button.setEnabled(false);
            button.setClickable(false);
            button.setFocusable(false);
            button.setImportantForAccessibility(
                    View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            FrameLayout target = handsetTarget(button, key.bit);
            boolean volume = key.bit == 8 || key.bit == 10;
            if (volume) {
                LinearLayout.LayoutParams volumeParams =
                        new LinearLayout.LayoutParams(
                                LinearLayout.LayoutParams.MATCH_PARENT, dp(40));
                side.addView(target, volumeParams);
            } else {
                GridLayout.LayoutParams keyParams = gridItem(
                        key.row, key.column, 1, 1, 1f);
                keypad.addView(target, keyParams);
            }
            keyButtons[key.bit] = button;
            keyTargets[key.bit] = target;
        }

        LinearLayout telemetry = new LinearLayout(this);
        telemetry.setOrientation(LinearLayout.VERTICAL);
        profileView = statusLine("");
        pcView = metricCell(R.string.metric_pc_empty);
        runView = metricCell(R.string.metric_run_empty);
        lcdView = metricCell(R.string.metric_lcd_empty);
        frameMetricView = metricCell(R.string.metric_frame_empty);
        inputView = metricCell(R.string.metric_input_empty);
        rejectView = metricCell(R.string.metric_reject_empty);
        jniView = metricCell(R.string.metric_jni_empty);
        ackView = metricCell(R.string.metric_ack_empty);
        sessionView = statusLine("");
        sessionView.setTextColor(Color.rgb(176, 176, 176));
        for (TextView line : new TextView[]{
                profileView, pcView, runView, lcdView, frameMetricView,
                inputView, rejectView, jniView, ackView, sessionView,
        }) {
            telemetry.addView(line, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        }
        side.addView(telemetry, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));

        moreButton = compactButton(R.string.more, view -> showMoreMenu());
        moreButton.setTextSize(20);
        moreButton.setContentDescription(getString(R.string.more_actions));
        side.addView(moreButton, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(40)));

        LinearLayout controls = new LinearLayout(this);
        controls.setOrientation(LinearLayout.HORIZONTAL);
        controls.addView(side, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.MATCH_PARENT, 1.5f));
        controls.addView(keypad, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.MATCH_PARENT, 3));
        content.addView(controls, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(280)));
        return content;
    }

    private void probeBackend() {
        if (backendProbeStarted) {
            return;
        }
        backendProbeStarted = true;
        Context application = getApplicationContext();
        new Thread(() -> {
            BackendBridge.Probe qemu = BackendBridge.probeQemu(application);
            BackendBridge.Probe detector = qemu.available
                    ? BackendBridge.probeDetectorRuntime(application) : null;
            handler.post(() -> {
                qemuReady = qemu.available;
                detectorRuntimeReady = detector != null && detector.available;
                if (!qemuReady) {
                    showError(getString(R.string.error_backend_failed));
                } else if (!detectorRuntimeReady) {
                    showError(getString(
                            R.string.error_detector_runtime_failed));
                }
                refreshSelection();
            });
        }, "qemu-probe").start();
    }

    @SuppressWarnings("deprecation")
    private void chooseFirmware() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/octet-stream")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                        | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        try {
            startActivityForResult(intent, PICK_FIRMWARE);
        } catch (ActivityNotFoundException error) {
            showError(getString(R.string.error_no_picker));
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != PICK_FIRMWARE || resultCode != RESULT_OK
                || data == null || data.getData() == null) {
            return;
        }
        Uri uri = data.getData();
        try {
            int grantFlags = data.getFlags()
                    & (Intent.FLAG_GRANT_READ_URI_PERMISSION
                    | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            getContentResolver().takePersistableUriPermission(uri, grantFlags);
        } catch (SecurityException ignored) {
            // The private copy remains usable when a provider declines persistence.
        }
        try {
            Selection selection = inspect(uri);
            preparePrivateCopy(selection);
        } catch (IOException | SecurityException error) {
            showError(getString(R.string.error_unreadable_document));
        }
    }

    private Selection inspect(Uri uri) throws IOException {
        if (!"content".equals(uri.getScheme())
                || DocumentsContract.Document.MIME_TYPE_DIR.equals(
                getContentResolver().getType(uri))) {
            throw new IOException("unsupported document");
        }
        String name = null;
        long size = -1;
        try (Cursor cursor = getContentResolver().query(uri,
                new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE},
                null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int nameColumn = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                int sizeColumn = cursor.getColumnIndex(OpenableColumns.SIZE);
                if (nameColumn >= 0 && !cursor.isNull(nameColumn)) {
                    name = cursor.getString(nameColumn);
                }
                if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) {
                    size = cursor.getLong(sizeColumn);
                }
            }
        }
        try (InputStream ignored = getContentResolver().openInputStream(uri)) {
            if (ignored == null) {
                throw new IOException("document cannot be opened");
            }
        }
        return new Selection(uri, SelectionLabels.displayName(this, name), size);
    }

    private void preparePrivateCopy(Selection selection) {
        if (session != null) {
            stopSession(true);
        }
        clearError();
        SharedPreferences preferences = preferences();
        String token = UUID.randomUUID().toString();
        autoStartToken = token;
        String previousCopy = preferences.getString(KEY_COPY, null);
        preferences.edit()
                .putString(KEY_URI, selection.uri.toString())
                .putString(KEY_NAME, selection.name)
                .putLong(KEY_SIZE, selection.size)
                .putString(KEY_TOKEN, token)
                .remove(KEY_COPY)
                .putString(KEY_STATE, STATE_COPYING)
                .remove(KEY_ERROR)
                .putString(KEY_DETECTION, DETECTION_NONE)
                .remove(KEY_DETECTION_TOKEN)
                .remove(KEY_PROFILE)
                .remove(KEY_REJECT)
                .commit();
        refreshSelection();

        Context application = getApplicationContext();
        new Thread(() -> copyFirmware(application, selection.uri, token,
                previousCopy), "firmware-copy").start();
    }

    private static void copyFirmware(Context context, Uri uri, String token,
                                     String previousCopy) {
        File directory = new File(new File(context.getNoBackupFilesDir(), "session"),
                token);
        File partial = new File(directory, "firmware.part");
        File complete = new File(directory, "firmware.bin");
        String failure = null;
        try {
            if (!directory.mkdirs()) {
                throw new IOException("private session directory was not created");
            }
            try (InputStream input = context.getContentResolver().openInputStream(uri);
                 FileOutputStream output = new FileOutputStream(partial)) {
                if (input == null) {
                    throw new IOException("document cannot be opened");
                }
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    output.write(buffer, 0, read);
                }
                output.getFD().sync();
            }
            if (!partial.renameTo(complete) || !complete.setReadOnly()) {
                throw new IOException("private firmware copy was not finalized");
            }
        } catch (IOException | SecurityException error) {
            failure = "copy-failed";
        }

        SharedPreferences preferences = context.getSharedPreferences(PREFS,
                Context.MODE_PRIVATE);
        if (!token.equals(preferences.getString(KEY_TOKEN, null))) {
            deleteSessionCopy(context, complete.getPath());
            deleteSessionCopy(context, partial.getPath());
            return;
        }
        if (failure == null) {
            preferences.edit()
                    .putString(KEY_COPY, complete.getPath())
                    .putString(KEY_STATE, STATE_READY)
                    .remove(KEY_ERROR)
                    .commit();
            deleteSessionCopy(context, previousCopy);
        } else {
            preferences.edit()
                    .remove(KEY_COPY)
                    .putString(KEY_STATE, STATE_ERROR)
                    .putString(KEY_ERROR, failure)
                    .commit();
            deleteSessionCopy(context, partial.getPath());
            deleteSessionCopy(context, complete.getPath());
        }
    }

    private static void deleteSessionCopy(Context context, String path) {
        if (path == null) {
            return;
        }
        try {
            File sessionRoot = new File(context.getNoBackupFilesDir(), "session")
                    .getCanonicalFile();
            File file = new File(path).getCanonicalFile();
            File parent = file.getParentFile();
            if (parent != null && parent.getParentFile() != null
                    && parent.getParentFile().equals(sessionRoot)
                    && (file.getName().equals("firmware.bin")
                    || file.getName().equals("firmware.part"))) {
                file.delete();
                parent.delete();
            }
        } catch (IOException ignored) {
            // A stale private copy is safer than deleting an unresolved path.
        }
    }

    private void refreshSelection() {
        SharedPreferences preferences = preferences();
        String state = preferences.getString(KEY_STATE, STATE_NONE);
        profileView.setText("");
        if (STATE_COPYING.equals(state)) {
            setIdleStatus(R.string.copying_firmware);
        } else if (STATE_READY.equals(state)) {
            String path = preferences.getString(KEY_COPY, null);
            if (path != null && privateCopyIsReadable(path)) {
                String token = preferences.getString(KEY_TOKEN, null);
                beginDetectionIfReady(path, token);
                showDetectionStatus(preferences, token);
            } else {
                setIdleStatus(R.string.session_failed);
                showError(getString(R.string.error_private_copy_missing));
            }
        } else if (STATE_ERROR.equals(state)) {
            setIdleStatus(R.string.session_failed);
            showError(getString(R.string.error_preparation_failed));
        } else {
            clearIdleStatus();
        }
        String token = preferences.getString(KEY_TOKEN, null);
        boolean accepted = token != null
                && token.equals(preferences.getString(KEY_DETECTION_TOKEN, null))
                && DETECTION_ACCEPTED.equals(preferences.getString(
                KEY_DETECTION, DETECTION_NONE))
                && preferences.getString(KEY_PROFILE, null) != null;
        String path = preferences.getString(KEY_COPY, null);
        boolean canStart = session == null && !sessionStarting && qemuReady
                && detectorRuntimeReady && accepted
                && STATE_READY.equals(state) && path != null
                && privateCopyIsReadable(path);
        updateSessionControls(canStart);
        if (canStart && activityResumed && token.equals(autoStartToken)) {
            autoStartToken = null;
            handler.post(this::startSession);
        }
    }

    private void beginDetectionIfReady(String path, String token) {
        if (!qemuReady || !detectorRuntimeReady || token == null) {
            return;
        }
        SharedPreferences preferences = preferences();
        String resultToken = preferences.getString(KEY_DETECTION_TOKEN, null);
        String state = preferences.getString(KEY_DETECTION, DETECTION_NONE);
        if (token.equals(resultToken) && (DETECTION_ACCEPTED.equals(state)
                || DETECTION_REJECTED.equals(state)
                || DETECTION_ERROR.equals(state))) {
            return;
        }
        if (!claimDetection(token)) {
            return;
        }
        preferences.edit()
                .putString(KEY_DETECTION, DETECTION_RUNNING)
                .putString(KEY_DETECTION_TOKEN, token)
                .remove(KEY_PROFILE)
                .remove(KEY_REJECT)
                .commit();
        Context application = getApplicationContext();
        new Thread(() -> {
            BackendBridge.Detection detection = BackendBridge.detect(
                    application, new File(path));
            SharedPreferences current = application.getSharedPreferences(
                    PREFS, Context.MODE_PRIVATE);
            if (token.equals(current.getString(KEY_TOKEN, null))) {
                SharedPreferences.Editor editor = current.edit();
                if (!detection.valid) {
                    editor.putString(KEY_DETECTION, DETECTION_ERROR)
                            .putString(KEY_REJECT, detection.message)
                            .remove(KEY_PROFILE);
                } else {
                    editor.putString(KEY_DETECTION, detection.accepted
                                    ? DETECTION_ACCEPTED : DETECTION_REJECTED)
                            .putString(KEY_PROFILE, detection.profileJson);
                    if (detection.rejectReason == null) {
                        editor.remove(KEY_REJECT);
                    } else {
                        editor.putString(KEY_REJECT, detection.rejectReason);
                    }
                }
                editor.commit();
            }
            releaseDetection(token);
            handler.post(this::refreshSelection);
        }, "firmware-detector").start();
    }

    private void showDetectionStatus(SharedPreferences preferences, String token) {
        String resultToken = preferences.getString(KEY_DETECTION_TOKEN, null);
        String detection = token != null && token.equals(resultToken)
                ? preferences.getString(KEY_DETECTION, DETECTION_NONE)
                : DETECTION_NONE;
        if (DETECTION_RUNNING.equals(detection)) {
            setIdleStatus(R.string.detecting_firmware);
        } else if (DETECTION_ACCEPTED.equals(detection)) {
            showProfile(preferences.getString(KEY_PROFILE, null));
            clearIdleStatus();
        } else if (DETECTION_REJECTED.equals(detection)) {
            setIdleStatus(R.string.session_failed);
            String reason = preferences.getString(KEY_REJECT, null);
            showError(reason == null ? getString(R.string.error_unsupported_firmware)
                    : SelectionLabels.displayName(this, reason));
        } else if (DETECTION_ERROR.equals(detection)) {
            setIdleStatus(R.string.session_failed);
            showError(getString(R.string.error_detection_failed));
        } else if (qemuReady && detectorRuntimeReady) {
            clearIdleStatus();
        } else {
            clearIdleStatus();
        }
    }

    private void startSession() {
        if (session != null) {
            return;
        }
        SharedPreferences preferences = preferences();
        String token = preferences.getString(KEY_TOKEN, null);
        String path = preferences.getString(KEY_COPY, null);
        String profile = preferences.getString(KEY_PROFILE, null);
        if (!qemuReady || !detectorRuntimeReady || token == null || path == null
                || profile == null || !token.equals(preferences.getString(
                KEY_DETECTION_TOKEN, null))
                || !DETECTION_ACCEPTED.equals(preferences.getString(
                KEY_DETECTION, DETECTION_NONE))
                || !privateCopyIsReadable(path)) {
            showError(getString(R.string.error_not_ready));
            refreshSelection();
            return;
        }
        boolean persistentState = preferences.getBoolean(
                KEY_PERSISTENT_STATE, true);
        boolean experimentalRex = preferences.getBoolean(
                KEY_EXPERIMENTAL_REX, false);
        int generation = ++sessionGeneration;
        sessionStarting = true;
        inputTiming.reset();
        clearError();
        updateSessionControls(false);
        updateKeypad(null);
        resetMetrics();
        sessionView.setText(R.string.starting_session);
        Context application = getApplicationContext();
        new Thread(() -> runSession(application, new File(path), profile,
                persistentState, experimentalRex, generation),
                "qemu-session").start();
    }

    private void runSession(Context context, File firmware, String profile,
                            boolean persistentState, boolean experimentalRex,
                            int generation) {
        BackendBridge.Session opened = null;
        FramePacket latestFrame = null;
        PcmAudioSink audioSink = new PcmAudioSink();
        boolean failed = false;
        try {
            opened = BackendBridge.open(context, firmware, profile,
                    persistentState, experimentalRex);
            if (generation != sessionGeneration) {
                return;
            }
            session = opened;
            updateSessionKeepScreenOn(true, generation);
            sessionStarting = false;
            BackendBridge.Session active = opened;
            handler.post(() -> {
                if (generation == sessionGeneration && session != null) {
                    sessionView.setText("");
                    updateKeypad(active);
                    updateSessionControls(false);
                }
            });
            long nextFrameUpdate = 0;
            long nextMetricUpdate = 0;
            long nextBackendUpdate = 0;
            long publishedInputEvents = -1;
            long publishedRejections = -1;
            while (generation == sessionGeneration) {
                if (!audioSink.disabled) {
                    try {
                        audioSink.offer(opened.audio());
                    } catch (IOException | RuntimeException audioError) {
                        audioSink.disable();
                    }
                }
                long now = SystemClock.elapsedRealtimeNanos();
                if (now < nextBackendUpdate) {
                    Thread.sleep(20);
                    continue;
                }
                FramePacket frame = FrameView.decodePacket(opened.frame());
                if (frame != null) {
                    if (latestFrame != null) {
                        latestFrame.recycle();
                    }
                    latestFrame = frame;
                }
                BackendBridge.Status status = opened.status();
                long ackNow = SystemClock.elapsedRealtimeNanos();
                InputTimingSnapshot timing = inputTiming.observe(
                        status.inputHostEvents, ackNow);
                now = SystemClock.elapsedRealtimeNanos();
                boolean inputChanged = status.inputHostEvents
                        != publishedInputEvents
                        || status.inputRejections != publishedRejections;
                boolean frameDue = latestFrame != null
                        && now >= nextFrameUpdate;
                boolean metricDue = now >= nextMetricUpdate;
                if (frameDue || inputChanged || metricDue) {
                    enqueueFrame(new FrameUpdate(generation, latestFrame,
                            status, timing));
                    latestFrame = null;
                    publishedInputEvents = status.inputHostEvents;
                    publishedRejections = status.inputRejections;
                    nextFrameUpdate = now + FRAME_UPDATE_INTERVAL_NS;
                    nextMetricUpdate = now + METRIC_UPDATE_INTERVAL_NS;
                }
                if (!status.processRunning) {
                    throw new IOException("QEMU process exited");
                }
                nextBackendUpdate = now + FRAME_UPDATE_INTERVAL_NS;
                Thread.sleep(20);
            }
        } catch (IOException | RuntimeException | LinkageError error) {
            failed = true;
            if (generation == sessionGeneration) {
                session = null;
                sessionStarting = false;
                updateSessionKeepScreenOn(false, generation);
                handler.post(() -> {
                    if (generation == sessionGeneration) {
                        updateKeypad(null);
                        sessionView.setText(R.string.session_failed);
                        showError(getString(R.string.error_session_failed));
                        refreshSelection();
                    }
                });
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        } finally {
            updateSessionKeepScreenOn(false, generation);
            audioSink.close();
            if (latestFrame != null) {
                latestFrame.recycle();
            }
            if (opened != null && (failed || generation != sessionGeneration)) {
                closeQuietly(opened);
            }
        }
    }

    private void enqueueFrame(FrameUpdate update) {
        FrameUpdate replaced = pendingFrame.getAndSet(update);
        if (replaced != null) {
            replaced.recycle();
        }
        if (framePosted.compareAndSet(false, true)) {
            handler.post(this::drainFrame);
        }
    }

    private void drainFrame() {
        FrameUpdate update = pendingFrame.getAndSet(null);
        if (update != null) {
            showSessionFrame(update.generation, update.frame, update.status,
                    update.timing);
        }
        framePosted.set(false);
        if (pendingFrame.get() != null
                && framePosted.compareAndSet(false, true)) {
            handler.post(this::drainFrame);
        }
    }

    private void showSessionFrame(int generation, FramePacket frame,
                                  BackendBridge.Status status,
                                  InputTimingSnapshot timing) {
        if (generation != sessionGeneration || session == null) {
            if (frame != null) {
                frame.recycle();
            }
            return;
        }
        frameView.setFrame(frame);
        setTextIfChanged(pcView, getString(R.string.metric_pc, status.pc));
        setTextIfChanged(runView, getString(
                R.string.metric_run, status.instructions));
        setTextIfChanged(lcdView, getString(
                R.string.metric_lcd, status.lcdWrites));
        setTextIfChanged(frameMetricView, getString(
                R.string.metric_frame, status.frameSequence));
        setTextIfChanged(inputView, getString(
                R.string.metric_input, status.inputHostEvents));
        setTextIfChanged(rejectView, getString(
                R.string.metric_reject, status.inputRejections));
        setTextIfChanged(jniView, getString(
                R.string.metric_jni, latency(timing.dispatchMillis)));
        setTextIfChanged(ackView, getString(
                R.string.metric_ack, latency(timing.ackMillis)));
        if (!status.processRunning) {
            showError(getString(R.string.error_process_exited));
        }
    }

    private boolean onKeyTouch(int bit, MotionEvent event) {
        BackendBridge.Session current = session;
        int action = event.getActionMasked();
        if (current == null) {
            return true;
        }
        if (action == MotionEvent.ACTION_DOWN) {
            if (heldKeyBit >= 0) {
                return true;
            }
            Integer mapped = manualKeyEvent(current.identity(), bit);
            if (mapped == null && !current.supportsKey(bit)) {
                mappingTapBit = bit;
                return true;
            }
            mappingTapBit = -1;
            heldKeyBit = bit;
            heldEventCode = mapped;
            keyButtons[bit].setPressed(true);
            sendSessionKey(current, bit, mapped, true, true);
            return true;
        }
        if (action == MotionEvent.ACTION_UP
                || action == MotionEvent.ACTION_CANCEL) {
            if (heldKeyBit == bit) {
                releaseHeldKey(true);
            } else if (mappingTapBit == bit
                    && action == MotionEvent.ACTION_UP) {
                mappingTapBit = -1;
                showKeyMapping(bit);
            } else if (mappingTapBit == bit) {
                mappingTapBit = -1;
            }
            return true;
        }
        return true;
    }

    private void sendSessionKey(BackendBridge.Session target, int bit,
                                Integer eventCode, boolean pressed,
                                boolean reportFailure) {
        InputProbe probe = inputTiming.begin(
                SystemClock.elapsedRealtimeNanos());
        inputExecutor.execute(() -> {
            try {
                target.setKey(bit, eventCode, pressed);
                inputTiming.dispatched(probe,
                        SystemClock.elapsedRealtimeNanos());
            } catch (IOException | RuntimeException error) {
                inputTiming.failed(probe);
                if (reportFailure) {
                    handler.post(() -> {
                        if (session == target) {
                            showError(getString(R.string.error_input_failed));
                        }
                    });
                }
            }
        });
    }

    private void releaseHeldKey(boolean reportFailure) {
        int bit = heldKeyBit;
        Integer eventCode = heldEventCode;
        BackendBridge.Session current = session;
        heldKeyBit = -1;
        heldEventCode = null;
        mappingTapBit = -1;
        if (bit >= 0 && bit < keyButtons.length && keyButtons[bit] != null) {
            keyButtons[bit].setPressed(false);
        }
        if (bit < 0 || current == null) {
            return;
        }
        sendSessionKey(current, bit, eventCode, false, reportFailure);
    }

    private void showKeyMapping(int bit) {
        BackendBridge.Session current = session;
        if (current == null || heldKeyBit >= 0) {
            return;
        }
        String identity = current.identity();
        Integer saved = manualKeyEvent(identity, bit);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(20);
        body.setPadding(padding, 0, padding, 0);
        TextView prompt = text(getString(R.string.mapping_prompt), 14);
        EditText value = new EditText(this);
        value.setSingleLine(true);
        value.setText(saved == null ? ""
                : getString(R.string.mapping_value, saved));
        body.addView(prompt, matchWidth());
        body.addView(value, matchWidth());
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(getString(R.string.mapping_title,
                        keyButtons[bit].getText()))
                .setView(body)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.save, null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(
                AlertDialog.BUTTON_POSITIVE).setOnClickListener(button -> {
            String requested = value.getText().toString();
            if (requested.trim().isEmpty()) {
                saveManualKeyEvent(identity, bit, null);
                updateKeypad(current);
                dialog.dismiss();
                return;
            }
            final int eventCode;
            try {
                eventCode = parseManualKeyEvent(requested);
            } catch (IllegalArgumentException error) {
                showError(getString(R.string.mapping_invalid));
                return;
            }
            button.setEnabled(false);
            inputExecutor.execute(() -> {
                boolean accepted = false;
                try {
                    accepted = current.canSetKey(bit, eventCode);
                } catch (IOException | RuntimeException ignoredError) {
                    // The same concise rejection covers an unavailable session.
                }
                boolean mappingAccepted = accepted;
                handler.post(() -> {
                    if (session != current || !identity.equals(
                            current.identity())) {
                        dialog.dismiss();
                        return;
                    }
                    button.setEnabled(true);
                    if (!mappingAccepted) {
                        showError(getString(R.string.mapping_rejected));
                        return;
                    }
                    saveManualKeyEvent(identity, bit, eventCode);
                    updateKeypad(current);
                    dialog.dismiss();
                });
            });
        }));
        dialog.show();
    }

    private Integer manualKeyEvent(String identity, int bit) {
        SharedPreferences mappings = getSharedPreferences(
                KEYMAP_PREFS, MODE_PRIVATE);
        String key = mappingKey(identity, bit);
        if (!mappings.contains(key)) {
            return null;
        }
        int value = mappings.getInt(key, -1);
        return value >= 0 && value <= 0xff ? value : null;
    }

    private void saveManualKeyEvent(String identity, int bit,
                                    Integer eventCode) {
        SharedPreferences.Editor editor = getSharedPreferences(
                KEYMAP_PREFS, MODE_PRIVATE).edit();
        String key = mappingKey(identity, bit);
        if (eventCode == null) {
            editor.remove(key);
        } else {
            editor.putInt(key, eventCode);
        }
        editor.apply();
    }

    private static String mappingKey(String identity, int bit) {
        return identity + ":" + bit;
    }

    static int parseManualKeyEvent(String source) {
        String value = source.trim();
        if (value.isEmpty()) {
            throw new IllegalArgumentException("empty input event");
        }
        String lower = value.toLowerCase(java.util.Locale.ROOT);
        boolean logHex = value.length() > 1 && value.startsWith("0")
                && !lower.startsWith("0x") && !lower.startsWith("0o")
                && !lower.startsWith("0b");
        int sign = 1;
        String digits = value;
        int radix = logHex ? 16 : 10;
        if (!logHex && (digits.startsWith("+") || digits.startsWith("-"))) {
            sign = digits.charAt(0) == '-' ? -1 : 1;
            digits = digits.substring(1);
        }
        String digitLower = digits.toLowerCase(java.util.Locale.ROOT);
        if (!logHex && digitLower.startsWith("0x")) {
            radix = 16;
            digits = digits.substring(2);
        } else if (!logHex && digitLower.startsWith("0o")) {
            radix = 8;
            digits = digits.substring(2);
        } else if (!logHex && digitLower.startsWith("0b")) {
            radix = 2;
            digits = digits.substring(2);
        } else if (!logHex && digits.length() > 1
                && digits.startsWith("0")) {
            String zeros = digits.replace("_", "");
            if (!zeros.matches("0+")) {
                throw new IllegalArgumentException("invalid leading zero");
            }
        }
        String digitPattern = radix == 16 ? "[0-9a-fA-F]"
                : radix == 8 ? "[0-7]" : radix == 2 ? "[01]" : "[0-9]";
        if (!digits.matches(digitPattern + "(?:_?" + digitPattern + ")*")) {
            throw new IllegalArgumentException("invalid input event");
        }
        final long parsed;
        try {
            parsed = Long.parseLong(digits.replace("_", ""), radix) * sign;
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException("invalid input event", error);
        }
        if (parsed < 0 || parsed > 0xff) {
            throw new IllegalArgumentException("input event outside byte");
        }
        return (int) parsed;
    }

    private void stopSession(boolean visible) {
        int generation = ++sessionGeneration;
        updateSessionKeepScreenOn(false, generation);
        autoStartToken = null;
        releaseHeldKey(false);
        FrameUpdate staleFrame = pendingFrame.getAndSet(null);
        if (staleFrame != null) {
            staleFrame.recycle();
        }
        BackendBridge.Session current = session;
        session = null;
        sessionStarting = false;
        updateKeypad(null);
        updateSessionControls(false);
        if (visible) {
            sessionView.setText(current == null
                    ? "" : getString(R.string.stopping_session));
        }
        if (current == null) {
            if (visible) {
                refreshSelection();
            }
            return;
        }
        inputExecutor.execute(() -> {
            boolean clean = true;
            try {
                current.close();
            } catch (IOException error) {
                clean = false;
            }
            boolean stoppedCleanly = clean;
            if (visible) {
                handler.post(() -> {
                    if (generation == sessionGeneration && session == null) {
                        sessionView.setText(stoppedCleanly
                                ? "" : getString(R.string.session_failed));
                        if (!stoppedCleanly) {
                            showError(getString(R.string.error_stop_failed));
                        }
                        refreshSelection();
                    }
                });
            }
        });
    }

    private void updateSessionKeepScreenOn(boolean enabled, int generation) {
        Runnable update = () -> {
            if (generation != sessionGeneration
                    || (enabled && session == null)) {
                return;
            }
            if (enabled) {
                getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            } else {
                getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            }
        };
        if (Looper.myLooper() == Looper.getMainLooper()) {
            update.run();
        } else {
            handler.post(update);
        }
    }

    private static void closeQuietly(BackendBridge.Session value) {
        try {
            value.close();
        } catch (IOException ignored) {
            // A stale or failed session has no further recoverable UI state.
        }
    }

    private void showProfile(String profileJson) {
        try {
            JSONObject profile = new JSONObject(profileJson);
            String model = SelectionLabels.displayName(this,
                    profile.getString("model"));
            String chipset = SelectionLabels.displayName(this,
                    profile.getString("chipset"));
            if (!"auto-default".equals(profile.optString(
                    "display_geometry_source", "auto-default"))) {
                profileView.setText(getString(R.string.profile_header,
                        model, profile.getInt("width"),
                        profile.getInt("height"), chipset));
            } else {
                profileView.setText(getString(
                        R.string.profile_header_without_geometry,
                        model, chipset));
            }
        } catch (JSONException | NullPointerException error) {
            profileView.setText("");
        }
    }

    private void showMoreMenu() {
        boolean busy = session != null || sessionStarting;
        PopupMenu popup = new PopupMenu(this, moreButton);
        popup.getMenu().add(0, MORE_CHOOSE, 0, R.string.choose)
                .setEnabled(!busy);
        popup.getMenu().add(0, MORE_SETTINGS, 1, R.string.settings)
                .setEnabled(!busy);
        popup.getMenu().add(0, MORE_RUN_STOP, 2,
                busy ? R.string.stop : R.string.start)
                .setEnabled(busy || canStartSession);
        popup.setOnMenuItemClickListener(item -> {
            if (item.getItemId() == MORE_CHOOSE) {
                chooseFirmware();
                return true;
            }
            if (item.getItemId() == MORE_SETTINGS) {
                showSettings();
                return true;
            }
            if (item.getItemId() == MORE_RUN_STOP) {
                if (session != null || sessionStarting) {
                    stopSession(true);
                } else {
                    startSession();
                }
                return true;
            }
            return false;
        });
        popup.show();
    }

    private void showSettings() {
        if (session != null || sessionStarting) {
            return;
        }
        SharedPreferences preferences = preferences();
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(20);
        body.setPadding(padding, 0, padding, 0);
        Switch persistent = new Switch(this);
        persistent.setText(R.string.persistent_state);
        persistent.setChecked(preferences.getBoolean(
                KEY_PERSISTENT_STATE, true));
        Switch experimental = new Switch(this);
        experimental.setText(R.string.experimental_rex);
        experimental.setChecked(preferences.getBoolean(
                KEY_EXPERIMENTAL_REX, false));
        body.addView(persistent, matchWidth());
        body.addView(experimental, matchWidth());
        new AlertDialog.Builder(this)
                .setTitle(R.string.settings_title)
                .setView(body)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.save, (dialog, which) ->
                        preferences.edit()
                                .putBoolean(KEY_PERSISTENT_STATE,
                                        persistent.isChecked())
                                .putBoolean(KEY_EXPERIMENTAL_REX,
                                        experimental.isChecked())
                                .apply())
                .show();
    }

    private void updateSessionControls(boolean canStart) {
        canStartSession = canStart;
        moreButton.setEnabled(true);
    }

    private void updateKeypad(BackendBridge.Session active) {
        for (KeySpec key : KEY_LAYOUT) {
            Button button = keyButtons[key.bit];
            View target = keyTargets[key.bit];
            boolean running = active != null;
            button.setEnabled(running);
            target.setEnabled(running);
            if (!running) {
                button.setAlpha(0.45f);
                target.setContentDescription(getString(key.labelResource));
                continue;
            }
            boolean mapped = manualKeyEvent(active.identity(), key.bit) != null;
            boolean detected = !mapped && active.supportsKey(key.bit);
            button.setAlpha(detected || mapped ? 1f : 0.72f);
            target.setContentDescription(getString(
                    mapped ? R.string.key_mapped_description
                            : detected ? R.string.key_detected_description
                            : R.string.key_mapping_description,
                    getString(key.labelResource)));
        }
    }

    private static synchronized boolean claimDetection(String token) {
        if (token.equals(activeDetectionToken)) {
            return false;
        }
        activeDetectionToken = token;
        return true;
    }

    private static synchronized void releaseDetection(String token) {
        if (token.equals(activeDetectionToken)) {
            activeDetectionToken = null;
        }
    }

    private boolean privateCopyIsReadable(String path) {
        try {
            File root = new File(getNoBackupFilesDir(), "session").getCanonicalFile();
            File file = new File(path).getCanonicalFile();
            File parent = file.getParentFile();
            return file.getName().equals("firmware.bin") && parent != null
                    && parent.getParentFile() != null
                    && parent.getParentFile().equals(root)
                    && file.isFile() && file.canRead();
        } catch (IOException error) {
            return false;
        }
    }

    private void showError(String message) {
        if (message == null || message.equals(lastErrorMessage)) {
            return;
        }
        lastErrorMessage = message;
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    private void clearError() {
        lastErrorMessage = null;
    }

    private void setIdleStatus(int textResource) {
        if (session == null && !sessionStarting) {
            sessionView.setText(textResource);
        }
    }

    private void clearIdleStatus() {
        if (session == null && !sessionStarting) {
            sessionView.setText("");
        }
    }

    private SharedPreferences preferences() {
        return getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    private void resetMetrics() {
        pcView.setText(R.string.metric_pc_empty);
        runView.setText(R.string.metric_run_empty);
        lcdView.setText(R.string.metric_lcd_empty);
        frameMetricView.setText(R.string.metric_frame_empty);
        inputView.setText(R.string.metric_input_empty);
        rejectView.setText(R.string.metric_reject_empty);
        jniView.setText(R.string.metric_jni_empty);
        ackView.setText(R.string.metric_ack_empty);
    }

    private FrameLayout handsetTarget(Button button, int bit) {
        FrameLayout target = new FrameLayout(this);
        target.setMinimumHeight(dp(40));
        target.setEnabled(false);
        target.setClickable(true);
        target.setFocusable(true);
        target.setOnTouchListener((view, event) -> onKeyTouch(bit, event));
        FrameLayout.LayoutParams visual = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT, Gravity.CENTER);
        target.addView(button, visual);
        return target;
    }

    private Drawable handsetButtonBackground() {
        int[][] states = {
                {-android.R.attr.state_enabled},
                {android.R.attr.state_pressed},
                {},
        };
        int[] colors = {
                Color.rgb(46, 46, 48),
                Color.rgb(112, 112, 116),
                Color.rgb(83, 83, 86),
        };
        StateListDrawable background = new StateListDrawable();
        for (int index = 0; index < states.length; index++) {
            GradientDrawable shape = new GradientDrawable();
            shape.setColor(colors[index]);
            shape.setCornerRadius(dp(1));
            shape.setStroke(1, Color.rgb(18, 18, 18));
            background.addState(states[index], shape);
        }
        return background;
    }

    private TextView metricCell(int textResource) {
        return statusLine(getString(textResource));
    }

    private TextView statusLine(String value) {
        TextView view = text(value, 7);
        view.setGravity(Gravity.CENTER_VERTICAL);
        view.setSingleLine(true);
        view.setEllipsize(TextUtils.TruncateAt.END);
        view.setPadding(dp(2), 0, dp(1), 0);
        return view;
    }

    private GridLayout.LayoutParams gridItem(int row, int column,
                                             int rowSpan, int columnSpan,
                                             float rowWeight) {
        GridLayout.LayoutParams params = new GridLayout.LayoutParams();
        params.rowSpec = GridLayout.spec(
                row, rowSpan, GridLayout.FILL, rowWeight);
        params.columnSpec = GridLayout.spec(
                column, columnSpan, GridLayout.FILL, 1f);
        params.width = 0;
        params.height = 0;
        params.setMargins(0, 0, 0, 0);
        return params;
    }

    private static void setTextIfChanged(TextView view, String value) {
        if (!value.contentEquals(view.getText())) {
            view.setText(value);
        }
    }

    private String latency(long milliseconds) {
        return milliseconds < 0 ? getString(R.string.latency_pending)
                : getString(R.string.latency_milliseconds, milliseconds);
    }

    private Button compactButton(int labelResource,
                                 View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(labelResource);
        button.setTextSize(12);
        button.setMinHeight(0);
        button.setMinimumHeight(0);
        button.setPadding(dp(4), 0, dp(4), 0);
        button.setOnClickListener(listener);
        return button;
    }

    private TextView text(String value, int sizeSp) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sizeSp);
        view.setTextColor(Color.WHITE);
        view.setPadding(0, dp(8), 0, dp(8));
        return view;
    }

    private LinearLayout.LayoutParams matchWidth() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private static final class FrameView extends View {
        private final Paint paint = new Paint();
        private Bitmap bitmap;

        FrameView(Context context) {
            super(context);
            paint.setFilterBitmap(false);
            paint.setAntiAlias(false);
            paint.setDither(false);
        }

        static FramePacket decodePacket(byte[] packet) {
            if (packet == null || packet.length < 16) {
                return null;
            }
            ByteBuffer buffer = ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN);
            int schema = buffer.getInt();
            int width = buffer.getInt();
            int height = buffer.getInt();
            buffer.getInt();
            long pixels = (long) width * height;
            if (schema != 1 || width < 1 || width > 2048
                    || height < 1 || height > 2048
                    || pixels > Integer.MAX_VALUE
                    || packet.length != 16L + pixels * 3L) {
                return null;
            }
            int[] colors = new int[(int) pixels];
            boolean visible = false;
            for (int index = 0; index < colors.length; index++) {
                int red = buffer.get() & 0xff;
                int green = buffer.get() & 0xff;
                int blue = buffer.get() & 0xff;
                visible |= red != 0 || green != 0 || blue != 0;
                colors[index] = Color.rgb(red, green, blue);
            }
            Bitmap bitmap = Bitmap.createBitmap(colors, width, height,
                    Bitmap.Config.ARGB_8888);
            bitmap.setDensity(Bitmap.DENSITY_NONE);
            return new FramePacket(bitmap, visible);
        }

        void setFrame(FramePacket frame) {
            if (frame == null) {
                return;
            }
            Bitmap previous = bitmap;
            bitmap = frame.bitmap;
            setContentDescription(getContext().getString(frame.nonBlank
                    ? R.string.lcd_visible : R.string.lcd_waiting));
            if (previous != null) {
                previous.recycle();
            }
            invalidate();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            Bitmap current = bitmap;
            if (current == null) {
                return;
            }
            float scale = Math.min((float) getWidth() / current.getWidth(),
                    (float) getHeight() / current.getHeight());
            int width = Math.max(1, Math.round(current.getWidth() * scale));
            int height = Math.max(1, Math.round(current.getHeight() * scale));
            int left = (getWidth() - width) / 2;
            int top = (getHeight() - height) / 2;
            canvas.drawBitmap(current, null,
                    new Rect(left, top, left + width, top + height), paint);
        }
    }

    private static final class PcmAudioSink implements AutoCloseable {
        private static final int SAMPLE_RATE = 44_100;
        private static final int FRAME_BYTES = 4;
        private static final int HEADER_BYTES = 24;
        private static final int PACKET_MAGIC = 0x3150354d;
        private static final int MAX_BYTES = HEADER_BYTES
                + SAMPLE_RATE * 30 * FRAME_BYTES;
        private final ArrayBlockingQueue<PcmPacket> pending =
                new ArrayBlockingQueue<>(1);
        private final Thread worker;
        private volatile boolean closed;
        private volatile boolean disabled;

        PcmAudioSink() {
            worker = new Thread(this::run, "msm5xxx-audio-output");
            worker.setDaemon(true);
            worker.start();
        }

        void offer(byte[] pcm) {
            if (closed || disabled || pcm == null || pcm.length == 0) {
                return;
            }
            PcmPacket packet = PcmPacket.decode(pcm);
            if (packet == null) {
                return;
            }
            pending.clear();
            pending.offer(packet);
        }

        private void run() {
            AudioTrack track = null;
            long trackStartFrame = 0;
            long revision = 0;
            try {
                while (!closed) {
                    PcmPacket packet = pending.take();
                    if (closed) {
                        break;
                    }
                    if (packet.revision <= revision) {
                        continue;
                    }
                    long playedFrame = packet.startFrame;
                    if (track != null) {
                        track.pause();
                        playedFrame = trackStartFrame
                                + Integer.toUnsignedLong(
                                        track.getPlaybackHeadPosition());
                        releaseTrack(track);
                    }
                    track = createTrack();
                    trackStartFrame = Math.max(packet.startFrame,
                            Math.min(playedFrame, packet.endFrame));
                    int offset = packet.byteOffset(trackStartFrame);
                    revision = packet.revision;
                    while (!closed && offset < packet.data.length) {
                        PcmPacket newer = pending.poll();
                        if (newer != null) {
                            if (newer.revision <= revision) {
                                continue;
                            }
                            track.pause();
                            playedFrame = trackStartFrame
                                    + Integer.toUnsignedLong(
                                            track.getPlaybackHeadPosition());
                            releaseTrack(track);
                            track = createTrack();
                            packet = newer;
                            trackStartFrame = Math.max(packet.startFrame,
                                    Math.min(playedFrame, packet.endFrame));
                            offset = packet.byteOffset(trackStartFrame);
                            revision = packet.revision;
                            continue;
                        }
                        int requested = Math.min(packet.data.length - offset,
                                SAMPLE_RATE * FRAME_BYTES / 50);
                        int written = track.write(packet.data, offset, requested,
                                AudioTrack.WRITE_BLOCKING);
                        if (written < 0) {
                            throw new IllegalStateException(
                                    "AudioTrack write failed: " + written);
                        }
                        if (written == 0) {
                            Thread.sleep(1);
                        } else {
                            offset += written;
                        }
                    }
                }
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException error) {
                disabled = true;
            } finally {
                releaseTrack(track);
            }
        }

        private static AudioTrack createTrack() {
            int minimum = AudioTrack.getMinBufferSize(
                    SAMPLE_RATE, AudioFormat.CHANNEL_OUT_STEREO,
                    AudioFormat.ENCODING_PCM_16BIT);
            if (minimum <= 0) {
                throw new IllegalStateException("AudioTrack is unavailable");
            }
            AudioFormat format = new AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(SAMPLE_RATE)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_STEREO)
                    .build();
            AudioTrack track = new AudioTrack.Builder()
                    .setAudioAttributes(new AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_GAME)
                            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                            .build())
                    .setAudioFormat(format)
                    .setBufferSizeInBytes(minimum)
                    .setTransferMode(AudioTrack.MODE_STREAM)
                    .setPerformanceMode(AudioTrack.PERFORMANCE_MODE_LOW_LATENCY)
                    .build();
            if (track.getState() != AudioTrack.STATE_INITIALIZED) {
                releaseTrack(track);
                throw new IllegalStateException("AudioTrack init failed");
            }
            try {
                track.play();
            } catch (RuntimeException error) {
                releaseTrack(track);
                throw error;
            }
            return track;
        }

        void disable() {
            disabled = true;
            closed = true;
            pending.clear();
            worker.interrupt();
        }

        @Override
        public void close() {
            closed = true;
            pending.clear();
            worker.interrupt();
            try {
                worker.join(1_000);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            }
        }

        private static void releaseTrack(AudioTrack track) {
            if (track == null) {
                return;
            }
            try {
                track.pause();
                track.flush();
            } catch (IllegalStateException ignored) {
                // Releasing an unavailable sink must not stop emulation.
            }
            try {
                track.release();
            } catch (RuntimeException ignored) {
                // Audio teardown is isolated from QEMU session teardown.
            }
        }

        private static final class PcmPacket {
            final byte[] data;
            final long revision;
            final long startFrame;
            final long endFrame;

            private PcmPacket(byte[] data, long revision, long startFrame) {
                this.data = data;
                this.revision = revision;
                this.startFrame = startFrame;
                this.endFrame = startFrame
                        + (data.length - HEADER_BYTES) / FRAME_BYTES;
            }

            static PcmPacket decode(byte[] data) {
                if (data.length <= HEADER_BYTES || data.length > MAX_BYTES
                        || (data.length - HEADER_BYTES) % FRAME_BYTES != 0) {
                    return null;
                }
                ByteBuffer header = ByteBuffer.wrap(data)
                        .order(ByteOrder.LITTLE_ENDIAN);
                if (header.getInt() != PACKET_MAGIC || header.getInt() != 1) {
                    return null;
                }
                long revision = header.getLong();
                long startFrame = header.getLong();
                long frames = (data.length - HEADER_BYTES) / FRAME_BYTES;
                if (revision <= 0 || startFrame != 0
                        || startFrame > Long.MAX_VALUE - frames) {
                    return null;
                }
                return new PcmPacket(data, revision, startFrame);
            }

            int byteOffset(long frame) {
                return HEADER_BYTES + (int) ((frame - startFrame) * FRAME_BYTES);
            }
        }
    }

    private static final class FramePacket {
        final Bitmap bitmap;
        final boolean nonBlank;

        FramePacket(Bitmap bitmap, boolean nonBlank) {
            this.bitmap = bitmap;
            this.nonBlank = nonBlank;
        }

        void recycle() {
            bitmap.recycle();
        }
    }

    private static final class FrameUpdate {
        final int generation;
        final FramePacket frame;
        final BackendBridge.Status status;
        final InputTimingSnapshot timing;

        FrameUpdate(int generation, FramePacket frame,
                    BackendBridge.Status status,
                    InputTimingSnapshot timing) {
            this.generation = generation;
            this.frame = frame;
            this.status = status;
            this.timing = timing;
        }

        void recycle() {
            if (frame != null) {
                frame.recycle();
            }
        }
    }

    private static final class InputTiming {
        private final ArrayDeque<InputProbe> pending = new ArrayDeque<>();
        private long observedEvents;
        private long expectedEvents;
        private long dispatchMillis = -1;
        private long ackMillis = -1;

        synchronized InputProbe begin(long startNanos) {
            expectedEvents = Math.max(expectedEvents, observedEvents) + 1;
            InputProbe probe = new InputProbe(expectedEvents, startNanos);
            pending.addLast(probe);
            return probe;
        }

        synchronized void dispatched(InputProbe probe, long nowNanos) {
            probe.dispatchMillis = elapsedMillis(probe.startNanos, nowNanos);
            if (probe.ackMillis >= 0) {
                dispatchMillis = probe.dispatchMillis;
            }
        }

        synchronized void failed(InputProbe probe) {
            pending.remove(probe);
        }

        synchronized InputTimingSnapshot observe(long events,
                                                   long nowNanos) {
            observedEvents = Math.max(observedEvents, events);
            while (!pending.isEmpty()
                    && pending.peekFirst().expectedEvents <= events) {
                InputProbe probe = pending.removeFirst();
                probe.ackMillis = elapsedMillis(probe.startNanos, nowNanos);
                ackMillis = probe.ackMillis;
                if (probe.dispatchMillis >= 0) {
                    dispatchMillis = probe.dispatchMillis;
                }
            }
            return new InputTimingSnapshot(dispatchMillis, ackMillis);
        }

        synchronized void reset() {
            pending.clear();
            observedEvents = 0;
            expectedEvents = 0;
            dispatchMillis = -1;
            ackMillis = -1;
        }

        private static long elapsedMillis(long startNanos, long endNanos) {
            return Math.max(0, (endNanos - startNanos) / 1_000_000L);
        }
    }

    private static final class InputProbe {
        final long expectedEvents;
        final long startNanos;
        long dispatchMillis = -1;
        long ackMillis = -1;

        InputProbe(long expectedEvents, long startNanos) {
            this.expectedEvents = expectedEvents;
            this.startNanos = startNanos;
        }
    }

    private static final class InputTimingSnapshot {
        final long dispatchMillis;
        final long ackMillis;

        InputTimingSnapshot(long dispatchMillis, long ackMillis) {
            this.dispatchMillis = dispatchMillis;
            this.ackMillis = ackMillis;
        }
    }

    private static final class KeySpec {
        final int labelResource;
        final int bit;
        final int row;
        final int column;

        KeySpec(int labelResource, int bit, int row, int column) {
            this.labelResource = labelResource;
            this.bit = bit;
            this.row = row;
            this.column = column;
        }
    }

    private static final class Selection {
        final Uri uri;
        final String name;
        final long size;

        Selection(Uri uri, String name, long size) {
            this.uri = uri;
            this.name = name;
            this.size = size;
        }
    }
}
