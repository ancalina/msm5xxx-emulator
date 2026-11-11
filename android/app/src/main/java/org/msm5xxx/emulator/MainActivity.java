package org.msm5xxx.emulator;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Presentation;
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
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.KeyEvent;
import android.view.Display;
import android.hardware.display.DisplayManager;
import android.view.View;
import android.view.WindowInsets;
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
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class MainActivity extends Activity {
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
    private static final String KEY_DETECTION_REVISION = "detection_revision";
    private static final String KEY_PROFILE = "profile";
    private static final String KEY_REJECT = "reject";
    private static final String KEY_PERSISTENT_STATE = "persistent_state";
    private static final String KEY_EXPERIMENTAL_REX = "experimental_rex";
    private static final String KEY_VIRTUAL_NETWORK = "virtual_network";
    private static final String KEY_NETWORK_HOST_TIME = "network_host_time";
    private static final String KEY_NETWORK_START_TIME = "network_start_time";
    private static final String KEY_SECONDARY_DESTINATION = "secondary_destination";
    private static final String SECONDARY_INTERNAL = "internal";
    private static final String SECONDARY_AUTO = "auto";
    private static final String SECONDARY_DISPLAY_PREFIX = "display:";
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
    // Bounded 30 Hz sampling; guest execution and audio cadence are independent.
    private static final long FRAME_UPDATE_INTERVAL_NS = 33_333_333L;
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
    // FIFO exclusively for key edges. Controls must never occupy this worker.
    private final ExecutorService inputExecutor =
            Executors.newSingleThreadExecutor(task -> new Thread(() -> {
                android.os.Process.setThreadPriority(
                        android.os.Process.THREAD_PRIORITY_DISPLAY);
                task.run();
            }, "key-edges"));
    private final ExecutorService controlExecutor =
            Executors.newSingleThreadExecutor();
    private final AtomicReference<FrameUpdate> pendingFrame =
            new AtomicReference<>();
    private final AtomicBoolean framePosted = new AtomicBoolean();
    private final InputTiming inputTiming = new InputTiming();
    // Only the key-edge executor accesses this state.
    private final KeyPressDuration keyPressDuration = new KeyPressDuration();
    private long lastMetricsLog;
    private long lastMetricLabels;
    private TextView profileView;
    private TextView sessionView;
    private LinearLayout metricsGroup;
    private TextView pcView;
    private TextView runView;
    private TextView lcdView;
    private TextView frameMetricView;
    private Button foldButton;
    private TextView inputView;
    private TextView rejectView;
    private TextView jniView;
    private TextView ackView;
    private FrameView frameView;
    private FrameView secondaryFrameView;
    private TextView secondaryPreviewNotice;
    private TextView presentationPreviewNotice;
    private FrameLayout displayHost;
    // Whole-app overlay host for the additional display; safe insets keep it out of cutouts and bars.
    private FrameLayout appRoot;
    private final android.graphics.Rect safeInsets = new android.graphics.Rect();
    private FrameLayout secondaryPanel;
    private boolean secondaryHidden;
    private DisplayManager displayManager;
    private Presentation secondaryPresentation;
    private FrameView presentationFrameView;
    private String presentationDisplayId;
    private boolean presentationListenerRegistered;
    private final DisplayManager.DisplayListener presentationDisplayListener =
            new DisplayManager.DisplayListener() {
                @Override
                public void onDisplayAdded(int displayId) {
                    updateSecondaryPresentation();
                }

                @Override
                public void onDisplayRemoved(int displayId) {
                    updateSecondaryPresentation();
                }

                @Override
                public void onDisplayChanged(int displayId) {
                    updateSecondaryPresentation();
                }
            };
    private BackendBridge.Status latestStatus;
    private Button moreButton;
    private final Button[] keyButtons = new Button[23];
    private final View[] keyTargets = new View[23];
    private boolean backendProbeStarted;
    private boolean qemuReady;
    private boolean detectorRuntimeReady;
    private volatile boolean activityResumed;
    private volatile boolean sessionStarting;
    private boolean canStartSession;
    private boolean editingInputMapping;
    private final Map<String, Integer> inputSources = new HashMap<>();
    private final Map<Integer, Integer> inputCounts = new HashMap<>();
    private final Map<Integer, Integer> inputCodes = new HashMap<>();
    private int heldKeyBit = -1;
    private Integer heldEventCode;
    private int mappingTapBit = -1;
    private File autorunDirectory;
    private long nextEvidenceNanos;
    private String autoStartToken;
    private String lastErrorMessage;
    private volatile BackendBridge.Session session;
    private FirmwareLibraryScreen libraryScreen;
    private volatile int sessionGeneration;
    private final Object sessionLifecycleLock = new Object();

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
    protected void attachBaseContext(Context base) {
        String language = base.getSharedPreferences(PREFS, MODE_PRIVATE).getString("ui_language", "auto");
        if (!"auto".equals(language)) {
            android.content.res.Configuration config = new android.content.res.Configuration(base.getResources().getConfiguration());
            config.setLocale(java.util.Locale.forLanguageTag(language));
            base = base.createConfigurationContext(config);
        }
        super.attachBaseContext(base);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        displayManager = getSystemService(DisplayManager.class);
        setContentView(buildContent());
        libraryScreen = new FirmwareLibraryScreen(this, null);
        File external = getExternalFilesDir(null);
        if (external != null && new File(external, "autorun").isFile()) {
            autorunDirectory = external;
            File[] files = new File(external, "firmware").listFiles(File::isFile);
            if (files != null && files.length > 0) {
                java.util.Arrays.sort(files);
                preparePrivateCopy(new Selection(Uri.fromFile(files[0]), files[0].getName(), files[0].length()));
            }
        }
        refreshSelection();
        probeBackend();
        if (autorunDirectory == null && getIntent().getData() != null) {
            Intent intent = getIntent();
            preparePrivateCopy(new Selection(intent.getData(), intent.getStringExtra("name"),
                    intent.getLongExtra("size", -1)));
        }
    }

    private void returnToLibrary() {
        Runnable navigate = () -> {
            Intent intent = new Intent(this, LibraryActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    .putExtra("returning", true);
            startActivity(intent);
            finish();
        };
        if (session != null || sessionStarting) {
            stopSession(false, navigate);
        } else navigate.run();
    }

    @Override
    public void onBackPressed() {
        if (session == null && !sessionStarting) returnToLibrary();
        else new AlertDialog.Builder(this).setMessage(R.string.confirm_power_off_library)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.stop_emulator, (dialog, which) -> returnToLibrary()).show();
    }

    @Override
    protected void onResume() {
        super.onResume();
        activityResumed = true;
        if (!presentationListenerRegistered && displayManager != null) {
            displayManager.registerDisplayListener(
                    presentationDisplayListener, handler);
            presentationListenerRegistered = true;
        }
        updateSecondaryPresentation();
        handler.removeCallbacks(refreshWhileCopying);
        refreshWhileCopying.run();
        updateSessionKeepScreenOn(session != null, sessionGeneration);
    }

    @Override
    protected void onPause() {
        activityResumed = false;
        if (session != null && libraryScreen != null && frameView != null)
            libraryScreen.recordFrame(preferences().getString(KEY_URI, null), frameView.bitmap);
        if (presentationListenerRegistered && displayManager != null) {
            displayManager.unregisterDisplayListener(presentationDisplayListener);
            presentationListenerRegistered = false;
        }
        dismissSecondaryPresentation();
        updateSecondaryPresentation();
        handler.removeCallbacks(refreshWhileCopying);
        releaseHeldKey(false);
        releaseKeyboardKeys();
        updateSessionKeepScreenOn(false, sessionGeneration);
        // Focus loss must not destroy guest RAM/state. Explicit stop/destroy owns it.
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (presentationListenerRegistered && displayManager != null) {
            displayManager.unregisterDisplayListener(presentationDisplayListener);
            presentationListenerRegistered = false;
        }
        dismissSecondaryPresentation();
        stopSession(false);
        if (libraryScreen != null) libraryScreen.close();
        inputExecutor.execute(controlExecutor::shutdown);
        inputExecutor.shutdown();
        super.onDestroy();
    }

    private View buildContent() {
        appRoot = new FrameLayout(this);
        LinearLayout content = new LinearLayout(this);
        appRoot.addView(content, new FrameLayout.LayoutParams(-1, -1));
        content.setOrientation(LinearLayout.VERTICAL);
        content.setBackgroundColor(Color.rgb(18, 18, 18));
        int padding = dp(2);
        content.setPadding(padding, padding, padding, padding);

        frameView = new FrameView(this);
        frameView.setBackgroundColor(Color.BLACK);
        frameView.setContentDescription(getString(R.string.phone_screen));
        frameView.setFocusable(true);
        displayHost = new FrameLayout(this);
        displayHost.addView(frameView, new FrameLayout.LayoutParams(-1, -1));
        content.addView(displayHost, new LinearLayout.LayoutParams(-1, 0, 1));
        displayHost.setMinimumHeight(dp(120));

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
                                LinearLayout.LayoutParams.MATCH_PARENT, dp(48));
                side.addView(target, volumeParams);
            } else {
                GridLayout.LayoutParams keyParams = gridItem(
                        key.row, key.column, 1, 1, 1f);
                keypad.addView(target, keyParams);
            }
            keyButtons[key.bit] = button;
            keyTargets[key.bit] = target;
        }

        foldButton = new Button(this);
        foldButton.setText(R.string.fold_open);
        foldButton.setTextSize(11);
        foldButton.setTextColor(Color.WHITE);
        foldButton.setMinHeight(0);
        foldButton.setMinimumHeight(0);
        foldButton.setMinWidth(0);
        foldButton.setMinimumWidth(0);
        foldButton.setPadding(0, 0, 0, 0);
        foldButton.setBackground(handsetButtonBackground());
        foldButton.setOnClickListener(view -> toggleFold());
        foldButton.setEnabled(true);
        foldButton.setAlpha(1f);
        side.addView(foldButton, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(48)));

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
        metricsGroup = new LinearLayout(this);
        metricsGroup.setOrientation(LinearLayout.VERTICAL);
        metricsGroup.setFocusable(true);
        metricsGroup.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
        for (TextView line : new TextView[]{runView, pcView, lcdView, frameMetricView}) {
            line.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            metricsGroup.addView(line, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        }
        updateMetricsDescription();
        telemetry.addView(metricsGroup, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 4));
        sessionView.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        telemetry.addView(sessionView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        side.addView(telemetry, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));

        moreButton = compactButton(R.string.more, view -> showMoreMenu());
        moreButton.setTextSize(20);
        moreButton.setBackground(menuButtonBackground());
        moreButton.setContentDescription(getString(R.string.more_actions) + ". " + getString(R.string.menu_hint));
        side.addView(moreButton, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(48)));

        LinearLayout controls = new LinearLayout(this);
        controls.setOrientation(LinearLayout.HORIZONTAL);
        controls.addView(side, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.MATCH_PARENT, 1.5f));
        controls.addView(keypad, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.MATCH_PARENT, 3));
        LinearLayout.LayoutParams controlsLayout = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(336));
        content.addView(controls, controlsLayout);
        appRoot.setOnApplyWindowInsetsListener((view, insets) -> {
            int left, top, right, bottom;
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets safe = insets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                left = safe.left; top = safe.top; right = safe.right; bottom = safe.bottom;
            } else {
                left = insets.getSystemWindowInsetLeft(); top = insets.getSystemWindowInsetTop();
                right = insets.getSystemWindowInsetRight(); bottom = insets.getSystemWindowInsetBottom();
                android.view.DisplayCutout cutout = insets.getDisplayCutout();
                if (cutout != null) {
                    left = Math.max(left, cutout.getSafeInsetLeft()); top = Math.max(top, cutout.getSafeInsetTop());
                    right = Math.max(right, cutout.getSafeInsetRight()); bottom = Math.max(bottom, cutout.getSafeInsetBottom());
                }
            }
            safeInsets.set(left, top, right, bottom);
            int edge = dp(2);
            content.setPadding(edge + left, edge + top, edge + right, edge);
            if (controlsLayout.bottomMargin != bottom) {
                controlsLayout.bottomMargin = bottom;
                controls.setLayoutParams(controlsLayout);
            }
            if (secondaryPanel != null) clampSecondary((FrameLayout.LayoutParams) secondaryPanel.getLayoutParams());
            return insets;
        });
        buildSecondaryPanel();
        return appRoot;
    }

    private TextView previewNotice(Context context) {
        TextView notice = new TextView(context);
        notice.setText(R.string.display_preview_notice);
        notice.setTextSize(10);
        notice.setTextColor(Color.WHITE);
        notice.setBackgroundColor(Color.argb(190, 0, 0, 0));
        notice.setVisibility(latestStatus != null && latestStatus.secondaryPreview
                ? View.VISIBLE : View.GONE);
        return notice;
    }

    private void buildSecondaryPanel() {
        secondaryPanel = new FrameLayout(this);
        secondaryPanel.setBackgroundColor(Color.rgb(40, 40, 40));
        secondaryPanel.setVisibility(View.GONE);
        FrameLayout.LayoutParams bounds = new FrameLayout.LayoutParams(dp(160), dp(128));
        bounds.gravity = Gravity.TOP | Gravity.LEFT;
        bounds.leftMargin = dp(8);
        bounds.topMargin = dp(8);
        appRoot.addView(secondaryPanel, bounds);
        TextView title = statusLine(getString(R.string.additional_display));
        title.setTextSize(11);
        title.setContentDescription(getString(R.string.move_display));
        title.setClickable(true);
        secondaryPanel.addView(title, new FrameLayout.LayoutParams(-1, dp(24)));
        title.setOnTouchListener((view, event) -> moveSecondary(view, event, false));
        secondaryFrameView = new FrameView(this);
        secondaryFrameView.setBackgroundColor(Color.BLACK);
        FrameLayout.LayoutParams image = new FrameLayout.LayoutParams(-1, -1);
        image.topMargin = dp(24);
        secondaryPanel.addView(secondaryFrameView, image);
        Button resize = compactButton(R.string.resize_display, view -> {
            FrameLayout.LayoutParams size = (FrameLayout.LayoutParams) secondaryPanel.getLayoutParams();
            size.width += dp(24);
            size.height += dp(16);
            clampSecondary(size);
        });
        resize.setText(R.string.resize_symbol);
        resize.setContentDescription(getString(R.string.resize_display));
        FrameLayout.LayoutParams handle = new FrameLayout.LayoutParams(dp(32), dp(32));
        handle.gravity = Gravity.BOTTOM | Gravity.RIGHT;
        secondaryPanel.addView(resize, handle);
        secondaryPreviewNotice = previewNotice(this);
        FrameLayout.LayoutParams noticeBounds = new FrameLayout.LayoutParams(-1, -2);
        noticeBounds.gravity = Gravity.BOTTOM;
        noticeBounds.rightMargin = dp(32);
        secondaryPanel.addView(secondaryPreviewNotice, noticeBounds);
        resize.setOnTouchListener((view, event) -> moveSecondary(view, event, true));
        appRoot.addOnLayoutChangeListener((view, l, t, r, b, ol, ot, or, ob) -> {
            if (r > l && b > t && (r - l != or - ol || b - t != ob - ot)) {
                clampSecondary((FrameLayout.LayoutParams) secondaryPanel.getLayoutParams());
            }
        });
    }

    private boolean moveSecondary(View handle, MotionEvent event, boolean resize) {
        if (event.getActionMasked() == MotionEvent.ACTION_DOWN) {
            FrameLayout.LayoutParams bounds = (FrameLayout.LayoutParams) secondaryPanel.getLayoutParams();
            handle.setTag(new float[]{event.getRawX(), event.getRawY(),
                    resize ? bounds.width : bounds.leftMargin,
                    resize ? bounds.height : bounds.topMargin, 0});
            return true;
        }
        if (event.getActionMasked() == MotionEvent.ACTION_MOVE && handle.getTag() instanceof float[]) {
            float[] start = (float[]) handle.getTag();
            float dx = event.getRawX() - start[0];
            float dy = event.getRawY() - start[1];
            int touchSlop = android.view.ViewConfiguration.get(this)
                    .getScaledTouchSlop();
            if (start[4] == 0 && Math.abs(dx) < touchSlop
                    && Math.abs(dy) < touchSlop) {
                return true;
            }
            start[4] = 1;
            FrameLayout.LayoutParams bounds = (FrameLayout.LayoutParams) secondaryPanel.getLayoutParams();
            int x = Math.round(start[2] + dx);
            int y = Math.round(start[3] + dy);
            if (resize) {
                bounds.width = Math.max(dp(96), x);
                bounds.height = Math.max(dp(72), y);
            } else {
                bounds.leftMargin = x;
                bounds.topMargin = y;
            }
            clampSecondary(bounds);
            return true;
        }
        if (event.getActionMasked() == MotionEvent.ACTION_UP) {
            float[] start = handle.getTag() instanceof float[]
                    ? (float[]) handle.getTag() : null;
            handle.setTag(null);
            if (start != null && start[4] == 0) {
                handle.performClick();
            }
            return true;
        }
        if (event.getActionMasked() == MotionEvent.ACTION_CANCEL) {
            handle.setTag(null);
        }
        return true;
    }

    private void clampSecondary(FrameLayout.LayoutParams bounds) {
        int width = appRoot.getWidth() - safeInsets.left - safeInsets.right;
        int height = appRoot.getHeight() - safeInsets.top - safeInsets.bottom;
        if (width < 1 || height < 1) {
            return;
        }
        int clampedWidth = Math.min(width, Math.max(dp(96), bounds.width));
        int clampedHeight = Math.min(height, Math.max(dp(72), bounds.height));
        int clampedLeft = Math.max(safeInsets.left,
                Math.min(safeInsets.left + width - clampedWidth, bounds.leftMargin));
        int clampedTop = Math.max(safeInsets.top,
                Math.min(safeInsets.top + height - clampedHeight, bounds.topMargin));
        bounds.width = clampedWidth;
        bounds.height = clampedHeight;
        bounds.leftMargin = clampedLeft;
        bounds.topMargin = clampedTop;
        secondaryPanel.setLayoutParams(bounds);
    }

    private void chooseSecondaryDestination() {
        ArrayList<String> destinations = new ArrayList<>();
        ArrayList<String> labels = new ArrayList<>();
        destinations.add(SECONDARY_INTERNAL);
        labels.add(getString(R.string.display_in_app));
        destinations.add(SECONDARY_AUTO);
        labels.add(getString(R.string.display_automatic));
        Display[] displays = displayManager == null ? new Display[0]
                : displayManager.getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION);
        for (Display display : displays) {
            destinations.add(SECONDARY_DISPLAY_PREFIX + presentationKey(display));
            labels.add(getString(R.string.display_external,
                    display.getName(), display.getDisplayId()));
        }
        String selected = preferences().getString(
                KEY_SECONDARY_DESTINATION, SECONDARY_INTERNAL);
        int checked = destinations.indexOf(selected);
        new AlertDialog.Builder(this)
                .setTitle(R.string.display_destination)
                .setSingleChoiceItems(labels.toArray(new String[0]), checked,
                        (dialog, which) -> {
                            preferences().edit().putString(
                                    KEY_SECONDARY_DESTINATION,
                                    destinations.get(which)).apply();
                            dialog.dismiss();
                            updateSecondaryPresentation();
                        })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private static String presentationKey(Display display) {
        // Public API has no persistent display ID; reconnect may require reselection.
        return display.getDisplayId() + ":" + display.getName();
    }

    private Display selectedPresentationDisplay() {
        if (!activityResumed || secondaryHidden || displayManager == null
                || latestStatus == null || !latestStatus.secondaryAvailable) {
            return null;
        }
        String destination = preferences().getString(
                KEY_SECONDARY_DESTINATION, SECONDARY_INTERNAL);
        if (SECONDARY_INTERNAL.equals(destination)) {
            return null;
        }
        String selectedId = destination.startsWith(SECONDARY_DISPLAY_PREFIX)
                ? destination.substring(SECONDARY_DISPLAY_PREFIX.length()) : null;
        for (Display display : displayManager.getDisplays(
                DisplayManager.DISPLAY_CATEGORY_PRESENTATION)) {
            if (selectedId == null || selectedId.equals(presentationKey(display))) {
                return display;
            }
        }
        return null;
    }

    private void updateSecondaryPresentation() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            handler.post(this::updateSecondaryPresentation);
            return;
        }
        Display display = selectedPresentationDisplay();
        if (display == null) {
            dismissSecondaryPresentation();
            secondaryPanel.setVisibility(latestStatus != null
                    && latestStatus.secondaryAvailable && !secondaryHidden
                    ? View.VISIBLE : View.GONE);
            return;
        }
        String uniqueId = presentationKey(display);
        if (secondaryPresentation != null && secondaryPresentation.isShowing()
                && uniqueId.equals(presentationDisplayId)) {
            secondaryPanel.setVisibility(View.GONE);
            return;
        }
        dismissSecondaryPresentation();
        try {
            Presentation presentation = new Presentation(this, display);
            FrameView output = new FrameView(presentation.getContext());
            output.setBackgroundColor(Color.BLACK);
            FrameLayout content = new FrameLayout(presentation.getContext());
            content.addView(output, new FrameLayout.LayoutParams(-1, -1));
            presentationPreviewNotice = previewNotice(presentation.getContext());
            FrameLayout.LayoutParams noticeBounds = new FrameLayout.LayoutParams(-1, -2);
            noticeBounds.gravity = Gravity.BOTTOM;
            content.addView(presentationPreviewNotice, noticeBounds);
            presentation.setContentView(content, new FrameLayout.LayoutParams(-1, -1));
            secondaryPresentation = presentation;
            presentationFrameView = output;
            presentationDisplayId = uniqueId;
            presentation.show();
            secondaryFrameView.moveFrameTo(output);
            secondaryPanel.setVisibility(View.GONE);
        } catch (RuntimeException error) {
            android.util.Log.w("MSM5xxxDisplay",
                    "Presentation display unavailable", error);
            dismissSecondaryPresentation();
            secondaryPanel.setVisibility(View.VISIBLE);
        }
    }

    private void dismissSecondaryPresentation() {
        Presentation oldPresentation = secondaryPresentation;
        FrameView oldView = presentationFrameView;
        secondaryPresentation = null;
        presentationFrameView = null;
        presentationPreviewNotice = null;
        presentationDisplayId = null;
        if (oldView != null) {
            oldView.moveFrameTo(secondaryFrameView);
        }
        if (oldPresentation != null) {
            oldPresentation.dismiss();
        }
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

    private void preparePrivateCopy(Selection selection) {
        if (session != null || sessionStarting) {
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
        new Thread(() -> {
            copyFirmware(application, selection.uri, token, previousCopy);
            handler.post(this::refreshSelection);
        }, "firmware-copy").start();
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
            try (InputStream input = "file".equals(uri.getScheme())
                    ? new FileInputStream(new File(uri.getPath()))
                    : context.getContentResolver().openInputStream(uri);
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
        if (canStart && (activityResumed || autorunDirectory != null)
                && token.equals(autoStartToken)) {
            autoStartToken = null;
            handler.post(this::startSession);
        }
    }

    private void beginDetectionIfReady(String path, String token) {
        if (!qemuReady || !detectorRuntimeReady || token == null) {
            return;
        }
        SharedPreferences preferences = preferences();
        final long revision;
        try {
            revision = getPackageManager().getPackageInfo(getPackageName(), 0).lastUpdateTime;
        } catch (android.content.pm.PackageManager.NameNotFoundException error) {
            throw new IllegalStateException("installed package unavailable", error);
        }
        String resultToken = preferences.getString(KEY_DETECTION_TOKEN, null);
        String state = preferences.getString(KEY_DETECTION, DETECTION_NONE);
        if (token.equals(resultToken)
                && preferences.getLong(KEY_DETECTION_REVISION, -1) == revision
                && (DETECTION_ACCEPTED.equals(state)
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
                .putLong(KEY_DETECTION_REVISION, revision)
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
        if (session != null || sessionStarting) {
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
        boolean virtualNetwork = preferences.getBoolean(
                KEY_VIRTUAL_NETWORK, false);
        boolean networkHostTime = preferences.getBoolean(KEY_NETWORK_HOST_TIME, true);
        Double networkStartTime = parseNetworkStartTime(preferences.getString(KEY_NETWORK_START_TIME, ""));
        int generation = ++sessionGeneration;
        sessionStarting = true;
        latestStatus = null;
        if (foldButton != null) { foldButton.setEnabled(true); foldButton.setAlpha(1f); }
        secondaryHidden = false;
        dismissSecondaryPresentation();
        secondaryPanel.setVisibility(View.GONE);
        secondaryFrameView.clear();
        frameView.clear();
        inputTiming.reset();
        clearError();
        updateSessionControls(false);
        updateKeypad(null);
        resetMetrics();
        sessionView.setText(R.string.starting_session);
        Context application = getApplicationContext();
        new Thread(() -> runSession(application, new File(path), profile,
                persistentState, experimentalRex, virtualNetwork, networkHostTime, networkStartTime, generation),
                "qemu-session").start();
    }

    private void runSession(Context context, File firmware, String profile,
                            boolean persistentState, boolean experimentalRex,
                            boolean virtualNetwork, boolean networkHostTime, Double networkStartTime,
                            int generation) {
        BackendBridge.Session opened = null;
        FramePacket latestFrame = null;
        FramePacket latestSecondary = null;
        PcmAudioSink audioSink = new PcmAudioSink();
        boolean audioStarted = false;
        boolean audioRejected = false;
        boolean backgroundPaused = false;
        boolean failed = false;
        try {
            opened = BackendBridge.open(context, firmware, profile,
                    persistentState, experimentalRex, virtualNetwork, networkHostTime, networkStartTime);
            synchronized (sessionLifecycleLock) {
                if (generation != sessionGeneration) {
                    return;
                }
                session = opened;
                sessionStarting = false;
            }
            updateSessionKeepScreenOn(true, generation);
            BackendBridge.Session active = opened;
            handler.post(() -> {
                if (generation == sessionGeneration && session != null) {
                    sessionView.setText("");
                    moreButton.announceForAccessibility(getString(R.string.booted_announcement));
                    libraryScreen.recordBoot(preferences().getString(KEY_URI, null), active.identity(),
                            preferences().getString(KEY_COPY, null), preferences().getString(KEY_NAME, null));
                    updateKeypad(active);
                    updateSessionControls(false);
                }
            });
            long nextMetricUpdate = 0;
            long nextBackendUpdate = SystemClock.elapsedRealtimeNanos();
            long publishedInputEvents = -1;
            long publishedRejections = -1;
            while (generation == sessionGeneration) {
                boolean shouldPause = !activityResumed && !preferences().getBoolean("keep_running_background", false);
                if (shouldPause != backgroundPaused) {
                    if (shouldPause) {
                        audioSink.close();
                        audioStarted = false;
                    }
                    opened.backgroundPause(shouldPause);
                    backgroundPaused = shouldPause;
                    if (!shouldPause && !audioRejected) audioSink = new PcmAudioSink();
                }
                if (backgroundPaused) {
                    Thread.sleep(50);
                    continue;
                }
                long now = SystemClock.elapsedRealtimeNanos();
                if (now < nextBackendUpdate) {
                    TimeUnit.NANOSECONDS.sleep(nextBackendUpdate - now);
                    continue;
                }
                FramePacket frame = FrameView.decodePacket(opened.frame());
                if (frame != null) {
                    if (latestFrame != null) {
                        latestFrame.recycle();
                    }
                    latestFrame = frame;
                }
                FramePacket secondary = FrameView.decodePacket(opened.secondaryFrame());
                if (secondary != null) {
                    if (latestSecondary != null) {
                        latestSecondary.recycle();
                    }
                    latestSecondary = secondary;
                }
                BackendBridge.Status status = opened.status();
                if (!audioRejected && !audioStarted
                        && "native".equals(status.audioStatus)) {
                    audioSink.start(opened);
                    audioStarted = true;
                } else if (!audioRejected
                        && "rejected".equals(status.audioStatus)) {
                    audioSink.close();
                    audioRejected = true;
                }
                long ackNow = SystemClock.elapsedRealtimeNanos();
                InputTimingSnapshot timing = inputTiming.observe(
                        status.inputHostEvents, ackNow);
                now = SystemClock.elapsedRealtimeNanos();
                boolean inputChanged = status.inputHostEvents
                        != publishedInputEvents
                        || status.inputRejections != publishedRejections;
                if (inputChanged && timing.ackMillis >= 0) {
                    android.util.Log.d("MSM5xxxSession", "Key dispatch=" + timing.dispatchMillis
                            + " ms ack=" + timing.ackMillis + " ms");
                }
                boolean frameDue = latestFrame != null || latestSecondary != null;
                boolean metricDue = now >= nextMetricUpdate;
                if (frameDue || inputChanged || metricDue) {
                    enqueueFrame(new FrameUpdate(generation, latestFrame, latestSecondary,
                            status, timing, audioSink.failureCount()));
                    latestFrame = null;
                    latestSecondary = null;
                    publishedInputEvents = status.inputHostEvents;
                    publishedRejections = status.inputRejections;
                    nextMetricUpdate = now + METRIC_UPDATE_INTERVAL_NS;
                }
                if (!status.processRunning) {
                    throw new IOException("QEMU process exited");
                }
                // Keep phase against an absolute deadline; skip missed slots.
                long completed = SystemClock.elapsedRealtimeNanos();
                nextBackendUpdate += FRAME_UPDATE_INTERVAL_NS;
                if (nextBackendUpdate <= completed) {
                    nextBackendUpdate += ((completed - nextBackendUpdate)
                            / FRAME_UPDATE_INTERVAL_NS + 1) * FRAME_UPDATE_INTERVAL_NS;
                }
            }
        } catch (IOException | RuntimeException | LinkageError error) {
            android.util.Log.e("MSM5xxxSession", "Session failed", error);
            failed = true;
            boolean currentGeneration;
            synchronized (sessionLifecycleLock) {
                currentGeneration = generation == sessionGeneration;
                if (currentGeneration) {
                    session = null;
                    sessionStarting = false;
                }
            }
            if (currentGeneration) {
                updateSessionKeepScreenOn(false, generation);
                handler.post(() -> {
                    if (generation == sessionGeneration) {
                        setInputMappingEditing(false);
                        updateKeypad(null);
                        if (libraryScreen != null && frameView != null)
                            libraryScreen.recordFrame(preferences().getString(KEY_URI, null), frameView.bitmap);
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
            if (latestSecondary != null) {
                latestSecondary.recycle();
            }
            if (opened != null && (failed || generation != sessionGeneration)) {
                closeAfterKeys(opened);
            }
        }
    }

    private void enqueueFrame(FrameUpdate update) {
        while (true) {
            FrameUpdate previous = pendingFrame.get();
            FramePacket frame = previous != null
                    && previous.generation == update.generation
                    && update.frame == null ? previous.frame : update.frame;
            FramePacket secondary = previous != null
                    && previous.generation == update.generation
                    && update.secondary == null ? previous.secondary : update.secondary;
            FrameUpdate merged = previous == null
                    || previous.generation != update.generation ? update
                    : new FrameUpdate(update.generation, frame, secondary,
                            update.status, update.timing, update.localAudioFailures);
            if (pendingFrame.compareAndSet(previous, merged)) {
                if (previous != null && previous != merged) {
                    previous.recycleExcept(frame, secondary);
                }
                if (update != merged) {
                    update.recycleExcept(frame, secondary);
                }
                break;
            }
        }
        if (framePosted.compareAndSet(false, true)) {
            handler.post(this::drainFrame);
        }
    }

    private void drainFrame() {
        FrameUpdate update = pendingFrame.getAndSet(null);
        if (update != null) {
            showSessionFrame(update.generation, update.frame, update.secondary, update.status,
                    update.timing, update.localAudioFailures);
        }
        framePosted.set(false);
        if (pendingFrame.get() != null
                && framePosted.compareAndSet(false, true)) {
            handler.post(this::drainFrame);
        }
    }

    private void showSessionFrame(int generation, FramePacket frame,
                                  FramePacket secondary, BackendBridge.Status status,
                                  InputTimingSnapshot timing,
                                  long localAudioFailures) {
        if (generation != sessionGeneration || session == null) {
            if (frame != null) {
                frame.recycle();
            }
            if (secondary != null) {
                secondary.recycle();
            }
            return;
        }
        boolean secondaryAvailabilityChanged = latestStatus == null
                || latestStatus.secondaryAvailable != status.secondaryAvailable;
        latestStatus = status;
        foldButton.setEnabled(true);
        foldButton.setAlpha(1f);
        setTextIfChanged(foldButton, getString(status.foldOpen ? R.string.fold_close : R.string.fold_open));
        secondaryPreviewNotice.setVisibility(status.secondaryPreview ? View.VISIBLE : View.GONE);
        if (presentationPreviewNotice != null) {
            presentationPreviewNotice.setVisibility(status.secondaryPreview ? View.VISIBLE : View.GONE);
        }
        if (secondaryAvailabilityChanged) {
            updateSecondaryPresentation();
        }
        frameView.setFrame(frame, generation);
        if (autorunDirectory != null && SystemClock.elapsedRealtimeNanos() >= nextEvidenceNanos) {
            nextEvidenceNanos = SystemClock.elapsedRealtimeNanos() + 2_000_000_000L;
            try {
                if (frameView.bitmap != null) {
                    try (FileOutputStream output = new FileOutputStream(new File(autorunDirectory, "frame.png"))) {
                        frameView.bitmap.compress(Bitmap.CompressFormat.PNG, 100, output);
                    }
                }
                try (FileWriter log = new FileWriter(new File(autorunDirectory, "session.log"), true)) {
                    log.write("app elapsed_ms=" + SystemClock.elapsedRealtime() + " frames="
                            + status.frameSequence + " instructions=" + status.instructions
                            + " input=" + status.inputHostEvents + " network=" + status.virtualCellStatus + "\n");
                }
            } catch (IOException error) {
                android.util.Log.e("MSM5xxxSession", "Evidence write failed", error);
            }
        }
        if (status.secondaryAvailable) {
            if (secondaryHidden) {
                secondaryFrameView.setFrame(secondary, generation);
                secondaryPanel.setVisibility(View.GONE);
            } else {
                if (secondaryPresentation != null
                        && !secondaryPresentation.isShowing()) {
                    dismissSecondaryPresentation();
                    secondaryPanel.setVisibility(View.VISIBLE);
                }
                FrameView destination = secondaryPresentation != null
                        ? presentationFrameView : secondaryFrameView;
                destination.setFrame(secondary, generation);
                secondaryPanel.setVisibility(secondaryPresentation != null
                        ? View.GONE : View.VISIBLE);
            }
        } else {
            if (secondary != null) {
                secondary.recycle();
            }
            dismissSecondaryPresentation();
            secondaryFrameView.clear();
            secondaryPanel.setVisibility(View.GONE);
        }
        setTextIfChanged(sessionView, "configured".equals(status.virtualCellStatus)
                ? getString(R.string.virtual_network_active)
                : "rejected".equals(status.virtualCellStatus)
                        ? getString(R.string.virtual_network_unavailable) : "");
        long now = SystemClock.elapsedRealtime();
        if (now - lastMetricsLog >= 10000) {
            lastMetricsLog = now;
            android.util.Log.d("MSM5xxxSession", "Run " + status.instructions + " PC " + status.pc
                    + " LCD " + status.lcdWrites + " Frame " + status.frameSequence);
        }
        if (now - lastMetricLabels >= 500) {
            lastMetricLabels = now;
            setTextIfChanged(pcView, getString(R.string.metric_pc, status.pc));
            setTextIfChanged(runView, getString(
                    R.string.metric_run, status.instructions));
            setTextIfChanged(lcdView, getString(
                    R.string.metric_lcd, status.lcdWrites));
            setTextIfChanged(frameMetricView, getString(
                    R.string.metric_frame, status.frameSequence));
            updateMetricsDescription();
            setTextIfChanged(inputView, getString(
                    R.string.metric_input, status.inputHostEvents));
            setTextIfChanged(rejectView, getString(
                    R.string.metric_reject, status.inputRejections,
                    status.audioUnderflowFrames, status.audioOverflowFrames,
                    status.audioEpoch, localAudioFailures,
                    status.audioRejectReason.isEmpty()
                            ? status.audioStatus : status.audioRejectReason));
            setTextIfChanged(jniView, getString(
                    R.string.metric_jni, latency(timing.dispatchMillis)));
            setTextIfChanged(ackView, getString(
                    R.string.metric_ack, latency(timing.ackMillis)));
        }
        if (!status.processRunning) {
            showError(getString(R.string.error_process_exited));
        }
    }

    private static int hardwareBit(int code) {
        if (code >= KeyEvent.KEYCODE_0 && code <= KeyEvent.KEYCODE_9) {
            int digit = code - KeyEvent.KEYCODE_0;
            return digit == 0 ? 21 : 10 + digit;
        }
        if (code >= KeyEvent.KEYCODE_NUMPAD_0 && code <= KeyEvent.KEYCODE_NUMPAD_9) {
            int digit = code - KeyEvent.KEYCODE_NUMPAD_0;
            return digit == 0 ? 21 : 10 + digit;
        }
        switch (code) {
            case KeyEvent.KEYCODE_DPAD_UP: return 1;
            case KeyEvent.KEYCODE_DPAD_DOWN: return 9;
            case KeyEvent.KEYCODE_DPAD_LEFT: return 4;
            case KeyEvent.KEYCODE_DPAD_RIGHT: return 6;
            case KeyEvent.KEYCODE_ENTER:
            case KeyEvent.KEYCODE_NUMPAD_ENTER: return 5;
            case KeyEvent.KEYCODE_ESCAPE: return 7;
            case KeyEvent.KEYCODE_PLUS:
            case KeyEvent.KEYCODE_NUMPAD_ADD: return 10;
            case KeyEvent.KEYCODE_MINUS:
            case KeyEvent.KEYCODE_NUMPAD_SUBTRACT: return 8;
            default: return -1;
        }
    }

    @Override
    public boolean dispatchKeyEvent(KeyEvent event) {
        String source = "keyboard:" + event.getDeviceId() + ":" + event.getKeyCode();
        if (event.getAction() == KeyEvent.ACTION_UP && inputSources.containsKey(source)) {
            releaseInput(source, session, true);
            return true;
        }
        int bit = event.getKeyCode() == KeyEvent.KEYCODE_EQUALS && event.isShiftPressed()
                ? 10 : hardwareBit(event.getKeyCode());
        BackendBridge.Session current = session;
        if (bit < 0 || current == null || editingInputMapping) {
            return super.dispatchKeyEvent(event);
        }
        if (event.getAction() == KeyEvent.ACTION_DOWN) {
            if (inputSources.containsKey(source)) return true;
            Integer mapped = manualKeyEvent(current.identity(), bit);
            if (mapped != null || current.supportsKey(bit)) {
                pressInput(source, current, bit, mapped);
            }
            return true;
        }
        return super.dispatchKeyEvent(event);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (!hasFocus) {
            releaseHeldKey(false);
            releaseKeyboardKeys();
        }
    }

    private void pressInput(String source, BackendBridge.Session current, int bit, Integer code) {
        if (inputSources.containsKey(source)) return;
        inputSources.put(source, bit);
        int count = inputCounts.containsKey(bit) ? inputCounts.get(bit) : 0;
        inputCounts.put(bit, count + 1);
        if (count == 0) {
            inputCodes.put(bit, code);
            sendSessionKey(current, bit, code, true, true);
        }
    }

    private void releaseInput(String source, BackendBridge.Session current, boolean reportFailure) {
        Integer bit = inputSources.remove(source);
        if (bit == null) return;
        int count = inputCounts.get(bit) - 1;
        if (count > 0) {
            inputCounts.put(bit, count);
        } else {
            inputCounts.remove(bit);
            Integer code = inputCodes.remove(bit);
            if (current != null) sendSessionKey(current, bit, code, false, reportFailure);
        }
    }

    private void releaseKeyboardKeys() {
        for (String source : new ArrayList<>(inputSources.keySet())) {
            if (source.startsWith("keyboard:")) releaseInput(source, session, false);
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
            if (editingInputMapping) {
                mappingTapBit = bit;
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
            pressInput("touch", current, bit, mapped);
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
            long executorStart = SystemClock.elapsedRealtimeNanos();
            android.util.Log.i("MSM5xxxInput", "executor_start bit=" + bit
                    + " pressed=" + pressed + " queue_us="
                    + (executorStart - probe.startNanos) / 1000L);
            try {
                if (!pressed) {
                    SystemClock.sleep(keyPressDuration.releaseDelayMillis(
                            target, bit, SystemClock.elapsedRealtimeNanos()));
                }
                target.setKey(bit, eventCode, pressed);
                if (pressed) {
                    keyPressDuration.pressed(target, bit, SystemClock.elapsedRealtimeNanos());
                }
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
        releaseInput("touch", current, reportFailure);
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
            controlExecutor.execute(() -> {
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
        stopSession(visible, null);
    }

    private void stopSession(boolean visible, Runnable afterStop) {
        int generation;
        BackendBridge.Session current;
        synchronized (sessionLifecycleLock) {
            generation = ++sessionGeneration;
            current = session;
            if (current != null && libraryScreen != null && frameView != null)
                libraryScreen.recordFrame(preferences().getString(KEY_URI, null), frameView.bitmap);
            releaseHeldKey(false);
            releaseKeyboardKeys();
            session = null;
            sessionStarting = false;
        }
        updateSessionKeepScreenOn(false, generation);
        autoStartToken = null;
        setInputMappingEditing(false);
        FrameUpdate staleFrame = pendingFrame.getAndSet(null);
        if (staleFrame != null) {
            staleFrame.recycle();
        }
        latestStatus = null;
        if (foldButton != null) { foldButton.setEnabled(true); foldButton.setAlpha(1f); }
        dismissSecondaryPresentation();
        secondaryPanel.setVisibility(View.GONE);
        secondaryFrameView.clear();
        updateKeypad(null);
        updateSessionControls(false);
        if (visible) {
            sessionView.setText(current == null
                    ? "" : getString(R.string.stopping_session));
        }
        if (current == null) {
            if (afterStop != null) afterStop.run();
            if (visible) {
                refreshSelection();
            }
            return;
        }
        // Drain previously queued edges (including release) before closing.
        // The barrier only submits work; close itself runs on the control worker.
        inputExecutor.execute(() -> controlExecutor.execute(() -> {
            boolean clean = true;
            try {
                current.close();
            } catch (IOException error) {
                clean = false;
            }
            boolean stoppedCleanly = clean;
            if (afterStop != null) handler.post(afterStop);
            if (visible) {
                handler.post(() -> {
                    if (generation == sessionGeneration && session == null) {
                        moreButton.announceForAccessibility(getString(R.string.powered_off_announcement));
                        sessionView.setText(stoppedCleanly
                                ? "" : getString(R.string.session_failed));
                        if (!stoppedCleanly) {
                            showError(getString(R.string.error_stop_failed));
                        }
                        refreshSelection();
                    }
                });
            }
        }));
    }

    private void updateSessionKeepScreenOn(boolean enabled, int generation) {
        Runnable update = () -> {
            if (generation != sessionGeneration
                    || (enabled && session == null)) {
                return;
            }
            if (enabled && activityResumed) {
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

    // Called by the session worker, including during Activity destruction.
    private void closeAfterKeys(BackendBridge.Session value) {
        try {
            inputExecutor.execute(() -> {
                try {
                    controlExecutor.execute(() -> closeQuietly(value));
                } catch (RejectedExecutionException destroyed) {
                    // The shutdown marker passed; all accepted edges drained.
                    closeQuietly(value);
                }
            });
        } catch (RejectedExecutionException destroyed) {
            // This is the session thread, never the UI thread. Destruction may
            // have shut down admission while accepted edges are still running.
            boolean interrupted = false;
            while (!inputExecutor.isTerminated()) {
                try {
                    inputExecutor.awaitTermination(30, TimeUnit.SECONDS);
                } catch (InterruptedException error) {
                    interrupted = true;
                }
            }
            closeQuietly(value);
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
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
            String model;
            if (!profile.isNull("verified_model")) {
                model = SelectionLabels.displayName(this, profile.getString("verified_model"));
            } else if (!profile.isNull("model")) {
                model = getString(R.string.model_unverified,
                        SelectionLabels.displayName(this, profile.getString("model")));
            } else {
                String filename = getSharedPreferences(PREFS, MODE_PRIVATE)
                        .getString(KEY_NAME, "");
                int extension = filename.lastIndexOf('.');
                String stem = extension > 0 ? filename.substring(0, extension) : filename;
                model = getString(R.string.model_unknown,
                        SelectionLabels.displayName(this, stem));
            }
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
        if (editingInputMapping) {
            setInputMappingEditing(false);
            return;
        }
        MenuSessionState actions = new MenuSessionState(session != null, sessionStarting, canStartSession);
        SharedPreferences prefs = preferences();
        PopupMenu popup = new PopupMenu(this, moreButton);
        android.view.Menu menu = popup.getMenu();
        menu.add(0, 101, 0, R.string.virtual_network_menu).setCheckable(true)
                .setChecked(prefs.getBoolean(KEY_VIRTUAL_NETWORK, false));
        menu.add(0, 102, 1, R.string.start).setEnabled(actions.start);
        menu.add(0, 103, 2, R.string.stop_emulator).setEnabled(actions.stop);
        menu.add(0, 104, 3, R.string.reboot_emulator).setEnabled(actions.reboot);
        menu.add(0, 105, 4, R.string.choose_firmware_menu);
        menu.add(0, 106, 5, R.string.capture).setEnabled(frameView.bitmap != null);
        menu.add(0, 107, 6, R.string.edit_key_input).setEnabled(session != null && !sessionStarting);
        android.view.SubMenu time = menu.addSubMenu(0, 108, 7, R.string.time_menu);
        time.add(1, 109, 0, R.string.host_time).setCheckable(true)
                .setChecked(prefs.getBoolean(KEY_NETWORK_HOST_TIME, true));
        time.add(1, 110, 1, R.string.set_time).setCheckable(true)
                .setChecked(!prefs.getBoolean(KEY_NETWORK_HOST_TIME, true));
        time.setGroupCheckable(1, true, true);
        menu.add(0, 111, 9, R.string.settings_menu);
        popup.setOnMenuItemClickListener(item -> {
            switch (item.getItemId()) {
                case 101:
                    prefs.edit().putBoolean(KEY_VIRTUAL_NETWORK,
                            !prefs.getBoolean(KEY_VIRTUAL_NETWORK, false)).apply();
                    restartIfRunning(); return true;
                case 102: startSession(); return true;
                case 103: stopSession(true); return true;
                case 104: stopSession(false); startSession(); return true;
                case 105:
                    if (session != null || sessionStarting) {
                        new AlertDialog.Builder(this).setMessage(R.string.confirm_firmware)
                                .setNegativeButton(R.string.cancel, null)
                                .setPositiveButton(android.R.string.ok, (dialog, which) -> returnToLibrary()).show();
                    } else returnToLibrary();
                    return true;
                case 106: saveCapture(); return true;
                case 107: setInputMappingEditing(true); return true;
                case 109:
                    prefs.edit().putBoolean(KEY_NETWORK_HOST_TIME, true).putString(KEY_NETWORK_START_TIME, "").apply();
                    if (prefs.getBoolean(KEY_VIRTUAL_NETWORK, false)) restartIfRunning();
                    return true;
                case 110: showNetworkTimeDialog(); return true;
                case 111: showSettings(); return true;
                case 112:
                    BackendBridge.Session current = session;
                    boolean host = prefs.getBoolean(KEY_NETWORK_HOST_TIME, true);
                    Double start = parseNetworkStartTime(prefs.getString(KEY_NETWORK_START_TIME, ""));
                    controlExecutor.execute(() -> {
                        try { if (current != null) current.refreshNetworkTime(host, start); }
                        catch (IOException error) { android.util.Log.e("MSM5xEmu", "Network time refresh failed", error); }
                    });
                    return true;
                default: return false;
            }
        });
        popup.show();
    }

    private void restartIfRunning() {
        if (session != null && !sessionStarting) {
            stopSession(false);
            startSession();
        }
    }

    private void showNetworkTimeDialog() {
        SharedPreferences prefs = preferences();
        NetworkTimePicker.show(this, prefs.getString(KEY_NETWORK_START_TIME, ""), value -> {
            prefs.edit().putBoolean(KEY_NETWORK_HOST_TIME, value.isEmpty())
                    .putString(KEY_NETWORK_START_TIME, value).apply();
            if (prefs.getBoolean(KEY_VIRTUAL_NETWORK, false)) restartIfRunning();
        });
    }

    private void setInputMappingEditing(boolean enabled) {
        boolean editing = enabled && session != null && !sessionStarting;
        if (editingInputMapping == editing) {
            return;
        }
        releaseHeldKey(false);
        releaseKeyboardKeys();
        editingInputMapping = editing;
        moreButton.setText(editing ? R.string.done_editing : R.string.more);
        moreButton.setTextSize(editing ? 11 : 20);
        moreButton.setContentDescription(editing ? getString(R.string.done_editing)
                : getString(R.string.more_actions) + ". " + getString(R.string.menu_hint));
        updateKeypad(session);
    }

    private static final int SAVE_CAPTURE = 73;

    private void saveCapture() {
        Bitmap bitmap = frameView.bitmap;
        if (bitmap == null) return;
        File file = CaptureProvider.captureFile(this);
        try (FileOutputStream output = new FileOutputStream(file)) {
            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)) throw new IOException("PNG encoding failed");
        } catch (IOException error) {
            showError(getString(R.string.error_capture));
            return;
        }
        new AlertDialog.Builder(this).setTitle(R.string.capture)
                .setItems(new String[]{getString(R.string.capture_share), getString(R.string.capture_save_as)},
                        (dialog, choice) -> {
            try {
                if (choice == 0) {
                    Uri uri = new Uri.Builder().scheme("content")
                            .authority(getPackageName() + ".capture").appendPath(CaptureProvider.NAME).build();
                    Intent share = new Intent(Intent.ACTION_SEND).setType("image/png")
                            .putExtra(Intent.EXTRA_STREAM, uri)
                            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    share.setClipData(android.content.ClipData.newRawUri("", uri));
                    startActivity(Intent.createChooser(share, getString(R.string.capture_share)));
                } else {
                    Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                            .setType("image/png").putExtra(Intent.EXTRA_TITLE, "capture.png");
                    startActivityForResult(save, SAVE_CAPTURE);
                }
            } catch (ActivityNotFoundException error) {
                showError(getString(R.string.error_no_picker));
            }
        }).show();
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != SAVE_CAPTURE || result != RESULT_OK || data == null || data.getData() == null) return;
        try (InputStream input = new FileInputStream(CaptureProvider.captureFile(this));
             OutputStream output = getContentResolver().openOutputStream(data.getData())) {
            if (output == null) throw new IOException("Destination unavailable");
            byte[] bytes = new byte[8192];
            int count;
            while ((count = input.read(bytes)) != -1) output.write(bytes, 0, count);
            Toast.makeText(this, getString(R.string.capture_saved, data.getData().toString()), Toast.LENGTH_LONG).show();
        } catch (IOException | SecurityException error) {
            showError(getString(R.string.error_capture));
        }
    }

    private void toggleFold() {
        BackendBridge.Session target = session;
        if (target == null || latestStatus == null || !latestStatus.foldSupported) return;
        boolean opened = !latestStatus.foldOpen;
        controlExecutor.execute(() -> {
            try {
                if (target != null) target.setFold(opened);
            } catch (IOException error) {
                android.util.Log.e("MSM5xxxSession", "Fold failed", error);
                handler.post(() -> {
                    if (session == target) showError(getString(R.string.error_input_failed));
                });
            }
        });
    }

    static Double parseNetworkStartTime(String value) {
        if (value.trim().isEmpty()) return null;
        java.text.SimpleDateFormat format = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US);
        format.setLenient(false);
        java.text.ParsePosition position = new java.text.ParsePosition(0);
        java.util.Date date = format.parse(value, position);
        if (date == null || position.getIndex() != value.length() || !format.format(date).equals(value)
                || date.getTime() < 315964800000L || date.getTime() >= 5813522920000L)
            throw new IllegalArgumentException("Invalid network time");
        return date.getTime() / 1000.0;
    }

    private static final String[] DETAIL_FIELDS = {"model", "chipset", "width", "height", "board_revision", "image_offset", "load_address", "flash_size", "ram_base", "ram_size", "ram_image_offset", "ram_image_size", "entry", "framebuffer_address", "framebuffer_stride", "framebuffer_format", "board_revision_register", "board_revision_value", "key_register", "key_active_low", "rex_idle_address", "rex_tick_address", "rex_tick_ms", "board_adc_value", "flash_id_address", "flash_id_value", "dmd_download_address", "primary_flash_probe_address", "secondary_flash_address", "secondary_flash_size", "secondary_flash_image", "secondary_flash_state", "secondary_flash_write_address", "flash_state", "nand_enabled", "nand_image", "nand_data_size", "nand_page_size", "nand_spare_size", "nand_pages_per_block", "nand_bus_width"};

    private void showSettings() {
        SharedPreferences preferences = preferences();
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(20);
        body.setPadding(padding, 0, padding, 0);
        body.addView(NetworkTimePicker.row(this, preferences.getString(KEY_NETWORK_START_TIME, ""), value -> {
            preferences.edit().putBoolean(KEY_NETWORK_HOST_TIME, value.isEmpty())
                    .putString(KEY_NETWORK_START_TIME, value).apply();
            if (preferences.getBoolean(KEY_VIRTUAL_NETWORK, false)) restartIfRunning();
        }), matchWidth());
        Switch persistent = new Switch(this);
        persistent.setText(R.string.persistent_state);
        persistent.setChecked(preferences.getBoolean(
                KEY_PERSISTENT_STATE, true));
        Switch experimental = new Switch(this);
        experimental.setText(R.string.experimental_rex);
        experimental.setChecked(preferences.getBoolean(
                KEY_EXPERIMENTAL_REX, false));
        body.addView(persistent, matchWidth());
        Switch background = new Switch(this);
        background.setText(R.string.keep_running_background);
        background.setChecked(preferences.getBoolean("keep_running_background", false));
        body.addView(background, matchWidth());
        TextView languageTitle = text(getString(R.string.ui_language), 14);
        body.addView(languageTitle, matchWidth());
        android.widget.Spinner language = new android.widget.Spinner(this);
        String[] languageValues = {"auto", "ko", "en"};
        String[] languageLabels = {getString(R.string.language_auto), getString(R.string.language_korean), getString(R.string.language_english)};
        language.setAdapter(new android.widget.ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, languageLabels));
        String selectedLanguage = preferences.getString("ui_language", "auto");
        language.setSelection("ko".equals(selectedLanguage) ? 1 : "en".equals(selectedLanguage) ? 2 : 0);
        body.addView(language, matchWidth());
        Switch secondary = new Switch(this);
        secondary.setText(R.string.additional_display);
        secondary.setChecked(!secondaryHidden);
        secondary.setEnabled(latestStatus != null && latestStatus.secondaryAvailable);
        secondary.setOnCheckedChangeListener((button, checked) -> {
            secondaryHidden = !checked;
            updateSecondaryPresentation();
        });
        body.addView(secondary, matchWidth());
        Button destination = new Button(this);
        destination.setText(R.string.display_destination);
        destination.setMinHeight(dp(48));
        destination.setOnClickListener(view -> chooseSecondaryDestination());
        body.addView(destination, matchWidth());
        String identity = null;
        try { identity = new JSONObject(preferences.getString(KEY_PROFILE, "{}"))
                    .getJSONObject("firmware").getString("sha256"); }
        catch (JSONException ignored) { }
        final String settingsIdentity = identity;
        body.addView(text(getString(R.string.detailed_settings), 16), matchWidth());
        if (settingsIdentity == null) body.addView(text(getString(R.string.profile_required), 14), matchWidth());
        experimental.setEnabled(settingsIdentity != null);
        body.addView(experimental, matchWidth());
        SharedPreferences detailPrefs = getSharedPreferences("detailed-settings", MODE_PRIVATE);
        JSONObject saved;
        try { saved = new JSONObject(settingsIdentity == null ? "{}" : detailPrefs.getString(settingsIdentity, "{}")); }
        catch (JSONException error) { saved = new JSONObject(); }
        final JSONObject initialDetails = saved;
        final boolean initialExperimental = experimental.isChecked();
        final boolean initialPersistent = persistent.isChecked();
        ArrayList<EditText> detailInputs = new ArrayList<>();
        String[] labels = getResources().getStringArray(R.array.detail_labels);
        String[] sections = getResources().getStringArray(R.array.detail_sections);
        int[] sectionStarts = {0, 5, 13, 16, 20, 28, 33};
        int section = 0;
        for (int index = 0; index < DETAIL_FIELDS.length; index++) {
            if (section < sectionStarts.length && index == sectionStarts[section]) {
                body.addView(text(sections[section++], 16), matchWidth());
            }
            TextView label = text(labels[index], 14);
            body.addView(label, matchWidth());
            EditText input = new EditText(this);
            input.setSingleLine(true);
            input.setText(saved.optString(DETAIL_FIELDS[index], ""));
            input.setHint(R.string.automatic_value);
            input.setEnabled(settingsIdentity != null);
            body.addView(input, matchWidth());
            detailInputs.add(input);
        }
        android.widget.ScrollView settingsScroll = new android.widget.ScrollView(this);
        settingsScroll.addView(body);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.settings_title)
                .setView(settingsScroll)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.save, null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
            boolean changed = initialExperimental != experimental.isChecked()
                    || initialPersistent != persistent.isChecked();
            if (settingsIdentity != null) {
                JSONObject edits = new JSONObject();
                try {
                    for (int i = 0; i < DETAIL_FIELDS.length; i++) {
                        String value = detailInputs.get(i).getText().toString().trim();
                        if (!value.equals(initialDetails.optString(DETAIL_FIELDS[i], "").trim())) changed = true;
                        if (!value.isEmpty()) edits.put(DETAIL_FIELDS[i], value);
                    }
                    detailPrefs.edit().putString(settingsIdentity, edits.toString()).apply();
                } catch (JSONException error) { showError(error.getMessage()); return; }
            }
            String newLanguage = languageValues[language.getSelectedItemPosition()];
            preferences.edit().putString("ui_language", newLanguage).putBoolean(KEY_PERSISTENT_STATE, persistent.isChecked())
                    .putBoolean(KEY_EXPERIMENTAL_REX, experimental.isChecked())
                    .putBoolean("keep_running_background", background.isChecked()).apply();
            dialog.dismiss();
            if (changed && session != null && !sessionStarting) {
                new AlertDialog.Builder(this).setMessage(R.string.apply_restart_prompt)
                        .setPositiveButton(R.string.apply_restart, (prompt, which) ->
                                stopSession(false, this::startSession))
                        .setNegativeButton(R.string.next_start, (prompt, which) -> {
                            if (!newLanguage.equals(selectedLanguage)) recreate();
                        }).show();
            } else if (!newLanguage.equals(selectedLanguage)) recreate();
        }));
        dialog.show();
        if (dialog.getWindow() != null) {
            dialog.getWindow().setLayout(WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.MATCH_PARENT);
        }
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
                button.setAlpha(1f);
                target.setContentDescription(spokenKeyLabel(key));
                continue;
            }
            boolean mapped = manualKeyEvent(active.identity(), key.bit) != null;
            boolean detected = !mapped && active.supportsKey(key.bit);
            if (editingInputMapping) {
                button.setAlpha(1f);
                target.setContentDescription(getString(
                        R.string.reassign_description,
                        spokenKeyLabel(key)));
                continue;
            }
            button.setAlpha(detected || mapped ? 1f : 0.72f);
            target.setContentDescription(getString(
                    mapped ? R.string.key_mapped_description
                            : detected ? R.string.key_detected_description
                            : R.string.key_mapping_description,
                    spokenKeyLabel(key)));
        }
    }

    private String spokenKeyLabel(KeySpec key) {
        switch (key.bit) {
            case 10: return getString(R.string.volume_up_spoken);
            case 8: return getString(R.string.volume_down_spoken);
            case 1: return getString(R.string.key_up_spoken);
            case 9: return getString(R.string.key_down_spoken);
            case 4: return getString(R.string.key_left_spoken);
            case 6: return getString(R.string.key_right_spoken);
            default: return getString(key.labelResource);
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
        moreButton.announceForAccessibility(message);
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

    private void updateMetricsDescription() {
        metricsGroup.setContentDescription(runView.getText() + ". " + pcView.getText() + ". "
                + lcdView.getText() + ". " + frameMetricView.getText());
    }

    private void resetMetrics() {
        pcView.setText(R.string.metric_pc_empty);
        runView.setText(R.string.metric_run_empty);
        lcdView.setText(R.string.metric_lcd_empty);
        frameMetricView.setText(R.string.metric_frame_empty);
        updateMetricsDescription();
        inputView.setText(R.string.metric_input_empty);
        rejectView.setText(R.string.metric_reject_empty);
        jniView.setText(R.string.metric_jni_empty);
        ackView.setText(R.string.metric_ack_empty);
    }

    private FrameLayout handsetTarget(Button button, int bit) {
        FrameLayout target = new FrameLayout(this);
        target.setMinimumHeight(dp(48));
        target.setEnabled(false);
        target.setClickable(true);
        target.setFocusable(true);
        target.setOnTouchListener((view, event) -> onKeyTouch(bit, event));
        target.setAccessibilityDelegate(new View.AccessibilityDelegate() {
            @Override public void onInitializeAccessibilityNodeInfo(View view, android.view.accessibility.AccessibilityNodeInfo info) {
                super.onInitializeAccessibilityNodeInfo(view, info);
                info.setClassName(Button.class.getName());
            }
        });
        target.setOnClickListener(view -> {
            BackendBridge.Session current = session;
            if (current == null) return;
            Integer mapped = manualKeyEvent(current.identity(), bit);
            if (editingInputMapping || (mapped == null && !current.supportsKey(bit))) {
                showKeyMapping(bit);
                return;
            }
            pressInput("accessibility", current, bit, mapped);
            releaseInput("accessibility", current, true);
        });
        FrameLayout.LayoutParams visual = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT, Gravity.CENTER);
        target.addView(button, visual);
        return target;
    }

    private Drawable menuButtonBackground() {
        StateListDrawable background = new StateListDrawable();
        int[][] states = {{-android.R.attr.state_enabled}, {android.R.attr.state_pressed}, {}};
        int[] colors = {Color.rgb(46, 46, 48), Color.rgb(112, 112, 116), Color.rgb(89, 88, 91)};
        for (int index = 0; index < states.length; index++) {
            GradientDrawable shape = new GradientDrawable();
            shape.setColor(colors[index]);
            shape.setCornerRadius(0);
            background.addState(states[index], shape);
        }
        return background;
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
                Color.rgb(46, 46, 48),
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
        TextView view = text(value, 10);
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
        private static final String LOG_TAG = "MSM5xxxFrame";
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
            int sequence = buffer.getInt();
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
            return new FramePacket(bitmap, visible, sequence);
        }

        // Transfer ownership on output changes, even if firmware pixels are static.
        void moveFrameTo(FrameView target) {
            if (bitmap == null) {
                return;
            }
            target.clear();
            target.bitmap = bitmap;
            bitmap = null;
            target.setContentDescription(getContentDescription());
            target.invalidate();
            invalidate();
        }

        void clear() {
            if (bitmap != null) {
                bitmap.recycle();
                bitmap = null;
                invalidate();
            }
        }

        void setFrame(FramePacket frame, int generation) {
            if (frame == null) {
                return;
            }
            Bitmap previous = bitmap;
            bitmap = frame.bitmap;
            setContentDescription(getContext().getString(R.string.phone_screen));
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
        private static final String LOG_TAG = "MSM5xxxAudio";
        private static final int SAMPLE_RATE = 44_100;
        private static final int FRAME_BYTES = 4;
        private static final int PREBUFFER_MILLIS = 60;
        private static final int BUFFER_MILLIS = 80;
        private static final int HEADER_BYTES = 32;
        private static final int PACKET_MAGIC = 0x3250354d;
        private static final int PACKET_BYTES = HEADER_BYTES
                + SAMPLE_RATE / 100 * FRAME_BYTES;
        private final ArrayBlockingQueue<PcmPacket> pending =
                new ArrayBlockingQueue<>(4);
        private final Thread worker;
        private volatile Thread producer;
        private volatile boolean closed;
        private volatile boolean disabled;
        private volatile AudioTrack activeTrack;
        private boolean firstPacketLogged;
        private long lastOfferNanos;
        private int cadenceLogs;
        private long localFailures;

        PcmAudioSink() {
            worker = new Thread(this::run, "msm5xxx-audio-output");
            worker.setDaemon(true);
            worker.start();
        }

        synchronized void start(BackendBridge.Session source) {
            if (closed || disabled || producer != null) {
                return;
            }
            producer = new Thread(() -> pump(source),
                    "msm5xxx-audio-input");
            producer.setDaemon(true);
            producer.start();
        }

        private void pump(BackendBridge.Session source) {
            try {
                while (!closed) {
                    if (!hasCapacity()) {
                        Thread.sleep(1);
                        continue;
                    }
                    byte[] pcm = source.audio();
                    if (pcm.length == 0) {
                        Thread.sleep(1);
                        continue;
                    }
                    offer(pcm);
                }
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            } catch (IOException | RuntimeException error) {
                disable();
            }
        }

        boolean hasCapacity() {
            return !closed && !disabled && pending.remainingCapacity() > 0;
        }

        void offer(byte[] pcm) {
            if (closed || disabled || pcm == null || pcm.length == 0) {
                return;
            }
            long offerNanos = SystemClock.elapsedRealtimeNanos();
            long offerGapMillis = lastOfferNanos == 0 ? 0
                    : TimeUnit.NANOSECONDS.toMillis(offerNanos - lastOfferNanos);
            lastOfferNanos = offerNanos;
            PcmPacket packet = PcmPacket.decode(pcm, offerGapMillis);
            if (packet == null) {
                disable();
                return;
            }
            if (!firstPacketLogged) {
                firstPacketLogged = true;
                android.util.Log.i(LOG_TAG, "first M5P2 packet epoch="
                        + packet.epoch + " sequence=" + packet.sequence
                        + " startFrame=" + packet.startFrame);
            }
            if (!pending.offer(packet)) {
                disable();
            }
        }

        private void run() {
            AudioTrack track = null;
            long writeFrame = 0;
            long epoch = 0;
            long sequence = 0;
            long spanStartFrame = -1;
            long spanStartNanos = 0;
            int prebufferFrames = 0;
            int underruns = 0;
            int underrunLogs = 0;
            boolean playing = false;
            try {
                android.os.Process.setThreadPriority(
                        android.os.Process.THREAD_PRIORITY_AUDIO);
                while (!closed) {
                    PcmPacket packet = pending.take();
                    if (closed) {
                        break;
                    }
                    if (packet.epoch != epoch) {
                        if (track == null) {
                            track = createTrack();
                            android.util.Log.i(LOG_TAG,
                                    "AudioTrack created epoch=" + packet.epoch);
                            if (!publishActiveTrack(track)) {
                                break;
                            }
                        } else {
                            track.pause();
                            track.flush();
                            android.util.Log.i(LOG_TAG,
                                    "AudioTrack resynced epoch=" + packet.epoch);
                        }
                        epoch = packet.epoch;
                        sequence = 0;
                        writeFrame = packet.startFrame;
                        spanStartFrame = packet.startFrame;
                        spanStartNanos = SystemClock.elapsedRealtimeNanos();
                        prebufferFrames = 0;
                        playing = false;
                    }
                    if (packet.sequence != sequence + 1
                            || packet.startFrame != writeFrame) {
                        throw new IllegalStateException("PCM sequence gap");
                    }
                    if (packet.offerGapMillis > 40 && cadenceLogs < 8) {
                        cadenceLogs++;
                        android.util.Log.i(LOG_TAG, "M5P2 ingress gapMs="
                                + packet.offerGapMillis + " epoch=" + epoch
                                + " sequence=" + packet.sequence
                                + " pending=" + pending.size());
                    }
                    int offset = HEADER_BYTES;
                    sequence = packet.sequence;
                    while (!closed && offset < packet.data.length) {
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
                            if (written % FRAME_BYTES != 0) {
                                throw new IllegalStateException(
                                        "unaligned AudioTrack write");
                            }
                            offset += written;
                            writeFrame += written / FRAME_BYTES;
                            if (!playing) {
                                prebufferFrames += written / FRAME_BYTES;
                                if (prebufferFrames >= SAMPLE_RATE
                                        * PREBUFFER_MILLIS / 1000) {
                                    track.play();
                                    playing = true;
                                    android.util.Log.i(LOG_TAG,
                                            "AudioTrack started epoch=" + epoch
                                            + " sequence=" + sequence
                                            + " writeFrame=" + writeFrame);
                                }
                            }
                        }
                    }
                    int currentUnderruns = track.getUnderrunCount();
                    if (currentUnderruns != underruns && underrunLogs < 8) {
                        underrunLogs++;
                        android.util.Log.i(LOG_TAG, "AudioTrack underruns="
                                + currentUnderruns + " delta="
                                + (currentUnderruns - underruns) + " epoch="
                                + epoch + " sequence=" + sequence
                                + " ingressGapMs=" + packet.offerGapMillis);
                    }
                    underruns = currentUnderruns;
                }
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException error) {
                android.util.Log.e(LOG_TAG, "PCM sink disabled", error);
                disable();
            } finally {
                if (spanStartFrame >= 0 && writeFrame >= spanStartFrame) {
                    android.util.Log.i(LOG_TAG, "AudioTrack span epoch=" + epoch
                            + " startFrame=" + spanStartFrame
                            + " writeFrame=" + writeFrame
                            + " elapsedNanos="
                            + (SystemClock.elapsedRealtimeNanos()
                            - spanStartNanos)
                            + " sequence=" + sequence
                            + " underruns=" + underruns);
                }
                clearActiveTrack(track);
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
                    .setBufferSizeInBytes(Math.max(minimum,
                            SAMPLE_RATE * FRAME_BYTES * BUFFER_MILLIS / 1000))
                    .setTransferMode(AudioTrack.MODE_STREAM)
                    .setPerformanceMode(AudioTrack.PERFORMANCE_MODE_LOW_LATENCY)
                    .build();
            if (track.getState() != AudioTrack.STATE_INITIALIZED) {
                releaseTrack(track);
                throw new IllegalStateException("AudioTrack init failed");
            }
            return track;
        }

        void disable() {
            AudioTrack track;
            Thread input;
            synchronized (this) {
                if (disabled || closed) {
                    return;
                }
                disabled = true;
                closed = true;
                localFailures++;
                pending.clear();
                track = activeTrack;
                input = producer;
            }
            pauseTrack(track);
            if (input != null) {
                input.interrupt();
            }
            worker.interrupt();
        }

        synchronized long failureCount() {
            return localFailures;
        }

        @Override
        public void close() {
            AudioTrack track;
            Thread input;
            synchronized (this) {
                closed = true;
                pending.clear();
                track = activeTrack;
                input = producer;
            }
            pauseTrack(track);
            if (input != null) {
                input.interrupt();
            }
            worker.interrupt();
            try {
                if (input != null) {
                    input.join(1_000);
                }
                worker.join(1_000);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            }
            if (worker.isAlive() || (input != null && input.isAlive())) {
                synchronized (this) {
                    localFailures++;
                }
            }
        }

        private synchronized boolean publishActiveTrack(AudioTrack track) {
            if (closed) {
                return false;
            }
            activeTrack = track;
            return true;
        }

        private synchronized void clearActiveTrack(AudioTrack track) {
            if (activeTrack == track) {
                activeTrack = null;
            }
        }

        private static void pauseTrack(AudioTrack track) {
            if (track == null) {
                return;
            }
            try {
                track.pause();
            } catch (IllegalStateException ignored) {
                // Audio-only teardown must not stop QEMU.
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
            final long epoch;
            final long sequence;
            final long startFrame;
            final long offerGapMillis;

            private PcmPacket(byte[] data, long epoch, long sequence,
                              long startFrame, long offerGapMillis) {
                this.data = data;
                this.epoch = epoch;
                this.sequence = sequence;
                this.startFrame = startFrame;
                this.offerGapMillis = offerGapMillis;
            }

            static PcmPacket decode(byte[] data, long offerGapMillis) {
                if (data.length != PACKET_BYTES) {
                    return null;
                }
                ByteBuffer header = ByteBuffer.wrap(data)
                        .order(ByteOrder.LITTLE_ENDIAN);
                if (header.getInt() != PACKET_MAGIC || header.getInt() != 2) {
                    return null;
                }
                long epoch = header.getLong();
                long sequence = header.getLong();
                long startFrame = header.getLong();
                long frames = (data.length - HEADER_BYTES) / FRAME_BYTES;
                if (epoch <= 0 || sequence <= 0 || startFrame < 0
                        || startFrame > Long.MAX_VALUE - frames) {
                    return null;
                }
                return new PcmPacket(data, epoch, sequence, startFrame,
                        offerGapMillis);
            }
        }
    }

    private static final class FramePacket {
        final Bitmap bitmap;
        final boolean nonBlank;
        final int sequence;

        FramePacket(Bitmap bitmap, boolean nonBlank, int sequence) {
            this.bitmap = bitmap;
            this.nonBlank = nonBlank;
            this.sequence = sequence;
        }

        void recycle() {
            bitmap.recycle();
        }
    }

    private static final class FrameUpdate {
        final int generation;
        final FramePacket frame;
        final FramePacket secondary;
        final BackendBridge.Status status;
        final InputTimingSnapshot timing;
        final long localAudioFailures;

        FrameUpdate(int generation, FramePacket frame, FramePacket secondary,
                    BackendBridge.Status status,
                    InputTimingSnapshot timing, long localAudioFailures) {
            this.generation = generation;
            this.frame = frame;
            this.secondary = secondary;
            this.status = status;
            this.timing = timing;
            this.localAudioFailures = localAudioFailures;
        }

        void recycle() {
            if (frame != null) {
                frame.recycle();
            }
            if (secondary != null) {
                secondary.recycle();
            }
        }

        void recycleExcept(FramePacket keepFrame, FramePacket keepSecondary) {
            if (frame != null && frame != keepFrame) {
                frame.recycle();
            }
            if (secondary != null && secondary != keepSecondary) {
                secondary.recycle();
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
