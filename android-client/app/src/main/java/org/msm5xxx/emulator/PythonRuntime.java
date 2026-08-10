package org.msm5xxx.emulator;

import android.content.Context;
import android.system.ErrnoException;
import android.system.Os;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** Official CPython asset layout and the one detector JSON seam. */
final class PythonRuntime {
    private static File home;

    static {
        System.loadLibrary("msm5xxx_python");
    }

    private PythonRuntime() {}

    static synchronized String probe(Context context) throws IOException {
        File pythonHome = prepare(context);
        File state = new File(context.getNoBackupFilesDir(), "backend-state");
        if (!state.isDirectory() && !state.mkdirs()) {
            throw new IOException("state directory unavailable");
        }
        try {
            Os.setenv("TMPDIR", context.getCacheDir().getPath(), true);
        } catch (ErrnoException error) {
            throw new IOException("temporary directory unavailable", error);
        }
        return nativeProbe(pythonHome.getPath(),
                context.getApplicationInfo().nativeLibraryDir, state.getPath());
    }

    static synchronized String detect(Context context, File firmware)
            throws IOException {
        if (home == null) {
            probe(context);
        }
        return nativeDetect(firmware.getPath());
    }

    static synchronized String start(Context context, File firmware, File qemu,
                                     File stateDirectory, String profileJson,
                                     boolean experimentalRex)
            throws IOException {
        if (home == null) {
            probe(context);
        }
        try {
            JSONObject request = new JSONObject()
                    .put("firmware", firmware.getPath())
                    .put("profile", new JSONObject(profileJson))
                    .put("qemu", qemu.getPath())
                    .put("state", stateDirectory == null
                            ? JSONObject.NULL : stateDirectory.getPath())
                    .put("experimental_rex", experimentalRex);
            return nativeStart(request.toString());
        } catch (JSONException error) {
            throw new IOException("session request is invalid", error);
        }
    }

    static synchronized byte[] frame() {
        return nativeFrame();
    }

    static synchronized String status() {
        return nativeStatus();
    }

    static String key(int bit, Integer eventCode, boolean pressed)
            throws IOException {
        try {
            JSONObject request = new JSONObject()
                    .put("bit", bit)
                    .put("event_code", eventCode == null
                            ? JSONObject.NULL : eventCode)
                    .put("pressed", pressed);
            return nativeKey(request.toString());
        } catch (JSONException error) {
            throw new IOException("input request is invalid", error);
        }
    }

    static String canKey(int bit, Integer eventCode)
            throws IOException {
        try {
            JSONObject request = new JSONObject()
                    .put("bit", bit)
                    .put("event_code", eventCode == null
                            ? JSONObject.NULL : eventCode);
            return nativeCanKey(request.toString());
        } catch (JSONException error) {
            throw new IOException("input query is invalid", error);
        }
    }

    static synchronized void stop() {
        nativeStop();
    }

    private static File prepare(Context context) throws IOException {
        if (home != null) {
            return home;
        }
        File target = new File(context.getFilesDir(), "python");
        deleteTree(target);
        extract(context, "python", context.getFilesDir());
        File cwd = new File(target, "cwd");
        if (!cwd.isDirectory() && !cwd.mkdirs()) {
            throw new IOException("runtime working directory unavailable");
        }
        home = target;
        return target;
    }

    private static void extract(Context context, String path, File targetRoot)
            throws IOException {
        String[] names = context.getAssets().list(path);
        if (names == null) {
            throw new IOException("runtime asset unavailable");
        }
        File directory = new File(targetRoot, path);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IOException("runtime directory unavailable");
        }
        for (String name : names) {
            String child = path + "/" + name;
            try (InputStream input = context.getAssets().open(child)) {
                String outputName = name.endsWith("-")
                        ? name.substring(0, name.length() - 1) : name;
                File outputFile = new File(directory, outputName);
                try (FileOutputStream output = new FileOutputStream(outputFile)) {
                    byte[] buffer = new byte[64 * 1024];
                    int read;
                    while ((read = input.read(buffer)) != -1) {
                        output.write(buffer, 0, read);
                    }
                }
            } catch (FileNotFoundException directoryEntry) {
                extract(context, child, targetRoot);
            }
        }
    }

    private static void deleteTree(File file) throws IOException {
        if (!file.exists()) {
            return;
        }
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteTree(child);
            }
        }
        if (!file.delete()) {
            throw new IOException("stale runtime could not be replaced");
        }
    }

    private static native String nativeProbe(String home, String nativeDirectory,
                                             String stateDirectory);
    private static native String nativeDetect(String firmware);
    private static native String nativeStart(String request);
    private static native byte[] nativeFrame();
    private static native String nativeStatus();
    private static native String nativeCanKey(String request);
    private static native String nativeKey(String request);
    private static native String nativeStop();
}
