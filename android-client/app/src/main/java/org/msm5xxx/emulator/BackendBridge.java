package org.msm5xxx.emulator;

import android.content.Context;

import org.json.JSONException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Validated boundary for the pinned Python detector and shared QEMU transport. */
final class BackendBridge {
    private static final String QEMU_LIBRARY = "libqemu-system-arm.so";
    private static final String QEMU_VERSION = "QEMU emulator version 10.2.1";
    private static final String MACHINE = "msm5xxx-poc";
    private static final int OUTPUT_LIMIT = 64 * 1024;

    private BackendBridge() {}

    static Probe probeQemu(Context context) {
        final File qemu;
        try {
            qemu = resolveQemu(context);
        } catch (IOException error) {
            return Probe.failure(error.getMessage());
        }

        CommandResult version = run(qemu, "--version");
        if (!version.ok || !version.output.contains(QEMU_VERSION)) {
            return Probe.failure(version.timeout
                    ? "QEMU version probe timed out."
                    : "QEMU version probe failed.");
        }
        CommandResult machines = run(qemu, "-machine", "help");
        if (!machines.ok || !containsMachine(machines.output)) {
            return Probe.failure(machines.timeout
                    ? "QEMU machine probe timed out."
                    : "The MSM5xxx QEMU machine is unavailable.");
        }
        return new Probe(true, "QEMU 10.2.1 and msm5xxx-poc verified.");
    }

    static Probe probeDetectorRuntime(Context context) {
        try {
            JSONObject result = new JSONObject(PythonRuntime.probe(context));
            if (result.getInt("schema") != 1
                    || !"3.14.4".equals(result.getString("python"))
                    || !"2.1.4".equals(result.getString("unicorn"))
                    || !"2.5.1".equals(result.getString("numpy"))
                    || !result.getBoolean("unicorn_arm")
                    || !result.getBoolean("audio_renderer")
                    || !result.getBoolean("detector_entry")
                    || !result.getBoolean("gdb_remote")
                    || !result.getBoolean("qemu_transport")) {
                return Probe.failure("Python detector runtime validation failed.");
            }
            return new Probe(true, "CPython 3.14.4, Unicorn 2.1.4 ARM, "
                    + "the detector, and QEMU transport are verified.");
        } catch (IOException | JSONException | RuntimeException | LinkageError error) {
            return Probe.failure("Python detector runtime probe failed.");
        }
    }

    static Detection detect(Context context, File firmware) {
        try {
            JSONObject envelope = new JSONObject(PythonRuntime.detect(context, firmware));
            if (envelope.getInt("schema") != 1) {
                return Detection.failure("Detector result schema is unsupported.");
            }
            boolean accepted = envelope.getBoolean("accepted");
            JSONObject profile = envelope.getJSONObject("profile");
            String reject = envelope.isNull("reject_reason")
                    ? null : envelope.getString("reject_reason");
            if (!validProfile(profile)
                    || accepted != ("firmware".equals(profile.getString("image_kind"))
                    && !"MSM6050".equals(profile.getString("chipset")))
                    || accepted != (reject == null)) {
                return Detection.failure("Detector result validation failed.");
            }
            return new Detection(true, accepted, profile.toString(), reject,
                    null);
        } catch (IOException | JSONException | RuntimeException | LinkageError error) {
            return Detection.failure("Firmware detection failed.");
        }
    }

    private static boolean validProfile(JSONObject profile) throws JSONException {
        JSONObject firmware = profile.getJSONObject("firmware");
        String sha256 = firmware.getString("sha256");
        profile.getJSONArray("detection_notes");
        return sha256.matches("[0-9a-f]{64}")
                && firmware.getLong("bytes") > 0
                && !profile.getString("model").isEmpty()
                && !profile.getString("chipset").isEmpty()
                && !profile.getString("image_kind").isEmpty()
                && !profile.has("path")
                && !profile.has("flash_state")
                && !profile.has("secondary_flash_image")
                && !profile.has("secondary_flash_state")
                && !profile.has("upper_flash_state")
                && !profile.has("nand_image");
    }

    private static boolean containsMachine(String output) {
        for (String line : output.split("\\R")) {
            String value = line.trim();
            if (value.equals(MACHINE) || value.startsWith(MACHINE + " ")) {
                return true;
            }
        }
        return false;
    }

    private static File resolveQemu(Context context) throws IOException {
        File directory = new File(context.getApplicationInfo().nativeLibraryDir)
                .getCanonicalFile();
        File qemu = new File(directory, QEMU_LIBRARY).getCanonicalFile();
        if (!directory.equals(qemu.getParentFile()) || !qemu.isFile()
                || !qemu.canExecute()) {
            throw new IOException("QEMU executable is unavailable.");
        }
        return qemu;
    }

    private static CommandResult run(File executable, String... arguments) {
        String[] command = new String[arguments.length + 1];
        command[0] = executable.getPath();
        System.arraycopy(arguments, 0, command, 1, arguments.length);
        Process process;
        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().put("LD_LIBRARY_PATH", executable.getParent());
            process = builder.start();
        } catch (IOException | SecurityException error) {
            return CommandResult.failure(false);
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> drain(process.getInputStream(), output),
                "qemu-probe-output");
        reader.start();
        boolean exited;
        try {
            exited = process.waitFor(10, TimeUnit.SECONDS);
            if (!exited) {
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            }
            reader.join(2_000);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return CommandResult.failure(false);
        }
        String text = new String(output.toByteArray(), StandardCharsets.UTF_8);
        return new CommandResult(exited && process.exitValue() == 0, !exited, text);
    }

    private static void drain(InputStream input, ByteArrayOutputStream output) {
        byte[] buffer = new byte[4096];
        try (InputStream stream = input) {
            int read;
            while ((read = stream.read(buffer)) != -1) {
                int room = OUTPUT_LIMIT - output.size();
                if (room > 0) {
                    output.write(buffer, 0, Math.min(room, read));
                }
            }
        } catch (IOException ignored) {
            // The command result remains authoritative when its pipe closes early.
        }
    }

    static Session open(Context context, File firmware, String profileJson,
                        boolean persistentState, boolean experimentalRex)
            throws IOException {
        File qemu = resolveQemu(context);
        File state = persistentState
                ? new File(context.getNoBackupFilesDir(), "qemu-state")
                .getCanonicalFile() : null;
        try {
            JSONObject profile = new JSONObject(profileJson);
            String identity = profile.getJSONObject("firmware")
                    .getString("sha256");
            JSONObject result = new JSONObject(PythonRuntime.start(
                    context, firmware, qemu, state, profileJson,
                    experimentalRex));
            int width = result.getInt("width");
            int height = result.getInt("height");
            boolean[] inputBits = parseInputBits(result.getJSONArray("input_bits"));
            if (result.getInt("schema") != 1
                    || !result.getBoolean("process_running")
                    || !identity.equals(result.getString("state_identity"))
                    || result.getBoolean("persistent_state") != persistentState
                    || width < 1 || width > 2048
                    || height < 1 || height > 2048) {
                throw new IOException("Backend session validation failed.");
            }
            return new PythonSession(identity, inputBits);
        } catch (JSONException | RuntimeException | LinkageError error) {
            stopAfterFailedOpen();
            throw new IOException("Backend session launch failed.", error);
        } catch (IOException error) {
            stopAfterFailedOpen();
            throw error;
        }
    }

    private static boolean[] parseInputBits(JSONArray values)
            throws JSONException {
        if (values.length() > 23) {
            throw new JSONException("too many input bits");
        }
        boolean[] result = new boolean[23];
        for (int index = 0; index < values.length(); index++) {
            int bit = values.getInt(index);
            if (bit < 0 || bit >= result.length || result[bit]) {
                throw new JSONException("invalid input bit");
            }
            result[bit] = true;
        }
        return result;
    }

    private static void stopAfterFailedOpen() {
        try {
            PythonRuntime.stop();
        } catch (RuntimeException | LinkageError ignored) {
            // The original launch failure remains authoritative.
        }
    }

    interface Session extends AutoCloseable {
        byte[] frame() throws IOException;
        byte[] audio() throws IOException;
        Status status() throws IOException;
        String identity();
        boolean supportsKey(int bit);
        boolean canSetKey(int bit, Integer eventCode) throws IOException;
        void setKey(int bit, Integer eventCode, boolean pressed) throws IOException;
        @Override
        void close() throws IOException;
    }

    private static final class PythonSession implements Session {
        private final String identity;
        private final boolean[] inputBits;
        private volatile boolean closed;

        private PythonSession(String identity, boolean[] inputBits) {
            this.identity = identity;
            this.inputBits = inputBits;
        }

        @Override
        public synchronized byte[] frame() throws IOException {
            requireOpen();
            try {
                return PythonRuntime.frame();
            } catch (RuntimeException | LinkageError error) {
                throw new IOException("Backend frame read failed.", error);
            }
        }

        @Override
        public byte[] audio() throws IOException {
            requireOpen();
            try {
                return PythonRuntime.audio();
            } catch (RuntimeException | LinkageError error) {
                throw new IOException("Backend audio read failed.", error);
            }
        }

        @Override
        public synchronized Status status() throws IOException {
            requireOpen();
            try {
                JSONObject result = new JSONObject(PythonRuntime.status());
                if (result.getInt("schema") != 1) {
                    throw new JSONException("unsupported status schema");
                }
                return new Status(result.getBoolean("process_running"),
                        result.getLong("instructions"),
                        result.getLong("pc"),
                        result.getLong("lcd_writes"),
                        result.getLong("frame_sequence"),
                        result.getLong("input_host_events"),
                        result.getLong("input_rejections"));
            } catch (JSONException | RuntimeException | LinkageError error) {
                throw new IOException("Backend status read failed.", error);
            }
        }

        @Override
        public String identity() {
            return identity;
        }

        @Override
        public boolean supportsKey(int bit) {
            return bit >= 0 && bit < inputBits.length && inputBits[bit];
        }

        @Override
        public boolean canSetKey(int bit, Integer eventCode)
                throws IOException {
            requireOpen();
            try {
                JSONObject result = new JSONObject(PythonRuntime.canKey(
                        bit, eventCode));
                if (result.getInt("schema") != 1) {
                    throw new JSONException("unsupported input query schema");
                }
                return result.getBoolean("accepted");
            } catch (JSONException | RuntimeException | LinkageError error) {
                throw new IOException("Backend input query failed.", error);
            }
        }

        @Override
        public void setKey(int bit, Integer eventCode, boolean pressed)
                throws IOException {
            requireOpen();
            try {
                JSONObject result = new JSONObject(PythonRuntime.key(
                        bit, eventCode, pressed));
                if (result.getInt("schema") != 1
                        || !result.getBoolean("accepted")) {
                    throw new JSONException("input was not accepted");
                }
            } catch (JSONException | RuntimeException | LinkageError error) {
                throw new IOException("Backend input failed.", error);
            }
        }

        private void requireOpen() throws IOException {
            if (closed) {
                throw new IOException("Backend session is closed.");
            }
        }

        @Override
        public synchronized void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            try {
                PythonRuntime.stop();
            } catch (RuntimeException | LinkageError error) {
                throw new IOException("Backend stop failed.", error);
            }
        }
    }

    static final class Probe {
        final boolean available;
        final String message;

        private Probe(boolean available, String message) {
            this.available = available;
            this.message = message;
        }

        static Probe failure(String message) {
            return new Probe(false, message);
        }
    }

    static final class Detection {
        final boolean valid;
        final boolean accepted;
        final String profileJson;
        final String rejectReason;
        final String message;

        private Detection(boolean valid, boolean accepted, String profileJson,
                          String rejectReason, String message) {
            this.valid = valid;
            this.accepted = accepted;
            this.profileJson = profileJson;
            this.rejectReason = rejectReason;
            this.message = message;
        }

        static Detection failure(String message) {
            return new Detection(false, false, null, null, message);
        }
    }

    static final class Status {
        final boolean processRunning;
        final long instructions;
        final long pc;
        final long lcdWrites;
        final long frameSequence;
        final long inputHostEvents;
        final long inputRejections;

        private Status(boolean processRunning, long instructions, long pc,
                       long lcdWrites, long frameSequence, long inputHostEvents,
                       long inputRejections) {
            this.processRunning = processRunning;
            this.instructions = instructions;
            this.pc = pc;
            this.lcdWrites = lcdWrites;
            this.frameSequence = frameSequence;
            this.inputHostEvents = inputHostEvents;
            this.inputRejections = inputRejections;
        }
    }

    private static final class CommandResult {
        final boolean ok;
        final boolean timeout;
        final String output;

        private CommandResult(boolean ok, boolean timeout, String output) {
            this.ok = ok;
            this.timeout = timeout;
            this.output = output;
        }

        static CommandResult failure(boolean timeout) {
            return new CommandResult(false, timeout, "");
        }
    }
}
