package org.msm5xxx.emulator

import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.UUID
import java.util.concurrent.Executors

/** Owns one capture and its export independently of an activity instance. */
class CaptureJob(private val savedState: SavedStateHandle) : ViewModel() {
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var cleared = false
    var state by mutableStateOf(savedState.get<Bundle>("capture_job") ?: Bundle())
        private set

    init {
        if (phase() == "encoding" || phase() == "writing") {
            publish("failed", state.getString("name"), state.getString("uri"), interrupted = true)
        }
    }

    private fun phase() = state.getString("phase", "idle")
    fun canCapture() = phase() == "idle"
    fun isChoice(name: String) = phase() == "choice" && state.getString("name") == name
    fun clear() = publish("idle")

    private fun publish(phase: String, name: String? = null, uri: String? = null, interrupted: Boolean = false) {
        if (cleared) return
        state = Bundle().apply {
            putString("phase", phase)
            putString("name", name)
            putString("uri", uri)
            putBoolean("interrupted", interrupted)
        }
        savedState["capture_job"] = state
    }

    fun prepare(context: Context, snapshot: Bitmap) {
        if (!canCapture()) { snapshot.recycle(); return }
        val app = context.applicationContext
        val name = "capture-${UUID.randomUUID()}.png"
        publish("encoding", name)
        io.execute {
            val file = File(app.cacheDir, name)
            val success = try {
                FileOutputStream(file).use { output ->
                    if (!snapshot.compress(Bitmap.CompressFormat.PNG, 100, output)) throw IOException("PNG encoding failed")
                }
                true
            } catch (_: IOException) {
                file.delete()
                false
            } catch (_: RuntimeException) {
                file.delete()
                false
            } finally {
                snapshot.recycle()
            }
            main.post { publish(if (success) "choice" else "failed", if (success) name else null) }
        }
    }

    fun beginPicker(name: String) {
        if (isChoice(name)) publish("picker", name)
    }

    fun destination(context: Context, destination: Uri?) {
        if (phase() != "picker") return
        if (destination == null) { clear(); return }
        val app = context.applicationContext
        val name = state.getString("name")
        publish("writing", name, destination.toString())
        io.execute {
            val success = try {
                FileInputStream(CaptureProvider.captureFile(app, name)).use { input ->
                    app.contentResolver.openOutputStream(destination, "wt").use { output ->
                        if (output == null) throw IOException("Destination unavailable")
                        input.copyTo(output)
                    }
                }
                true
            } catch (_: IOException) {
                false
            } catch (_: RuntimeException) {
                false
            }
            main.post { publish(if (success) "saved" else "failed", name, destination.toString()) }
        }
    }

    override fun onCleared() {
        cleared = true
        io.shutdown()
    }
}
