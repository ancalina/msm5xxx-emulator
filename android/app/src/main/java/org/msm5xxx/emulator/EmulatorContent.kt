package org.msm5xxx.emulator

import android.view.View
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.SystemBarStyle
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.toggleableState
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import java.util.function.Consumer
import java.util.function.IntConsumer

/** Material menus and dialogs around the handset renderer and touch surface. */
internal class EmulatorContent private constructor(private val activity: MainActivity, private val handset: View) {
    private var title by mutableStateOf("")
    private var status by mutableStateOf("")
    private var error by mutableStateOf<String?>(null)
    private var canStart by mutableStateOf(false)
    private var running by mutableStateOf(false)
    private var starting by mutableStateOf(false)
    private var editing by mutableStateOf(false)
    private var menu by mutableStateOf(false)
    private var timeMenu by mutableStateOf(false)
    private var virtualNetwork by mutableStateOf(false)
    private var settings by mutableStateOf(false)
    private var modal by mutableStateOf<Modal?>(null)
    private var notice by mutableStateOf<String?>(null)
    private val snackbar = SnackbarHostState()
    val hasModal: Boolean get() = menu || timeMenu || settings || modal != null

    fun restore(state: android.os.Bundle?) {
        settings = state?.getBoolean("settings_open", false) ?: false
        if (state == null) return
        when (state.getString("editor_kind")) {
            "mapping" -> activity.restoreKeyMapping(state.getString("editor_identity"), state.getInt("editor_bit", -1))
            "network-time" -> activity.restoreNetworkTime(state.getString("editor_initial", ""))
        }
    }
    fun save(state: android.os.Bundle) {
        state.putBoolean("settings_open", settings)
        when (val value = modal) {
            is Modal.Input -> {
                state.putString("editor_kind", "mapping")
                state.putString("editor_identity", value.identity)
                state.putInt("editor_bit", value.bit)
            }
            is Modal.NetworkTime -> {
                state.putString("editor_kind", "network-time")
                state.putString("editor_initial", value.initial)
            }
            else -> state.remove("editor_kind")
        }
    }
    fun update(model: String, state: String, ready: Boolean, active: Boolean, busy: Boolean, edit: Boolean) {
        virtualNetwork = activity.getSharedPreferences("launcher", android.content.Context.MODE_PRIVATE).getBoolean("virtual_network", false)
        title = model; status = state; canStart = ready; running = active; starting = busy; editing = edit
    }
    fun showError(message: String) { error = message }
    fun notify(message: String) { notice = message }
    fun clearError() { error = null }
    fun showActions() { menu = true }
    fun showSettings() { settings = true }
    fun networkTime(initial: String, action: Consumer<String>) { modal = Modal.NetworkTime(initial, action) }
    fun message(title: String, body: String) { modal = Modal.Message(title, body) }
    fun confirm(title: String, body: String, positive: String, action: Runnable) {
        modal = Modal.Confirm(title, body, positive, action)
    }
    @JvmOverloads
    fun choose(title: String, labels: Array<String>, selected: Int, action: IntConsumer, onDismiss: Runnable = Runnable {}) {
        modal = Modal.Choice(title, labels.toList(), selected, action, onDismiss)
    }
    fun input(identity: String, bit: Int, title: String, label: String, initial: String,
              validate: java.util.function.Function<String, String?>, action: Consumer<String>) {
        modal = Modal.Input(identity, bit, title, label, initial, validate, action)
    }

    @Composable
    private fun Screen() {
        val captureJob = activity.captureJob()
        val capture = captureJob.state
        LaunchedEffect(capture, hasModal) {
            when (capture.getString("phase", "idle")) {
                "choice" -> if (!hasModal) activity.showCaptureChoice(capture.getString("name"))
                "saved" -> {
                    captureJob.clear()
                    notify(activity.getString(R.string.capture_saved, capture.getString("uri")))
                }
                "failed" -> {
                    captureJob.clear()
                    showError(activity.getString(if (capture.getBoolean("interrupted")) R.string.capture_interrupted else R.string.error_capture))
                }
            }
        }
        notice?.let { text -> LaunchedEffect(text) { snackbar.showSnackbar(text); notice = null } }
        Scaffold(containerColor = androidx.compose.ui.graphics.Color.Black, snackbarHost = { SnackbarHost(snackbar) }) { insets ->
            Box(Modifier.fillMaxSize().padding(insets)) {
                AndroidView(factory = { handset }, modifier = Modifier.fillMaxSize())
                Column(Modifier.fillMaxWidth()) {
                    if (status.isNotEmpty() && !running) {
                        Surface {
                            Column(Modifier.fillMaxWidth()) {
                                if (starting || status == stringResource(R.string.detecting_firmware)
                                    || status == stringResource(R.string.copying_firmware)
                                    || status == stringResource(R.string.preparing_emulator))
                                    LinearProgressIndicator(Modifier.fillMaxWidth())
                                Text(status, Modifier.padding(horizontal = 16.dp, vertical = 8.dp), style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                    error?.let { text ->
                        ListItem(headlineContent = { Text(text, color = MaterialTheme.colorScheme.error) },
                            trailingContent = { TextButton(onClick = { error = null }) { Text(stringResource(android.R.string.ok)) } })
                    }
                }
                // This rectangle matches the handset's wider bottom-left key.
                Box(Modifier.align(Alignment.BottomStart).fillMaxWidth(1f / 3f).height(48.dp)) {
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        val actions = listOf(
                            Triple(if (running || starting) 103 else 102, if (running || starting) R.string.stop_emulator else R.string.start, running || starting || canStart),
                            Triple(104, R.string.reboot_emulator, running && !starting),
                            Triple(106, R.string.capture, activity.hasFrame()),
                            Triple(114, R.string.additional_display, true),
                            Triple(115, R.string.library_info, true),
                            Triple(101, R.string.virtual_network_menu, true),
                            Triple(108, R.string.network_time, true),
                            Triple(107, R.string.edit_key_input, running && !starting),
                            Triple(111, R.string.settings_title, true),
                            Triple(105, R.string.back_to_library, true),
                        )
                        actions.forEach { (id, label, enabled) ->
                            DropdownMenuItem(text = { Text(stringResource(label)) }, enabled = enabled,
                                modifier = if (id == 101) Modifier.semantics {
                                    role = Role.Checkbox
                                    toggleableState = if (virtualNetwork) ToggleableState.On else ToggleableState.Off
                                } else Modifier,
                                trailingIcon = {
                                    if (id == 101 && virtualNetwork) Icon(painterResource(R.drawable.ic_check), null)
                                },
                                onClick = {
                                    if (menu) {
                                        menu = false
                                        if (id == 108) timeMenu = true else activity.performAction(id)
                                    }
                                })
                        }
                    }
                    DropdownMenu(expanded = timeMenu, onDismissRequest = { timeMenu = false }) {
                        val host = activity.getSharedPreferences("launcher", android.content.Context.MODE_PRIVATE)
                            .getBoolean("network_host_time", true)
                        listOf(R.string.time_device_clock, R.string.time_set_manually, R.string.refresh_network_time)
                            .forEachIndexed { index, label ->
                                DropdownMenuItem(text = { Text(stringResource(label)) },
                                    modifier = if (index < 2) Modifier.semantics {
                                        role = Role.RadioButton
                                        toggleableState = if ((index == 0 && host) || (index == 1 && !host)) ToggleableState.On else ToggleableState.Off
                                    } else Modifier,
                                    trailingIcon = {
                                        if ((index == 0 && host) || (index == 1 && !host)) Icon(painterResource(R.drawable.ic_check), null)
                                    },
                                    onClick = { if (timeMenu) { timeMenu = false; activity.networkTimeAction(index) } })
                            }
                    }
                }
            }
        }
        if (settings) Dialog(onDismissRequest = { settings = false }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            AppTheme { EmulatorSettings(activity) { settings = false } }
        }
        modal?.let { value ->
            when (value) {
                is Modal.Message -> AlertDialog(onDismissRequest = { modal = null }, title = { Text(value.title) },
                    text = { androidx.compose.foundation.text.selection.SelectionContainer {
                        Text(value.body, Modifier.verticalScroll(rememberScrollState()))
                    } },
                    confirmButton = { TextButton(onClick = { modal = null }) { Text(stringResource(android.R.string.ok)) } })
                is Modal.Confirm -> AlertDialog(onDismissRequest = { modal = null }, title = { Text(value.title) }, text = { Text(value.body) },
                    confirmButton = { TextButton(onClick = { modal = null; value.action.run() }) { Text(value.positive) } },
                    dismissButton = { TextButton(onClick = { modal = null }) { Text(stringResource(R.string.cancel)) } })
                is Modal.Choice -> AlertDialog(onDismissRequest = { modal = null; value.onDismiss.run() }, title = { Text(value.title) },
                    text = {
                        Column(Modifier.verticalScroll(rememberScrollState())) {
                            value.labels.forEachIndexed { index, label ->
                                ListItem(headlineContent = { Text(label) },
                                    leadingContent = { if (value.selected >= 0) RadioButton(selected = index == value.selected, onClick = null) },
                                    modifier = Modifier.fillMaxWidth().then(Modifier.choiceClick { modal = null; value.action.accept(index) }))
                            }
                        }
                    }, confirmButton = {}, dismissButton = { TextButton(onClick = { modal = null; value.onDismiss.run() }) { Text(stringResource(R.string.cancel)) } })
                is Modal.Input -> InputDialog(value)
                is Modal.NetworkTime -> NetworkTimeDialog(value.initial, onDismiss = { modal = null }) {
                    modal = null
                    value.action.accept(it)
                }
            }
        }
    }

    @Composable
    private fun InputDialog(value: Modal.Input) {
        var text by rememberSaveable(value.identity, value.bit) { mutableStateOf(value.initial) }
        var validation by rememberSaveable(value.identity, value.bit) { mutableStateOf<String?>(null) }
        AlertDialog(onDismissRequest = { modal = null }, title = { Text(value.title) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(value.label)
                    OutlinedTextField(value = text, onValueChange = { text = it; validation = null },
                        label = { Text(value.title) }, singleLine = true, isError = validation != null,
                        supportingText = { validation?.let { Text(it) } }, modifier = Modifier.fillMaxWidth())
                }
            },
            confirmButton = { TextButton(onClick = {
                validation = value.validate.apply(text)
                if (validation == null) { modal = null; value.action.accept(text) }
            }) { Text(stringResource(R.string.save)) } },
            dismissButton = { TextButton(onClick = { modal = null }) { Text(stringResource(R.string.cancel)) } })
    }

    private sealed interface Modal {
        data class NetworkTime(val initial: String, val action: Consumer<String>) : Modal
        data class Message(val title: String, val body: String) : Modal
        data class Confirm(val title: String, val body: String, val positive: String, val action: Runnable) : Modal
        data class Choice(val title: String, val labels: List<String>, val selected: Int, val action: IntConsumer, val onDismiss: Runnable) : Modal
        data class Input(val identity: String, val bit: Int, val title: String, val label: String, val initial: String,
            val validate: java.util.function.Function<String, String?>, val action: Consumer<String>) : Modal
    }

    companion object {
        @JvmStatic fun install(activity: MainActivity, handset: View): EmulatorContent {
            activity.enableEdgeToEdge(
                statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
                navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.BLACK),
            )
            return EmulatorContent(activity, handset).also { content ->
                activity.setContent { AppTheme { content.Screen() } }
            }
        }
    }
}

private fun Modifier.choiceClick(action: () -> Unit) = clickable(onClick = action)
