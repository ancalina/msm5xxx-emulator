package org.msm5xxx.emulator

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.launch
import androidx.compose.ui.unit.dp
import java.util.Locale

/** App-wide options and folders used by the firmware library. */
class SettingsActivity : ComponentActivity() {
    override fun attachBaseContext(base: Context) {
        val language = base.getSharedPreferences(PREFS, MODE_PRIVATE).getString("ui_language", "auto")
        if (language != null && language != "auto") {
            val configuration = android.content.res.Configuration(base.resources.configuration)
            configuration.setLocale(Locale.forLanguageTag(language))
            super.attachBaseContext(base.createConfigurationContext(configuration))
        } else {
            super.attachBaseContext(base)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { AppTheme { SettingsScreen() } }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun SettingsScreen() {
        val preferences = getSharedPreferences(PREFS, MODE_PRIVATE)
        var refresh by remember { mutableStateOf(0) }
        var showIcon by rememberSaveable { mutableStateOf(false) }
        var showTime by rememberSaveable { mutableStateOf(false) }
        var storedTimeText by rememberSaveable { mutableStateOf(preferences.getString("network_start_time", "").orEmpty()) }
        var language by rememberSaveable { mutableStateOf(preferences.getString("ui_language", "auto") ?: "auto") }
        var virtualNetwork by remember { mutableStateOf(preferences.getBoolean("virtual_network", false)) }

        val snackbar = remember { SnackbarHostState() }
        val scope = rememberCoroutineScope()
        val iconError = stringResource(R.string.app_icon_error)
        Scaffold(topBar = {
            TopAppBar(title = { Text(stringResource(R.string.settings_title)) }, navigationIcon = {
                IconButton(onClick = { finish() }) {
                    Icon(painterResource(R.drawable.ic_arrow_back), stringResource(R.string.back))
                }
            })
        }, snackbarHost = { SnackbarHost(snackbar) }) { insets ->
            Column(
                modifier = Modifier.fillMaxSize().padding(insets).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                SectionTitle(R.string.library_folders)
                val folders = remember(refresh) { FirmwareLibraryScreen.folders(this@SettingsActivity).toList() }
                if (folders.isEmpty()) {
                    ListItem(headlineContent = { Text(stringResource(R.string.library_no_folders)) })
                }
                folders.forEach { folder ->
                    ListItem(
                        headlineContent = { Text(folderLabel(folder)) },
                        trailingContent = {
                            TextButton(onClick = {
                                FirmwareLibraryScreen.removeFolder(this@SettingsActivity, folder)
                                refresh++
                            }) { Text(stringResource(R.string.library_remove_folder)) }
                        }
                    )
                }
                ListItem(
                    headlineContent = { Text(stringResource(R.string.library_add_folder)) },
                    modifier = Modifier.clickable { returnAction(ACTION_ADD_FOLDER) }
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.library_import)) },
                    modifier = Modifier.clickable { returnAction(ACTION_IMPORT_FILE) }
                )

                SectionTitle(R.string.app_icon)
                val currentIcon = if (AppIconChoice.isSimple(this@SettingsActivity)) R.string.app_icon_simple else R.string.app_icon_full
                ListItem(
                    headlineContent = { Text(stringResource(currentIcon)) },
                    modifier = Modifier.clickable { showIcon = true }
                )

                SectionTitle(R.string.library_session_settings)
                PreferenceSwitch(preferences, "virtual_network", false, R.string.virtual_network) { virtualNetwork = it }
                ListItem(
                    headlineContent = { Text(stringResource(R.string.network_time)) },
                    supportingContent = {
                        val parsed = NetworkTimeValue.parse(storedTimeText)
                        Text(if (parsed == null) stringResource(R.string.time_device_clock)
                        else NetworkTimeValue.display(parsed, resources.configuration.locales[0]))
                    },
                    modifier = Modifier.clickable(enabled = virtualNetwork) { showTime = true }
                )
                PreferenceSwitch(preferences, "persistent_state", true, R.string.persistent_state)
                PreferenceSwitch(preferences, "experimental_rex", false, R.string.experimental_rex)
                PreferenceSwitch(preferences, "keep_running_background", false, R.string.keep_running_background)

                SectionTitle(R.string.ui_language)
                LanguageChoice(language) { selected ->
                    language = selected
                    preferences.edit().putString("ui_language", selected).apply()
                    recreate()
                }
                HorizontalDivider()
            }
        }

        if (showIcon) {
            val initial = AppIconChoice.isSimple(this)
            IconChoiceDialog(initial, onDismiss = { showIcon = false }, onChoose = { simple ->
                if (!AppIconChoice.setSimple(this, simple)) scope.launch { snackbar.showSnackbar(iconError) }
                showIcon = false
            })
        }
        if (showTime) {
            NetworkTimeDialog(initial = storedTimeText, onDismiss = { showTime = false }) { stored ->
                preferences.edit().putBoolean("network_host_time", stored.isEmpty()).putString("network_start_time", stored).apply()
                storedTimeText = stored
                showTime = false
            }
        }
    }

    private fun returnAction(action: String) {
        setResult(RESULT_OK, Intent().putExtra(EXTRA_ACTION, action))
        finish()
    }



    private fun folderLabel(folder: String): String {
        val segment = Uri.parse(folder).lastPathSegment ?: folder
        val path = Uri.decode(segment)
        return if (path.contains(':')) path.substringAfter(':') else path
    }

    companion object {
        const val EXTRA_ACTION = "action"
        const val ACTION_ADD_FOLDER = "folder"
        const val ACTION_IMPORT_FILE = "file"
        private const val PREFS = "launcher"
    }
}

@Composable
private fun SectionTitle(resource: Int) {
    Text(
        text = stringResource(resource),
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.fillMaxWidth().padding(start = 16.dp, top = 18.dp, end = 16.dp, bottom = 6.dp)
    )
}

@Composable
private fun PreferenceSwitch(preferences: android.content.SharedPreferences, key: String, fallback: Boolean, label: Int, changed: (Boolean) -> Unit = {}) {
    var checked by remember(key) { mutableStateOf(preferences.getBoolean(key, fallback)) }
    ListItem(
        headlineContent = { Text(stringResource(label)) },
        trailingContent = {
            Switch(checked = checked, onCheckedChange = null)
        },
        modifier = Modifier.toggleable(
            value = checked,
            role = Role.Switch,
            onValueChange = {
                checked = it
                preferences.edit().putBoolean(key, it).apply()
                changed(it)
            }
        )
    )
}

@Composable
private fun LanguageChoice(selected: String, onSelected: (String) -> Unit) {
    val choices = listOf(
        "auto" to R.string.language_auto,
        "ko" to R.string.language_korean,
        "en" to R.string.language_english
    )
    choices.forEach { (value, label) ->
        ListItem(
            headlineContent = { Text(stringResource(label)) },
            leadingContent = { RadioButton(selected = selected == value, onClick = null) },
            modifier = Modifier.selectable(
                selected = selected == value,
                role = Role.RadioButton,
                onClick = { onSelected(value) }
            )
        )
    }
}

@Composable
private fun IconChoiceDialog(initial: Boolean, onDismiss: () -> Unit, onChoose: (Boolean) -> Unit) {
    var selected by rememberSaveable(initial) { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.app_icon)) },
        text = {
            Column {
                listOf(false to R.string.app_icon_full, true to R.string.app_icon_simple).forEach { (simple, label) ->
                    ListItem(
                        headlineContent = { Text(stringResource(label)) },
                        leadingContent = { RadioButton(selected = selected == simple, onClick = null) },
                        modifier = Modifier.selectable(selected = selected == simple, role = Role.RadioButton, onClick = { selected = simple })
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = { onChoose(selected) }) { Text(stringResource(R.string.save)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}
