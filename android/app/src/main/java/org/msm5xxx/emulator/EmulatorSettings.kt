package org.msm5xxx.emulator

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.ListItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringArrayResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.json.JSONObject

private data class DetailSection(val label: String, val start: Int, val endExclusive: Int)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun EmulatorSettings(activity: MainActivity, onClose: () -> Unit) {
    val preferences = remember { activity.getSharedPreferences("launcher", android.content.Context.MODE_PRIVATE) }
    var networkStart by remember { mutableStateOf(preferences.getString("network_start_time", "").orEmpty()) }
    var networkHost by remember { mutableStateOf(preferences.getBoolean("network_host_time", true)) }
    DisposableEffect(preferences) {
        val listener = android.content.SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == "network_start_time" || key == "network_host_time") {
                networkStart = preferences.getString("network_start_time", "").orEmpty()
                networkHost = preferences.getBoolean("network_host_time", true)
            }
        }
        preferences.registerOnSharedPreferenceChangeListener(listener)
        onDispose { preferences.unregisterOnSharedPreferenceChangeListener(listener) }
    }
    val identity = remember { activity.settingsIdentity() }
    val fields = remember { activity.detailFields() }
    val labels = stringArrayResource(R.array.detail_labels)
    val sectionLabels = stringArrayResource(R.array.detail_sections)
    val starts = intArrayOf(0, 5, 13, 16, 20, 28, 33, fields.size)
    val sections = remember(sectionLabels, fields.size) {
        sectionLabels.indices.map { index ->
            DetailSection(sectionLabels[index], starts[index], starts[index + 1])
        }
    }
    val detailPrefs = remember { activity.getSharedPreferences("detailed-settings", android.content.Context.MODE_PRIVATE) }
    val initial = remember(identity) {
        try { JSONObject(if (identity == null) "{}" else detailPrefs.getString(identity, "{}") ?: "{}") }
        catch (_: Exception) { JSONObject() }
    }
    val valuesSaver = remember(identity) {
        listSaver<androidx.compose.runtime.snapshots.SnapshotStateList<String>, String>(
            save = { it.toList() },
            restore = { saved -> mutableStateListOf<String>().apply { addAll(saved) } }
        )
    }
    val values = rememberSaveable(identity, saver = valuesSaver) {
        mutableStateListOf<String>().apply {
            fields.forEach { field -> add(initial.optString(field, "")) }
        }
    }

    var sectionIndex by rememberSaveable { mutableStateOf<Int?>(null) }
    var languageMenu by remember { mutableStateOf(false) }
    var iconDialog by rememberSaveable { mutableStateOf(false) }
    var iconSimple by rememberSaveable { mutableStateOf(AppIconChoice.isSimple(activity)) }
    var language by rememberSaveable { mutableStateOf(preferences.getString("ui_language", "auto") ?: "auto") }
    var persistent by rememberSaveable { mutableStateOf(preferences.getBoolean("persistent_state", true)) }
    var experimental by rememberSaveable { mutableStateOf(preferences.getBoolean("experimental_rex", false)) }
    var background by rememberSaveable { mutableStateOf(preferences.getBoolean("keep_running_background", false)) }
    var secondary by remember { mutableStateOf(activity.secondaryVisible()) }
    val secondaryAvailable = activity.secondaryAvailable()

    val currentSection = sectionIndex?.let { sections.getOrNull(it) }
    BackHandler(enabled = sectionIndex != null) { sectionIndex = null }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val iconError = stringResource(R.string.app_icon_error)
    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(currentSection?.label ?: stringResource(R.string.settings_title)) },
                navigationIcon = {
                    IconButton(onClick = {
                        if (sectionIndex != null) sectionIndex = null else onClose()
                    }) {
                        Icon(painterResource(if (sectionIndex == null) R.drawable.ic_close else R.drawable.ic_arrow_back),
                            stringResource(if (sectionIndex == null) R.string.cancel else R.string.back))
                    }
                },
                actions = {
                    if (sectionIndex == null) {
                        TextButton(onClick = {
                            val details = JSONObject()
                            if (identity != null) {
                                fields.forEachIndexed { index, key ->
                                    val value = values[index].trim()
                                    if (value.isNotEmpty()) details.put(key, value)
                                }
                            }
                            activity.applyComposeSettings(details, persistent, experimental, background, language)
                            onClose()
                        }) { Text(stringResource(R.string.save)) }
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(0.dp)
        ) {
            if (currentSection == null) {
                ListItem(
                    headlineContent = { Text(stringResource(R.string.app_icon)) },
                    modifier = Modifier.clickable { iconDialog = true }
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.network_time)) },
                    supportingContent = {
                        val parsed = NetworkTimeValue.parse(networkStart)
                        Text(if (networkHost || parsed == null) stringResource(R.string.time_device_clock)
                            else NetworkTimeValue.display(parsed, activity.resources.configuration.locales[0]))
                    },
                    modifier = Modifier.clickable { activity.showNetworkTimeDialog() }
                )
                SettingToggle(R.string.persistent_state, persistent) { persistent = it }
                SettingToggle(R.string.experimental_rex, experimental, enabled = identity != null) { experimental = it }
                SettingToggle(R.string.keep_running_background, background) { background = it }
                ListItem(headlineContent = { Text(stringResource(R.string.ui_language)) }, trailingContent = {
                    Box {
                        TextButton(onClick = { languageMenu = true }) { Text(languageLabel(language)) }
                        DropdownMenu(expanded = languageMenu, onDismissRequest = { languageMenu = false }) {
                            listOf(
                                "auto" to R.string.language_auto,
                                "ko" to R.string.language_korean,
                                "en" to R.string.language_english
                            ).forEach { (value, label) ->
                                DropdownMenuItem(
                                    text = { Text(stringResource(label)) },
                                    onClick = { language = value; languageMenu = false }
                                )
                            }
                        }
                    }
                })
                SettingToggle(R.string.additional_display, secondary, enabled = secondaryAvailable) {
                    secondary = it
                    activity.setSecondaryVisible(it)
                }
                ListItem(
                    headlineContent = { Text(stringResource(R.string.display_destination)) },
                    modifier = Modifier.clickable {
                        activity.chooseSecondaryDestination()
                    }
                )

                ListItem(headlineContent = { Text(stringResource(R.string.detailed_settings)) })
                if (identity == null) {
                    ListItem(headlineContent = { Text(stringResource(R.string.profile_required)) })
                }
                sections.forEachIndexed { index, section ->
                    ListItem(
                        headlineContent = { Text(section.label) },
                        modifier = Modifier.clickable(enabled = identity != null) { sectionIndex = index }
                    )
                }
            } else {
                val sec = currentSection
                for (index in sec.start until minOf(sec.endExclusive, fields.size, labels.size)) {
                    val field = fields[index]
                    when (field) {
                        "key_active_low", "nand_enabled" -> HardwareChoiceField(
                            label = labels[index],
                            value = values[index],
                            choices = listOf(
                                "" to stringResource(R.string.automatic_value),
                                "true" to "true",
                                "false" to "false"
                            ),
                            enabled = identity != null,
                            onValueChange = { values[index] = it }
                        )
                        "framebuffer_format" -> HardwareChoiceField(
                            label = labels[index],
                            value = values[index],
                            choices = listOf(
                                "" to stringResource(R.string.automatic_value),
                                "none" to "none",
                                "rgb565le" to "rgb565le",
                                "bgr565le" to "bgr565le",
                                "rgb565be" to "rgb565be",
                                "bgr565be" to "bgr565be"
                            ),
                            enabled = identity != null,
                            onValueChange = { values[index] = it }
                        )
                        else -> OutlinedTextField(
                            value = values[index],
                            onValueChange = { values[index] = it },
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
                            enabled = identity != null,
                            label = { Text(labels[index]) },
                            placeholder = { Text(stringResource(R.string.automatic_value)) },
                            singleLine = true
                        )
                    }
                }
            }
        }
    }

    if (iconDialog) {
        AlertDialog(
            onDismissRequest = { iconDialog = false },
            title = { Text(stringResource(R.string.app_icon)) },
            text = {
                Column {
                    listOf(false to R.string.app_icon_full, true to R.string.app_icon_simple).forEach { (simple, label) ->
                        ListItem(
                            headlineContent = { Text(stringResource(label)) },
                            leadingContent = { RadioButton(selected = iconSimple == simple, onClick = null) },
                            modifier = Modifier.selectable(selected = iconSimple == simple, role = Role.RadioButton, onClick = { iconSimple = simple })
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (!AppIconChoice.setSimple(activity, iconSimple)) scope.launch { snackbar.showSnackbar(iconError) }
                    iconDialog = false
                }) { Text(stringResource(R.string.save)) }
            },
            dismissButton = {
                TextButton(onClick = { iconDialog = false }) { Text(stringResource(R.string.cancel)) }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HardwareChoiceField(
    label: String,
    value: String,
    choices: List<Pair<String, String>>,
    enabled: Boolean,
    onValueChange: (String) -> Unit
) {
    var expanded by remember(label) { mutableStateOf(false) }
    val displayValue = choices.firstOrNull { it.first == value }?.second ?: value
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { if (enabled) expanded = it },
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
        OutlinedTextField(
            value = displayValue,
            onValueChange = {},
            modifier = Modifier.fillMaxWidth().menuAnchor(),
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            enabled = enabled,
            readOnly = true,
            label = { Text(label) },
            singleLine = true
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            choices.forEach { (stored, shown) ->
                DropdownMenuItem(
                    text = { Text(shown) },
                    onClick = {
                        onValueChange(stored)
                        expanded = false
                    }
                )
            }
        }
    }
}

@Composable
private fun SettingToggle(label: Int, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    ListItem(
        headlineContent = { Text(stringResource(label)) },
        trailingContent = { Switch(checked = checked, onCheckedChange = null, enabled = enabled) },
        modifier = Modifier.toggleable(
            value = checked,
            enabled = enabled,
            role = Role.Switch,
            onValueChange = onChange
        )
    )
}

@Composable
private fun languageLabel(value: String): String = stringResource(
    when (value) {
        "ko" -> R.string.language_korean
        "en" -> R.string.language_english
        else -> R.string.language_auto
    }
)
