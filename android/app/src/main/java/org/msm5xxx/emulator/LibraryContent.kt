package org.msm5xxx.emulator

import android.app.Activity
import android.graphics.BitmapFactory
import androidx.activity.ComponentActivity
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import java.util.Locale
import java.util.function.IntConsumer

/** Compose presentation for the firmware index. The controller owns scanning and document access. */
class LibraryContent private constructor(
    private val activity: Activity,
    private val controller: FirmwareLibraryScreen,
) {
    private val entries = mutableStateListOf<JSONObject>()
    private var loading by mutableStateOf(false)
    private var message by mutableStateOf<String?>(null)
    private var scanIssueText by mutableStateOf<String?>(null)
    private var info by mutableStateOf<Pair<String, String>?>(null)
    private var choice by mutableStateOf<Choice?>(null)
    internal var confirmation by mutableStateOf<Confirmation?>(null)
    val view: ComposeView

    init {
        view = ComposeView(activity).apply {
            setContent {
                AppTheme {
                    LibraryScreen(this@LibraryContent)
                }
            }
        }
        activity.setContentView(view)
    }

    fun publish(rows: List<JSONObject>, isLoading: Boolean) {
        entries.clear()
        entries.addAll(rows.map { JSONObject(it.toString()) })
        loading = isLoading
    }

    fun showMessage(value: String) { message = value }
    fun setScanIssue(value: String?) { scanIssueText = value }
    fun showInfo(title: String, body: String) { info = title to body }
    fun choose(title: String, labels: Array<String>, callback: IntConsumer) {
        choice = Choice(title, labels.toList(), callback)
    }
    fun confirm(title: String, body: String, action: Runnable) {
        confirmation = Confirmation(title, body, action)
    }
    internal data class Confirmation(val title: String, val body: String, val action: Runnable)
    internal fun rows() = entries.toList()
    internal fun isLoading() = loading
    internal fun error() = message
    internal fun scanError() = scanIssueText
    internal fun clearError() { message = null }
    internal fun infoDialog() = info
    internal fun closeInfo() { info = null }
    internal fun choiceDialog() = choice
    internal fun closeChoice() { choice = null }
    internal fun onChoice(index: Int) { choice?.callback?.accept(index); choice = null }
    internal fun folder() = controller.chooseFolder()
    internal fun importFile() = controller.chooseImport()
    internal fun settings() = controller.openSettings()
    internal fun refresh() = controller.refresh()
    internal fun boot(row: JSONObject) = controller.select(row)
    internal fun showDetails(row: JSONObject) = controller.info(row)
    internal fun remove(row: JSONObject) = controller.requestRemove(row)

    internal data class Choice(val title: String, val labels: List<String>, val callback: IntConsumer)

    companion object {
        @JvmStatic
        fun install(activity: Activity, controller: Any): LibraryContent {
            require(activity is ComponentActivity) { "Compose requires ComponentActivity" }
            return LibraryContent(activity, controller as FirmwareLibraryScreen)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LibraryScreen(state: LibraryContent) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val rows = state.rows()
    val grouped = remember(rows) {
        rows.groupBy { row ->
            row.optString("model").trim().takeIf(String::isNotEmpty)?.lowercase(Locale.ROOT)
                ?: "file:${row.optString("uri")}"
        }.values.sortedWith(
            compareBy<List<JSONObject>> { it.first().optString("model").trim().isEmpty() }
                .thenBy { it.first().optString("model").trim().lowercase(Locale.ROOT) }
                .thenBy { it.first().optString("name").lowercase(Locale.ROOT) },
        )
    }
    var menuExpanded by remember { mutableStateOf(false) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.library_title), maxLines = 1) },
                actions = {
                    IconButton(onClick = { menuExpanded = true }) {
                        Icon(painterResource(R.drawable.ic_add), context.getString(R.string.library_add))
                    }
                    DropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.library_add_folder)) },
                            onClick = { menuExpanded = false; state.folder() },
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.library_import)) },
                            onClick = { menuExpanded = false; state.importFile() },
                        )
                    }
                    IconButton(onClick = state::refresh) {
                        Icon(painterResource(R.drawable.ic_refresh), context.getString(R.string.library_refresh))
                    }
                    IconButton(onClick = state::settings) {
                        Icon(painterResource(R.drawable.ic_settings), context.getString(R.string.settings_title))
                    }
                },
            )
        },
    ) { insets ->
        Column(Modifier.fillMaxSize().padding(insets)) {
            if (state.isLoading()) LinearProgressIndicator(Modifier.fillMaxWidth())
            state.error()?.let { error ->
                ListItem(
                    headlineContent = { Text(error) },
                    trailingContent = { TextButton(onClick = state::clearError) { Text(stringResource(android.R.string.ok)) } },
                )
            }
            state.scanError()?.let { issue ->
                ListItem(
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                    headlineContent = { Text(issue) },
                    trailingContent = {
                        TextButton(onClick = state::refresh) { Text(stringResource(R.string.library_refresh)) }
                    },
                )
            }
            if (rows.isEmpty() && state.isLoading()) {
                Text(
                    stringResource(R.string.library_loading),
                    modifier = Modifier.align(Alignment.CenterHorizontally).padding(24.dp),
                    style = MaterialTheme.typography.bodyLarge,
                )
            } else if (rows.isEmpty() && state.scanError() != null) {
                Text(
                    stringResource(R.string.library_scan_empty_error),
                    modifier = Modifier.padding(24.dp),
                    style = MaterialTheme.typography.bodyLarge,
                )
            } else if (rows.isEmpty()) {
                Column(
                    Modifier.fillMaxSize().padding(24.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(stringResource(R.string.library_empty), style = MaterialTheme.typography.bodyLarge)
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp), horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(top = 16.dp)) {
                        Button(onClick = state::importFile) { Text(stringResource(R.string.library_import)) }
                        TextButton(onClick = state::folder) { Text(stringResource(R.string.library_add_folder)) }
                    }
                }
            } else {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(grouped, key = { group -> group.first().optString("model").ifEmpty { group.first().optString("uri") } }) { group ->
                        FirmwareRow(group, state)
                    }
                }
            }
        }
    }

    state.confirmation?.let { dialog ->
        AlertDialog(onDismissRequest = { state.confirmation = null }, title = { Text(dialog.title) },
            text = { Text(dialog.body, Modifier.verticalScroll(rememberScrollState())) },
            confirmButton = { TextButton(onClick = { state.confirmation = null; dialog.action.run() }) { Text(stringResource(R.string.library_remove)) } },
            dismissButton = { TextButton(onClick = { state.confirmation = null }) { Text(stringResource(R.string.cancel)) } })
    }
    state.infoDialog()?.let { (title, body) ->
        AlertDialog(
            onDismissRequest = state::closeInfo,
            title = { Text(title) },
            text = { androidx.compose.foundation.text.selection.SelectionContainer { Text(body, Modifier.verticalScroll(rememberScrollState())) } },
            confirmButton = { TextButton(onClick = state::closeInfo) { Text(stringResource(android.R.string.ok)) } },
        )
    }
    state.choiceDialog()?.let { dialog ->
        AlertDialog(
            onDismissRequest = state::closeChoice,
            title = { Text(dialog.title) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    dialog.labels.forEachIndexed { index, label ->
                        TextButton(onClick = { state.onChoice(index) }, modifier = Modifier.fillMaxWidth()) {
                            Text(label, modifier = Modifier.fillMaxWidth())
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = state::closeChoice) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
private fun FirmwareRow(group: List<JSONObject>, state: LibraryContent) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val entry = group.filter { it.optBoolean("available", false) }
        .maxByOrNull { it.optLong("last_booted", 0) }
        ?: group.maxByOrNull { it.optLong("last_booted", 0) }
        ?: return
    var moreExpanded by remember(entry.optString("uri")) { mutableStateOf(false) }
    val path = entry.optString("thumbnail").takeIf(String::isNotEmpty)
    // Every publish copies the rows, so keep the bitmap across publishes and stat the file off the main thread.
    val thumbnail = remember(path) { mutableStateOf<Pair<Long, android.graphics.Bitmap?>>(-1L to null) }
    LaunchedEffect(path, entry) {
        if (path == null) { thumbnail.value = -1L to null; return@LaunchedEffect }
        withContext(Dispatchers.IO) {
            val version = java.io.File(path).lastModified()
            if (version != thumbnail.value.first) thumbnail.value = version to BitmapFactory.decodeFile(path)
        }
    }
    val name = entry.optString("model").ifEmpty { entry.optString("display", entry.optString("name")) }
    val chipset = entry.optString("chipset", "—")
    val size = if (group.size > 1) {
        group.joinToString(" / ") { file ->
            file.optLong("size", -1).let { if (it < 0) context.getString(R.string.size_unavailable) else String.format(Locale.getDefault(), "%.1f MiB", it / 1048576.0) }
        }
    } else entry.optLong("size", -1).let { if (it < 0) context.getString(R.string.size_unavailable) else String.format(Locale.getDefault(), "%.1f MiB", it / 1048576.0) }
    val booted = entry.optLong("last_booted", 0).let {
        if (it == 0L) context.getString(R.string.library_never)
        else DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, context.resources.configuration.locales[0]).format(Date(it))
    }
    val available = entry.optBoolean("available", false)
    val chooseFile: (Int, Int) -> Unit = { action, index ->
        val selected = JSONObject(group[index].toString())
        when (action) {
            0 -> if (selected.optBoolean("available", false)) state.boot(selected)
                else state.showMessage(context.getString(R.string.library_unavailable))
            1 -> state.showDetails(selected)
            else -> state.remove(selected)
        }
    }
    val onAction: (Int) -> Unit = { action ->
        if (group.size == 1) chooseFile(action, 0)
        else state.choose(
            context.getString(R.string.library_files),
            group.map { file ->
                val fileName = file.optString("name")
                val fileSize = file.optLong("size", -1).let { if (it < 0) context.getString(R.string.size_unavailable) else String.format(Locale.getDefault(), "%.1f MiB", it / 1048576.0) }
                val lastBoot = file.optLong("last_booted", 0).let {
                    if (it == 0L) context.getString(R.string.library_never)
                    else DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, context.resources.configuration.locales[0]).format(Date(it))
                }
                val availability = if (file.optBoolean("available", false)) "" else " · ${context.getString(R.string.library_unavailable)}"
                val inspection = if (file.optBoolean("inspection_failed", false)) " · ${context.getString(R.string.library_inspection_failed)}" else ""
                "$fileName · $fileSize · $lastBoot$availability$inspection"
            }.toTypedArray(),
            java.util.function.IntConsumer { index -> chooseFile(action, index) },
        )
    }
    ListItem(
        modifier = Modifier.clickable(enabled = group.any { it.optBoolean("available", false) }) { onAction(0) }
            .semantics { contentDescription = context.getString(R.string.library_row, name, chipset, booted) },
        leadingContent = {
            val bitmap = thumbnail.value.second
            if (bitmap != null) {
                Image(bitmap.asImageBitmap(), null, Modifier.size(64.dp))
            } else {
                Icon(
                    painterResource(R.drawable.ic_phone),
                    null,
                    Modifier.size(64.dp).wrapContentSize(Alignment.Center),
                )
            }
        },
        headlineContent = { Text(name, maxLines = 1) },
        supportingContent = {
            Column {
                if (group.any { it.optBoolean("inspection_failed", false) }) {
                    Text(stringResource(R.string.library_inspection_failed))
                }
                Text("$chipset · $size", maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    "$booted${if (available) "" else " · ${context.getString(R.string.library_unavailable)}"}",
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        },
        trailingContent = {
            androidx.compose.foundation.layout.Box {
                IconButton(onClick = { moreExpanded = true }) {
                    Icon(painterResource(R.drawable.ic_more), context.getString(R.string.more_actions))
                }
                DropdownMenu(expanded = moreExpanded, onDismissRequest = { moreExpanded = false }) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.library_info)) },
                        onClick = { moreExpanded = false; onAction(1) },
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.library_remove)) },
                        onClick = { moreExpanded = false; onAction(2) },
                    )
                }
            }
        },
    )
}
