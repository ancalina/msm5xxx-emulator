package org.msm5xxx.emulator

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import java.util.Calendar
import java.util.TimeZone

/** Date and time are edited as a draft; only Save changes the network clock. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun NetworkTimeDialog(initial: String, onDismiss: () -> Unit, onSave: (String) -> Unit) {
    val context = LocalContext.current
    val largeText = LocalDensity.current.fontScale > 1.5f
    val local = remember(initial) {
        Calendar.getInstance().apply { NetworkTimeValue.parse(initial)?.let { time = it } }
    }
    val utcDay = remember(initial) {
        Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply {
            clear()
            set(local.get(Calendar.YEAR).coerceIn(1980, 2100), local.get(Calendar.MONTH), local.get(Calendar.DAY_OF_MONTH))
        }.timeInMillis.coerceAtLeast(315964800000L)
    }
    val dates = rememberDatePickerState(
        initialSelectedDateMillis = utcDay,
        yearRange = 1980..2100,
        initialDisplayMode = if (largeText) DisplayMode.Input else DisplayMode.Picker,
        selectableDates = remember {
            object : SelectableDates {
                override fun isSelectableDate(utcTimeMillis: Long) = utcTimeMillis >= 315964800000L
            }
        },
    )
    val clock = rememberTimePickerState(
        initialHour = local.get(Calendar.HOUR_OF_DAY),
        initialMinute = local.get(Calendar.MINUTE),
        is24Hour = android.text.format.DateFormat.is24HourFormat(context),
    )
    var editingTime by rememberSaveable { mutableStateOf(false) }
    var keyboard by rememberSaveable { mutableStateOf(largeText) }
    var error by rememberSaveable { mutableStateOf(false) }

    if (!editingTime) {
        DatePickerDialog(
            onDismissRequest = onDismiss,
            confirmButton = {
                TextButton(enabled = dates.selectedDateMillis != null, onClick = { editingTime = true }) {
                    Text(stringResource(android.R.string.ok))
                }
            },
            dismissButton = {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { onSave("") }) { Text(stringResource(R.string.time_clear)) }
                    TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
                }
            },
        ) {
            DatePicker(state = dates)
        }
    } else {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.network_time)) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(Modifier.horizontalScroll(rememberScrollState())) {
                        if (keyboard) TimeInput(state = clock) else TimePicker(state = clock)
                    }
                    TextButton(onClick = { keyboard = !keyboard }) {
                        Text(stringResource(if (keyboard) R.string.time_dial_input else R.string.time_keyboard_input))
                    }
                    if (error) Text(stringResource(R.string.network_time_error), color = MaterialTheme.colorScheme.error)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val selected = Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply { timeInMillis = dates.selectedDateMillis!! }
                    val value = Calendar.getInstance().apply {
                        clear()
                        set(selected.get(Calendar.YEAR), selected.get(Calendar.MONTH), selected.get(Calendar.DAY_OF_MONTH), clock.hour, clock.minute)
                    }
                    val stored = NetworkTimeValue.stored(value.time)
                    if (NetworkTimeValue.parse(stored) != null && value.timeInMillis >= 315964800000L) onSave(stored)
                    else error = true
                }) { Text(stringResource(R.string.save)) }
            },
            dismissButton = { TextButton(onClick = { editingTime = false }) { Text(stringResource(R.string.back)) } },
        )
    }
}
