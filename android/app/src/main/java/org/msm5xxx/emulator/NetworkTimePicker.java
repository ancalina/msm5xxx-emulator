package org.msm5xxx.emulator;

import android.app.Activity;
import android.app.DatePickerDialog;
import android.app.TimePickerDialog;
import android.graphics.Color;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.util.Calendar;
import java.util.Date;
import java.util.function.Consumer;

final class NetworkTimePicker {
    private NetworkTimePicker() { }
    static void show(Activity activity, String stored, Consumer<String> changed) {
        Calendar date = Calendar.getInstance();
        Date parsed = NetworkTimeValue.parse(stored);
        if (parsed != null) date.setTime(parsed);
        Calendar min = Calendar.getInstance(); min.clear(); min.set(1980, Calendar.JANUARY, 6);
        Calendar max = Calendar.getInstance(); max.clear(); max.set(2100, Calendar.DECEMBER, 31, 23, 59);
        if (date.before(min)) date.setTime(min.getTime());
        if (date.after(max)) date.setTime(max.getTime());
        DatePickerDialog picker = new DatePickerDialog(activity, (view, year, month, day) -> {
            date.set(year, month, day);
            new TimePickerDialog(activity, (clock, hour, minute) -> {
                date.set(Calendar.HOUR_OF_DAY, hour); date.set(Calendar.MINUTE, minute);
                date.set(Calendar.SECOND, 0); date.set(Calendar.MILLISECOND, 0);
                String value = NetworkTimeValue.stored(date.getTime());
                try { MainActivity.parseNetworkStartTime(value); changed.accept(value); }
                catch (IllegalArgumentException error) {
                    new android.app.AlertDialog.Builder(activity).setMessage(R.string.network_time_error)
                            .setPositiveButton(android.R.string.ok, null).show();
                }
            }, date.get(Calendar.HOUR_OF_DAY), date.get(Calendar.MINUTE),
                    android.text.format.DateFormat.is24HourFormat(activity)).show();
        }, date.get(Calendar.YEAR), date.get(Calendar.MONTH), date.get(Calendar.DAY_OF_MONTH));
        picker.getDatePicker().setMinDate(min.getTimeInMillis());
        picker.getDatePicker().setMaxDate(max.getTimeInMillis());
        picker.setButton(DatePickerDialog.BUTTON_NEUTRAL, activity.getString(R.string.time_clear),
                (dialog, which) -> changed.accept(""));
        picker.show();
    }
    static LinearLayout row(Activity activity, String value, Consumer<String> changed) {
        int pad = Math.round(16 * activity.getResources().getDisplayMetrics().density);
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.VERTICAL); row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(pad, pad / 2, pad, pad / 2); row.setMinimumHeight(pad * 4);
        TextView title = new TextView(activity); title.setText(R.string.network_start_time);
        title.setTextSize(16); title.setTextColor(Color.WHITE); row.addView(title);
        TextView subtitle = new TextView(activity); subtitle.setTextSize(13);
        subtitle.setTextColor(Color.rgb(160, 160, 166)); row.addView(subtitle);
        final String[] current = {value};
        Runnable update = () -> {
            Date date = NetworkTimeValue.parse(current[0]);
            subtitle.setText(date == null ? activity.getString(R.string.time_off)
                    : NetworkTimeValue.display(date, activity.getResources().getConfiguration().getLocales().get(0)));
        };
        update.run();
        row.setOnClickListener(v -> show(activity, current[0], next -> {
            current[0] = next; update.run(); changed.accept(next);
        }));
        return row;
    }
}
