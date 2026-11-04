package org.msm5xxx.emulator;

import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

final class NetworkTimeValue {
    private NetworkTimeValue() { }
    static Date parse(String text) {
        if (text == null || text.isEmpty()) return null;
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
        format.setLenient(false);
        ParsePosition pos = new ParsePosition(0);
        Date date = format.parse(text, pos);
        if (date == null || pos.getIndex() != text.length() || !format.format(date).equals(text)) return null;
        Calendar calendar = Calendar.getInstance(); calendar.setTime(date);
        int year = calendar.get(Calendar.YEAR);
        if (year < 1980 || year > 2100 || (year == 1980 && calendar.get(Calendar.DAY_OF_YEAR) < 6)) return null;
        return date;
    }
    static String stored(Date date) {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(date);
    }
    static String display(Date date, Locale locale) {
        return java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM,
                java.text.DateFormat.SHORT, locale).format(date);
    }
}
