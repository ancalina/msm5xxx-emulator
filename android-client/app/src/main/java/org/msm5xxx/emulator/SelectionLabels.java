package org.msm5xxx.emulator;

import android.content.Context;

final class SelectionLabels {
    private static final int MAX_NAME_CODE_POINTS = 120;

    private SelectionLabels() {}

    static String displayName(Context context, String source) {
        if (source == null || source.trim().isEmpty()) {
            return context.getString(R.string.unnamed_firmware);
        }
        StringBuilder clean = new StringBuilder();
        int count = 0;
        for (int offset = 0; offset < source.length()
                && count < MAX_NAME_CODE_POINTS; count++) {
            int codePoint = source.codePointAt(offset);
            offset += Character.charCount(codePoint);
            int type = Character.getType(codePoint);
            clean.append(Character.isISOControl(codePoint)
                    || type == Character.FORMAT ? '\uFFFD' :
                    new String(Character.toChars(codePoint)));
        }
        String result = clean.toString().trim();
        return result.isEmpty()
                ? context.getString(R.string.unnamed_firmware) : result;
    }

    static String size(Context context, long bytes) {
        return bytes < 0 ? context.getString(R.string.size_unavailable)
                : context.getString(R.string.size_bytes, bytes);
    }
}
