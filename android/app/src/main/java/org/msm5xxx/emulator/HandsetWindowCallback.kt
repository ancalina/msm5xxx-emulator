package org.msm5xxx.emulator

import android.view.KeyEvent
import android.view.Window

/** Captures guest keys before Android focus traversal while preserving app shortcuts. */
internal class HandsetWindowCallback(
    private val original: Window.Callback,
    private val activity: MainActivity,
) : Window.Callback by original {
    override fun dispatchKeyEvent(event: KeyEvent): Boolean =
        activity.dispatchHandsetKeyEvent(event) || original.dispatchKeyEvent(event)
}
