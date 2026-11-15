package org.msm5xxx.emulator;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;

/** The enabled launcher alias is the source of truth, including after an app update. */
final class AppIconChoice {
    private AppIconChoice() { }

    static boolean isSimple(Context context) {
        return context.getPackageManager().getComponentEnabledSetting(component(context, "Simple"))
                == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
    }

    private static ComponentName component(Context context, String name) {
        return new ComponentName(context, context.getPackageName() + "." + name);
    }

    static boolean setSimple(Context context, boolean simple) {
        if (simple == isSimple(context)) return true;
        PackageManager manager = context.getPackageManager();
        String selected = simple ? "Simple" : "FullIcon";
        String previous = simple ? "FullIcon" : "Simple";
        try {
            manager.setComponentEnabledSetting(component(context, selected),
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP);
            manager.setComponentEnabledSetting(component(context, previous),
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
            return true;
        } catch (RuntimeException error) {
            manager.setComponentEnabledSetting(component(context, previous),
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP);
            manager.setComponentEnabledSetting(component(context, selected),
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
            return false;
        }
    }
}
