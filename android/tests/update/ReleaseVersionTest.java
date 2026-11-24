package org.msm5xxx.emulator;
public class ReleaseVersionTest {
    public static void main(String[] args) {
        if (!ReleaseVersion.newer("0.2.0","0.1.99")) throw new AssertionError();
        if (!ReleaseVersion.newer("0.2.0","0.2.0-rc")) throw new AssertionError();
        if (ReleaseVersion.newer("0.2.0","0.2.0") || ReleaseVersion.newer("0.2.0","0.3.0")) throw new AssertionError();
        for (String invalid : new String[]{"garbage","0.2","999999999999.0.0","0.2.0-rc"}) {
            try { ReleaseVersion.newer(invalid,"0.1.99"); throw new AssertionError(invalid); }
            catch (IllegalArgumentException expected) { }
        }
        System.out.println("8 version assertions passed");
    }
}
