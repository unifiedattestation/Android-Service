package net.uattest.service;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Binder;

public class IdentityVerifier {
    public static void enforceCaller(Context context, String projectId) throws SecurityException {
        int uid = Binder.getCallingUid();
        PackageManager pm = context.getPackageManager();
        String[] packages = pm.getPackagesForUid(uid);
        if (packages == null) {
            throw new SecurityException("Unknown UID");
        }
        for (String pkg : packages) {
            if (pkg.equals(projectId)) {
                return;
            }
        }
        throw new SecurityException("Caller package does not match projectId");
    }
}
