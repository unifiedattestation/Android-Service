package net.uattest.service;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class UnifiedAttestationService extends Service {
    public static final int ERROR_INVALID_CALLER = 1;
    public static final int ERROR_RATE_LIMIT = 2;
    public static final int ERROR_BACKEND_NOT_FOUND = 3;
    public static final int ERROR_ATTESTATION_FAILED = 4;
    public static final int ERROR_NETWORK = 5;

    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final RateLimiter rateLimiter = new RateLimiter(20, 60_000);
    private List<BackendEntry> backends = new ArrayList<>();

    private final IUnifiedAttestationService.Stub binder = new IUnifiedAttestationService.Stub() {
        @Override
        public List<String> getProviderSet(String projectId) {
            try {
                IdentityVerifier.enforceCaller(UnifiedAttestationService.this, projectId);
            } catch (SecurityException e) {
                return new ArrayList<>();
            }
            List<String> ids = new ArrayList<>();
            for (BackendEntry entry : backends) {
                if (entry.enabled && entry.backendId != null) {
                    ids.add(entry.backendId);
                }
            }
            return ids;
        }

        @Override
        public void requestIntegrityToken(
                String backendId,
                String projectId,
                String requestHash,
                IIntegrityTokenCallback callback
        ) {
            int uid = Binder.getCallingUid();
            if (!rateLimiter.tryAcquire(uid)) {
                safeError(callback, ERROR_RATE_LIMIT, "Rate limit exceeded");
                return;
            }
            try {
                IdentityVerifier.enforceCaller(UnifiedAttestationService.this, projectId);
            } catch (SecurityException e) {
                safeError(callback, ERROR_INVALID_CALLER, e.getMessage());
                return;
            }
            executor.submit(() -> {
                try {
                    BackendEntry entry = findBackend(backendId);
                    if (entry == null || !entry.enabled) {
                        safeError(callback, ERROR_BACKEND_NOT_FOUND, "Backend not enabled");
                        return;
                    }
                    byte[] requestHashBytes = HexUtil.decode(requestHash);
                    String alias = "ua:" + projectId + ":" + backendId;
                    List<String> chain = KeyAttestationManager.getAttestationChain(
                            UnifiedAttestationService.this,
                            alias,
                            requestHashBytes
                    );
                    String token = UaHttp.postDeviceProcess(
                            entry.url,
                            projectId,
                            requestHash,
                            chain,
                            buildDeviceMeta()
                    );
                    safeSuccess(callback, token);
                } catch (Exception e) {
                    Log.e("UAService", "requestIntegrityToken failed", e);
                    safeError(callback, ERROR_ATTESTATION_FAILED, e.getMessage());
                }
            });
        }

        @Override
        public void requestIntegrityTokenWithChain(
                String backendId,
                String projectId,
                String requestHash,
                List<String> attestationChain,
                IIntegrityTokenCallback callback
        ) {
            int uid = Binder.getCallingUid();
            if (!rateLimiter.tryAcquire(uid)) {
                safeError(callback, ERROR_RATE_LIMIT, "Rate limit exceeded");
                return;
            }
            try {
                IdentityVerifier.enforceCaller(UnifiedAttestationService.this, projectId);
            } catch (SecurityException e) {
                safeError(callback, ERROR_INVALID_CALLER, e.getMessage());
                return;
            }
            executor.submit(() -> {
                try {
                    BackendEntry entry = findBackend(backendId);
                    if (entry == null || !entry.enabled) {
                        safeError(callback, ERROR_BACKEND_NOT_FOUND, "Backend not enabled");
                        return;
                    }
                    if (attestationChain == null || attestationChain.isEmpty()) {
                        safeError(callback, ERROR_ATTESTATION_FAILED, "Missing attestation chain");
                        return;
                    }
                    String token = UaHttp.postDeviceProcess(
                            entry.url,
                            projectId,
                            requestHash,
                            attestationChain,
                            buildDeviceMeta()
                    );
                    safeSuccess(callback, token);
                } catch (Exception e) {
                    Log.e("UAService", "requestIntegrityTokenWithChain failed", e);
                    safeError(callback, ERROR_ATTESTATION_FAILED, e.getMessage());
                }
            });
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        backends = BackendStore.load(this);
        executor.submit(this::resolveBackendIds);
        scheduleHealthChecks();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    private void resolveBackendIds() {
        boolean changed = false;
        for (BackendEntry entry : backends) {
            if (entry.backendId == null) {
                try {
                    BackendInfo info = UaHttp.fetchBackendInfo(entry.url);
                    entry.backendId = info.backendId;
                    entry.lastStatus = "ok";
                    entry.lastCheckedAt = System.currentTimeMillis();
                    changed = true;
                } catch (Exception e) {
                    entry.lastStatus = "unreachable";
                    entry.lastCheckedAt = System.currentTimeMillis();
                    Log.w("UAService", "Failed to resolve backendId for " + entry.url, e);
                }
            }
        }
        if (changed) {
            BackendStore.save(this, backends);
        }
    }

    private BackendEntry findBackend(String backendId) {
        for (BackendEntry entry : backends) {
            if (backendId != null && backendId.equals(entry.backendId)) {
                return entry;
            }
        }
        return null;
    }

    private void scheduleHealthChecks() {
        executor.submit(() -> {
            while (true) {
                try {
                    Thread.sleep(15 * 60 * 1000L);
                } catch (InterruptedException ignored) {
                }
                boolean changed = false;
                for (BackendEntry entry : backends) {
                    boolean ok = UaHttp.pingBackend(entry.url);
                    entry.lastStatus = ok ? "ok" : "unreachable";
                    entry.lastCheckedAt = System.currentTimeMillis();
                    changed = true;
                }
                if (changed) {
                    BackendStore.save(this, backends);
                }
            }
        });
    }

    private org.json.JSONObject buildDeviceMeta() {
        org.json.JSONObject meta = new org.json.JSONObject();
        try {
            meta.put("manufacturer", Build.MANUFACTURER);
            meta.put("brand", Build.BRAND);
            meta.put("model", Build.MODEL);
            meta.put("device", Build.DEVICE);
            meta.put("buildFingerprint", Build.FINGERPRINT);
        } catch (Exception e) {
            Log.w("UAService", "Failed to build device meta", e);
        }
        return meta;
    }

    private void safeSuccess(IIntegrityTokenCallback callback, String token) {
        try {
            callback.onSuccess(token);
        } catch (Exception ignored) {
        }
    }

    private void safeError(IIntegrityTokenCallback callback, int code, String message) {
        try {
            callback.onError(code, message == null ? "error" : message);
        } catch (Exception ignored) {
        }
    }
}
