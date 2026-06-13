package net.uattest.service;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private List<BackendEntry> backends = new ArrayList<>();
    private LinearLayout backendList;
    private TextView statusText;
    private EditText backendUrlInput;
    private IUnifiedAttestationService service;

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            service = IUnifiedAttestationService.Stub.asInterface(binder);
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            service = null;
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.statusText);
        backendList = findViewById(R.id.backendList);
        backendUrlInput = findViewById(R.id.backendUrlInput);

        Button addButton = findViewById(R.id.addBackendButton);
        Button refreshButton = findViewById(R.id.refreshButton);
        Button submitButton = findViewById(R.id.submitDeviceButton);

        addButton.setOnClickListener(v -> addBackend());
        refreshButton.setOnClickListener(v -> refreshHealth());
        submitButton.setOnClickListener(v -> submitDevice());

        backends = BackendStore.load(this);
        renderBackends();
        bindService(new Intent(this, UnifiedAttestationService.class), serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        try {
            unbindService(serviceConnection);
        } catch (Exception ignored) {
        }
        executor.shutdownNow();
    }

    private void addBackend() {
        String url = backendUrlInput.getText().toString().trim();
        if (url.isEmpty()) {
            return;
        }
        executor.submit(() -> {
            try {
                BackendInfo info = UaHttp.fetchBackendInfo(url);
                BackendEntry entry = new BackendEntry(info.backendId, info.url, true);
                entry.lastStatus = "ok";
                entry.lastCheckedAt = System.currentTimeMillis();
                backends.add(entry);
                BackendStore.save(this, backends);
                runOnUiThread(() -> {
                    backendUrlInput.setText("");
                    renderBackends();
                });
            } catch (Exception e) {
                Log.e(TAG,"Failed to add backend", e);
                runOnUiThread(() -> statusText.setText("Add failed: " + e.getMessage()));
            }
        });
    }

    private void refreshHealth() {
        executor.submit(() -> {
            for (BackendEntry entry : backends) {
                boolean ok = UaHttp.pingBackend(entry.url);
                entry.lastStatus = ok ? "ok" : "unreachable";
                entry.lastCheckedAt = System.currentTimeMillis();
            }
            BackendStore.save(this, backends);
            runOnUiThread(this::renderBackends);
        });
    }

    private void renderBackends() {
        backendList.removeAllViews();
        statusText.setText("Backends: " + backends.size());
        for (BackendEntry entry : backends) {
            backendList.addView(buildBackendRow(entry));
        }
    }

    private View buildBackendRow(BackendEntry entry) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(0, 12, 0, 12);

        TextView title = new TextView(this);
        title.setText(entry.backendId != null ? entry.backendId : "(unresolved)");
        title.setTextSize(16f);
        title.setTypeface(null, android.graphics.Typeface.BOLD);

        TextView url = new TextView(this);
        url.setText(entry.url);

        TextView status = new TextView(this);
        status.setText("Status: " + (entry.lastStatus == null ? "unknown" : entry.lastStatus));

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setGravity(Gravity.START);

        Button toggle = new Button(this);
        toggle.setText(entry.enabled ? "Disable" : "Enable");
        toggle.setOnClickListener(v -> {
            entry.enabled = !entry.enabled;
            BackendStore.save(this, backends);
            renderBackends();
        });

        Button remove = new Button(this);
        remove.setText("Remove");
        remove.setOnClickListener(v -> {
            backends.remove(entry);
            BackendStore.save(this, backends);
            renderBackends();
        });

        Button check = new Button(this);
        check.setText("Check");
        check.setOnClickListener(v -> runSanityCheck(entry));

        Button submitBtn = new Button(this);
        submitBtn.setText("Submit");
        submitBtn.setOnClickListener(v -> submitToBackend(entry));

        actions.addView(toggle);
        actions.addView(remove);
        actions.addView(check);
        actions.addView(submitBtn);

        row.addView(title);
        row.addView(url);
        row.addView(status);
        row.addView(actions);
        return row;
    }

    private void runSanityCheck(BackendEntry entry) {
        if (service == null || entry.backendId == null) {
            statusText.setText("Service not bound or backend unresolved");
            return;
        }
        String projectId = getPackageName();
        String canonical = "action=sanity&ts=0";
        String requestHash = sha256Hex(canonical.getBytes(StandardCharsets.UTF_8));
        try {
            service.requestIntegrityToken(
                    entry.backendId,
                    projectId,
                    requestHash,
                    new IIntegrityTokenCallback.Stub() {
                        @Override
                        public void onSuccess(String token) {
                            runOnUiThread(() -> statusText.setText("Sanity OK: " + token.substring(0, Math.min(16, token.length()))));
                        }

                        @Override
                        public void onError(int code, String message) {
                            runOnUiThread(() -> statusText.setText("Sanity failed: " + code + " " + message));
                        }
                    }
            );
        } catch (Exception e) {
            statusText.setText("Sanity error: " + e.getMessage());
        }
    }

    private static final String TAG = "UAService";
    private static final String PREFS_NAME = "ua_service";
    private static final String OEM_TOKEN_KEY_PREFIX = "oem_token_";

    private void submitToBackend(BackendEntry entry) {
        if (entry.backendId == null) {
            statusText.setText("Backend not resolved");
            return;
        }
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String savedToken = prefs.getString(OEM_TOKEN_KEY_PREFIX + entry.backendId, null);
        if (savedToken != null && !savedToken.isEmpty()) {
            doSubmit(entry, savedToken);
        } else {
            showTokenDialog(entry);
        }
    }

    private void showTokenDialog(BackendEntry entry) {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(48, 24, 48, 0);

        EditText tokenInput = new EditText(this);
        tokenInput.setHint("ua_oem_...");
        layout.addView(tokenInput);

        CheckBox rememberBox = new CheckBox(this);
        rememberBox.setText("Remember for this backend");
        rememberBox.setChecked(true);
        layout.addView(rememberBox);

        new AlertDialog.Builder(this)
                .setTitle("OEM API Token")
                .setView(layout)
                .setPositiveButton("Submit", (dialog, which) -> {
                    String token = tokenInput.getText().toString().trim();
                    if (token.isEmpty()) return;
                    if (rememberBox.isChecked() && entry.backendId != null) {
                        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                                .edit()
                                .putString(OEM_TOKEN_KEY_PREFIX + entry.backendId, token)
                                .apply();
                    }
                    doSubmit(entry, token);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void doSubmit(BackendEntry entry, String token) {
        statusText.setText("Submitting to backend…");
        executor.submit(() -> {
            try {
                org.json.JSONObject json = DeviceSubmitHelper.generate(this);
                org.json.JSONObject result = UaHttp.postOemDeviceSubmit(entry.url, token, json);
                String msg = buildSubmitSuccessMsg(result);
                runOnUiThread(() -> {
                    statusText.setText("Submit OK");
                    new AlertDialog.Builder(this)
                            .setTitle("Submit Successful")
                            .setMessage(msg)
                            .setPositiveButton("OK", null)
                            .show();
                });
            } catch (Exception e) {
                Log.e(TAG,"OEM submit failed", e);
                String errorMsg = parseSubmitError(e.getMessage());
                // Check if token was invalid and clear it
                if (errorMsg.contains("UNAUTHORIZED") && entry.backendId != null) {
                    getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            .edit()
                            .remove(OEM_TOKEN_KEY_PREFIX + entry.backendId)
                            .apply();
                }
                runOnUiThread(() -> {
                    statusText.setText("Submit failed");
                    new AlertDialog.Builder(this)
                            .setTitle("Submit Failed")
                            .setMessage(errorMsg)
                            .setPositiveButton("OK", null)
                            .setNeutralButton("Change Token", (d, w) -> showTokenDialog(entry))
                            .show();
                });
            }
        });
    }

    private String buildSubmitSuccessMsg(org.json.JSONObject result) {
        StringBuilder sb = new StringBuilder();
        try {
            org.json.JSONObject family = result.optJSONObject("deviceFamily");
            if (family != null) {
                sb.append("Device: ").append(family.optString("codename", "?"));
                sb.append(family.optBoolean("created") ? " (created)" : " (existed)").append("\n");
            }
            org.json.JSONObject policy = result.optJSONObject("buildPolicy");
            if (policy != null) {
                sb.append("Build policy: ").append(policy.optBoolean("created") ? "created" : "existed").append("\n");
            }
            if (!result.isNull("anchor") && result.optJSONObject("anchor") != null) {
                sb.append("Anchor registered\n");
            }
            String authority = result.optString("matchedAuthorityName", "");
            if (!authority.isEmpty()) sb.append("Authority: ").append(authority).append("\n");
            org.json.JSONArray warnings = result.optJSONArray("warnings");
            if (warnings != null && warnings.length() > 0) {
                for (int i = 0; i < warnings.length(); i++) {
                    sb.append("⚠ ").append(warnings.optString(i)).append("\n");
                }
            }
        } catch (Exception ignored) { }
        return sb.toString().trim().isEmpty() ? "OK" : sb.toString().trim();
    }

    private String parseSubmitError(String exceptionMsg) {
        if (exceptionMsg == null) return "Unknown error";
        int jsonStart = exceptionMsg.indexOf('{');
        if (jsonStart >= 0) {
            try {
                org.json.JSONObject err = new org.json.JSONObject(exceptionMsg.substring(jsonStart));
                String code = err.optString("code", "");
                String msg = err.optString("message", "");
                if (!msg.isEmpty()) return code.isEmpty() ? msg : "[" + code + "] " + msg;
            } catch (Exception ignored) { }
        }
        return exceptionMsg;
    }

    private void submitDevice() {
        statusText.setText("Generating device attestation...");
        executor.submit(() -> {
            try {
                org.json.JSONObject json = DeviceSubmitHelper.generate(this);
                String output = json.toString(2);
                runOnUiThread(() -> showSubmitResult(output));
            } catch (Exception e) {
                Log.e(TAG,"Submit device failed", e);
                runOnUiThread(() -> statusText.setText("Submit failed: " + e.getMessage()));
            }
        });
    }

    private void showSubmitResult(String json) {
        statusText.setText("Ready to submit");

        TextView textView = new TextView(this);
        textView.setText(json);
        textView.setTextSize(11f);
        textView.setPadding(24, 16, 24, 16);
        textView.setTypeface(android.graphics.Typeface.MONOSPACE);
        textView.setTextIsSelectable(true);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(textView);

        new AlertDialog.Builder(this)
                .setTitle("Device Registration Data")
                .setView(scroll)
                .setPositiveButton("Copy", (dialog, which) -> {
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    cm.setPrimaryClip(ClipData.newPlainText("ua_device_submit", json));
                })
                .setNegativeButton("Close", null)
                .show();
    }

    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
