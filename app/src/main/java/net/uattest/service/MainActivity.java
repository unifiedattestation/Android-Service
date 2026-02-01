package net.uattest.service;

import androidx.appcompat.app.AppCompatActivity;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
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

        addButton.setOnClickListener(v -> addBackend());
        refreshButton.setOnClickListener(v -> refreshHealth());

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
                Log.e("UAService", "Failed to add backend", e);
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
        check.setText("Sanity Check");
        check.setOnClickListener(v -> runSanityCheck(entry));

        actions.addView(toggle);
        actions.addView(remove);
        actions.addView(check);

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
