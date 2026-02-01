package net.uattest.service;

public class BackendEntry {
    public String backendId;
    public String url;
    public boolean enabled;
    public String lastStatus;
    public long lastCheckedAt;

    public BackendEntry(String backendId, String url, boolean enabled) {
        this.backendId = backendId;
        this.url = url;
        this.enabled = enabled;
    }
}
