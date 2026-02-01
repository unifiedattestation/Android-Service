package net.uattest.service;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class BackendStore {
    private static final String PREFS_NAME = "ua_backends";
    private static final String KEY_LIST = "backend_list";

    public static List<BackendEntry> load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String raw = prefs.getString(KEY_LIST, null);
        if (raw == null || raw.isEmpty()) {
            List<BackendEntry> defaults = new ArrayList<>();
            for (String url : ConfigReader.loadDefaultUrls(context)) {
                defaults.add(new BackendEntry(null, url, true));
            }
            save(context, defaults);
            return defaults;
        }
        List<BackendEntry> entries = new ArrayList<>();
        try {
            JSONArray arr = new JSONArray(raw);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                BackendEntry entry = new BackendEntry(
                        obj.optString("backendId", null),
                        obj.getString("url"),
                        obj.optBoolean("enabled", true)
                );
                entry.lastStatus = obj.optString("lastStatus", null);
                entry.lastCheckedAt = obj.optLong("lastCheckedAt", 0);
                entries.add(entry);
            }
        } catch (Exception ignored) {
        }
        return entries;
    }

    public static void save(Context context, List<BackendEntry> entries) {
        JSONArray arr = new JSONArray();
        for (BackendEntry entry : entries) {
            JSONObject obj = new JSONObject();
            try {
                obj.put("backendId", entry.backendId);
                obj.put("url", entry.url);
                obj.put("enabled", entry.enabled);
                obj.put("lastStatus", entry.lastStatus);
                obj.put("lastCheckedAt", entry.lastCheckedAt);
            } catch (Exception ignored) {
            }
            arr.put(obj);
        }
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(KEY_LIST, arr.toString()).apply();
    }
}
