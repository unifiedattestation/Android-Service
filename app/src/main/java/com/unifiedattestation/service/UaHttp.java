package com.unifiedattestation.service;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class UaHttp {
    public static BackendInfo fetchBackendInfo(String baseUrl) throws Exception {
        String url = normalize(baseUrl) + "/api/v1/info";
        JSONObject response = getJson(url);
        String backendId = response.getString("backendId");
        return new BackendInfo(backendId, normalize(baseUrl));
    }

    public static String postDeviceProcess(
            String baseUrl,
            String projectId,
            String requestHash,
            List<String> attestationChain,
            JSONObject deviceMeta
    ) throws Exception {
        String url = normalize(baseUrl) + "/api/v1/device/process";
        JSONObject body = new JSONObject();
        body.put("projectId", projectId);
        body.put("requestHash", requestHash);
        JSONArray arr = new JSONArray();
        for (String cert : attestationChain) {
            arr.put(cert);
        }
        body.put("attestationChain", arr);
        if (deviceMeta != null) {
            body.put("deviceMeta", deviceMeta);
        }
        JSONObject response = postJson(url, body);
        return response.getString("token");
    }

    public static boolean pingBackend(String baseUrl) {
        try {
            fetchBackendInfo(baseUrl);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static JSONObject getJson(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        return readJson(conn);
    }

    private static JSONObject postJson(String url, JSONObject body) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setConnectTimeout(8000);
        conn.setReadTimeout(8000);
        byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
        conn.setFixedLengthStreamingMode(bytes.length);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(bytes);
        }
        return readJson(conn);
    }

    private static JSONObject readJson(HttpURLConnection conn) throws Exception {
        int code = conn.getResponseCode();
        InputStream stream = code >= 200 && code < 300 ? conn.getInputStream() : conn.getErrorStream();
        String raw = readAll(stream);
        if (code < 200 || code >= 300) {
            throw new RuntimeException("HTTP " + code + ": " + raw);
        }
        return new JSONObject(raw);
    }

    private static String readAll(InputStream input) throws Exception {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }

    private static String normalize(String baseUrl) {
        if (baseUrl.endsWith("/")) {
            return baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl;
    }
}
