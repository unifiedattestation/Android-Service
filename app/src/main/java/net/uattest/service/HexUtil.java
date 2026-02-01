package net.uattest.service;

public class HexUtil {
    public static byte[] decode(String hex) {
        String normalized = hex.trim().toLowerCase();
        if (normalized.startsWith("0x")) {
            normalized = normalized.substring(2);
        }
        if (normalized.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex length");
        }
        byte[] data = new byte[normalized.length() / 2];
        for (int i = 0; i < normalized.length(); i += 2) {
            int hi = Character.digit(normalized.charAt(i), 16);
            int lo = Character.digit(normalized.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex string");
            }
            data[i / 2] = (byte) ((hi << 4) + lo);
        }
        return data;
    }
}
