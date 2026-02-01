package net.uattest.service;

import android.util.Base64;

public class Base64Util {
    public static String encode(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }
}
