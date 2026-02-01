package net.uattest.service;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

public class KeyAttestationManager {
    private static final String PROVIDER = "AndroidKeyStore";
    private static final String PREFS = "ua_attestation_keys";

    public static List<String> getAttestationChain(
            Context context,
            String alias,
            byte[] requestHash
    ) throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);

        boolean regenerate = shouldRegenerate(context, alias, requestHash);
        if (!ks.containsAlias(alias) || regenerate) {
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias);
            }
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(requestHash)
                    .build();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    PROVIDER
            );
            kpg.initialize(spec);
            kpg.generateKeyPair();
            rememberRequestHash(context, alias, requestHash);
        }

        Certificate[] chain = ks.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("No attestation certificate chain");
        }
        List<String> output = new ArrayList<>();
        for (Certificate cert : chain) {
            output.add(Base64Util.encode(cert.getEncoded()));
        }
        return output;
    }

    private static boolean shouldRegenerate(Context context, String alias, byte[] requestHash) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String stored = prefs.getString(alias, null);
        String current = Base64Util.encode(requestHash);
        return stored != null && !stored.equals(current);
    }

    private static void rememberRequestHash(Context context, String alias, byte[] requestHash) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        prefs.edit().putString(alias, Base64Util.encode(requestHash)).apply();
    }
}
