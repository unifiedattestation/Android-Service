package net.uattest.service;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.android.keyattestation.verifier.AuthorizationList;
import com.android.keyattestation.verifier.KeyDescription;
import com.android.keyattestation.verifier.RootOfTrust;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

public class DeviceSubmitHelper {

    private static final String ALIAS_EC  = "ua_device_submit_probe_ec";
    private static final String ALIAS_RSA = "ua_device_submit_probe_rsa";

    public static JSONObject generate(Context context) throws Exception {
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        X509Certificate[] ecChain  = generateAttestedChain(ks, ALIAS_EC,  KeyProperties.KEY_ALGORITHM_EC,  challenge);
        X509Certificate[] rsaChain = null;
        try {
            rsaChain = generateAttestedChain(ks, ALIAS_RSA, KeyProperties.KEY_ALGORITHM_RSA, challenge);
        } catch (Exception ignored) {
            // RSA hardware attestation is not available on all devices
        }

        X509Certificate ecLeaf = ecChain[0];

        // Parse device/policy fields from the EC leaf (primary)
        Function1<String, Unit> noLog = msg -> Unit.INSTANCE;
        KeyDescription desc = KeyDescription.Companion.parseFrom(ecLeaf, noLog);
        if (desc == null) {
            throw new IllegalStateException(
                    "No Key Attestation extension found — device may not support hardware attestation");
        }

        AuthorizationList hw = desc.getHardwareEnforced();
        RootOfTrust rot = hw.getRootOfTrust();

        String verifiedBootKey   = rot != null ? bytesToHex(rot.getVerifiedBootKey().toByteArray()) : null;
        String verifiedBootHash  = (rot != null && rot.getVerifiedBootHash() != null)
                ? bytesToHex(rot.getVerifiedBootHash().toByteArray()) : null;
        String verifiedBootState = rot != null ? rot.getVerifiedBootState().name() : null;
        String osVersion    = hw.getOsVersion()    != null ? hw.getOsVersion().toString()    : null;
        String osPatchLevel = hw.getOsPatchLevel() != null ? hw.getOsPatchLevel().toString() : null;

        // Build output JSON
        JSONObject json = new JSONObject();

        JSONObject device = new JSONObject();
        device.put("manufacturer",     Build.MANUFACTURER);
        device.put("brand",            Build.BRAND);
        device.put("model",            Build.MODEL);
        device.put("codename",         Build.DEVICE);
        device.put("buildFingerprint", Build.FINGERPRINT);
        json.put("device", device);

        JSONObject buildPolicy = new JSONObject();
        if (verifiedBootKey   != null) buildPolicy.put("verifiedBootKey",   verifiedBootKey);
        if (verifiedBootHash  != null) buildPolicy.put("verifiedBootHash",  verifiedBootHash);
        if (verifiedBootState != null) buildPolicy.put("verifiedBootState", verifiedBootState);
        if (osVersion    != null) buildPolicy.put("osVersionRaw",    osVersion);
        if (osPatchLevel != null) buildPolicy.put("osPatchLevelRaw", osPatchLevel);
        json.put("buildPolicy", buildPolicy);

        JSONObject trustAnchor = new JSONObject();
        trustAnchor.put("ec",  chainToJson(ecChain));
        if (rsaChain != null) {
            trustAnchor.put("rsa", chainToJson(rsaChain));
        }
        json.put("trustAnchor", trustAnchor);

        JSONObject attestInfo = new JSONObject();
        attestInfo.put("attestationVersion",       desc.getAttestationVersion().toString());
        attestInfo.put("attestationSecurityLevel", desc.getAttestationSecurityLevel().name());
        attestInfo.put("keymasterSecurityLevel",   desc.getKeyMintSecurityLevel().name());
        json.put("attestationInfo", attestInfo);

        return json;
    }

    private static X509Certificate[] generateAttestedChain(
            KeyStore ks, String alias, String algorithm, byte[] challenge) throws Exception {
        if (ks.containsAlias(alias)) ks.deleteEntry(alias);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge);

        if (KeyProperties.KEY_ALGORITHM_RSA.equals(algorithm)) {
            builder.setKeySize(2048)
                   .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, "AndroidKeyStore");
        kpg.initialize(builder.build());
        kpg.generateKeyPair();

        Certificate[] raw = ks.getCertificateChain(alias);
        ks.deleteEntry(alias);

        if (raw == null || raw.length == 0) {
            throw new IllegalStateException("No certificate chain for " + algorithm);
        }
        X509Certificate[] chain = new X509Certificate[raw.length];
        for (int i = 0; i < raw.length; i++) chain[i] = (X509Certificate) raw[i];
        return chain;
    }

    private static JSONObject chainToJson(X509Certificate[] chain) throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("leafCertificatePem", certToPem(chain[0]));

        JSONArray intermediates = new JSONArray();
        for (int i = 1; i < chain.length - 1; i++) {
            intermediates.put(certToPem(chain[i]));
        }
        if (intermediates.length() > 0) {
            obj.put("intermediateCertificatesPem", intermediates);
        }

        obj.put("rootCertificatePem", certToPem(chain[chain.length - 1]));
        return obj;
    }

    private static String certToPem(X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP)
                + "\n-----END CERTIFICATE-----";
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
