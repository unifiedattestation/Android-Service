/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Adapted from https://github.com/android/keyattestation (Extension.kt), Apache-2.0.
//
// Ported from Kotlin to Java and trimmed to attestation-extension *parsing* only:
//  - ProvisioningInfoMap (a different extension, OID ...2.1.30) and its CBOR decoding were
//    dropped; DeviceSubmitHelper never touches it.
//  - The ASN.1 write direction (toAsn1/encodeToAsn1/asExtension) was dropped; this app only
//    reads fields out of a locally generated attestation certificate, never re-encodes one.
//  - Certificate-chain verification, revocation-list checking, and the CLI (the rest of the
//    upstream library) were dropped as out of scope for this app.
// Byte fields use plain byte[] instead of protobuf ByteString, and logging uses
// java.util.function.Consumer<String> instead of Kotlin's (String) -> Unit, so the only
// remaining external dependency is BouncyCastle's org.bouncycastle.asn1 package.

package net.uattest.service.keyattestation;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.function.Consumer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Representation of the Key Attestation certificate extension.
 *
 * @see <a
 *     href="https://source.android.com/docs/security/features/keystore/attestation#schema">Key
 *     Attestation extension schema</a>
 */
public final class KeyDescription {
    /** OID for the key attestation extension. */
    public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");

    private final BigInteger attestationVersion;
    private final SecurityLevel attestationSecurityLevel;
    private final BigInteger keyMintVersion;
    private final SecurityLevel keyMintSecurityLevel;
    private final byte[] attestationChallenge;
    private final byte[] uniqueId;
    private final AuthorizationList softwareEnforced;
    private final AuthorizationList hardwareEnforced;

    private KeyDescription(
            BigInteger attestationVersion,
            SecurityLevel attestationSecurityLevel,
            BigInteger keyMintVersion,
            SecurityLevel keyMintSecurityLevel,
            byte[] attestationChallenge,
            byte[] uniqueId,
            AuthorizationList softwareEnforced,
            AuthorizationList hardwareEnforced) {
        this.attestationVersion = attestationVersion;
        this.attestationSecurityLevel = attestationSecurityLevel;
        this.keyMintVersion = keyMintVersion;
        this.keyMintSecurityLevel = keyMintSecurityLevel;
        this.attestationChallenge = attestationChallenge;
        this.uniqueId = uniqueId;
        this.softwareEnforced = softwareEnforced;
        this.hardwareEnforced = hardwareEnforced;
    }

    public BigInteger getAttestationVersion() {
        return attestationVersion;
    }

    public SecurityLevel getAttestationSecurityLevel() {
        return attestationSecurityLevel;
    }

    public BigInteger getKeyMintVersion() {
        return keyMintVersion;
    }

    public SecurityLevel getKeyMintSecurityLevel() {
        return keyMintSecurityLevel;
    }

    public byte[] getAttestationChallenge() {
        return attestationChallenge;
    }

    public byte[] getUniqueId() {
        return uniqueId;
    }

    public AuthorizationList getSoftwareEnforced() {
        return softwareEnforced;
    }

    public AuthorizationList getHardwareEnforced() {
        return hardwareEnforced;
    }

    /** Returns null if {@code cert} has no key attestation extension. */
    public static KeyDescription parseFrom(X509Certificate cert) {
        return parseFrom(cert, msg -> {}, new InputLimits());
    }

    /** Returns null if {@code cert} has no key attestation extension. */
    public static KeyDescription parseFrom(X509Certificate cert, Consumer<String> logFn) {
        return parseFrom(cert, logFn, new InputLimits());
    }

    /** Returns null if {@code cert} has no key attestation extension. */
    public static KeyDescription parseFrom(
            X509Certificate cert, Consumer<String> logFn, InputLimits inputLimits) {
        byte[] extensionValue = cert.getExtensionValue(OID.getId());
        if (extensionValue == null) {
            return null;
        }
        byte[] octets = ASN1OctetString.getInstance(extensionValue).getOctets();
        return parseFrom(octets, logFn, inputLimits);
    }

    public static KeyDescription parseFrom(byte[] bytes, Consumer<String> logFn, InputLimits inputLimits) {
        ASN1Sequence seq;
        try {
            seq = ASN1Sequence.getInstance(bytes);
        } catch (NullPointerException e) {
            // Workaround for a NPE in BouncyCastle.
            // https://github.com/bcgit/bc-java/blob/228211ecb973fe87fdd0fc4ab16ba0446ec1a29c/core/src/main/java/org/bouncycastle/asn1/ASN1UniversalType.java#L24
            throw new IllegalArgumentException(e);
        }
        return from(seq, logFn, inputLimits);
    }

    private static KeyDescription from(ASN1Sequence seq, Consumer<String> logFn, InputLimits inputLimits) {
        if (seq.size() != 8) {
            throw new ExtensionParsingException(
                    "KeyDescription sequence must have 8 elements, had " + seq.size());
        }
        return new KeyDescription(
                Asn1Util.toBigInteger(seq.getObjectAt(0)),
                Asn1Util.toSecurityLevel(seq.getObjectAt(1)),
                Asn1Util.toBigInteger(seq.getObjectAt(2)),
                Asn1Util.toSecurityLevel(seq.getObjectAt(3)),
                Asn1Util.toByteArray(seq.getObjectAt(4)),
                Asn1Util.toByteArray(seq.getObjectAt(5)),
                toAuthorizationList(seq.getObjectAt(6), logFn, inputLimits),
                toAuthorizationList(seq.getObjectAt(7), logFn, inputLimits));
    }

    private static AuthorizationList toAuthorizationList(
            org.bouncycastle.asn1.ASN1Encodable obj, Consumer<String> logFn, InputLimits inputLimits) {
        if (!(obj instanceof ASN1Sequence)) {
            throw new ExtensionParsingException(
                    "Object must be an ASN1Sequence, was " + obj.getClass().getSimpleName());
        }
        return AuthorizationList.from((ASN1Sequence) obj, logFn, inputLimits);
    }
}
