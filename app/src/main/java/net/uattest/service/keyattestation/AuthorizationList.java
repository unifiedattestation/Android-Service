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
// Ported from Kotlin to Java; the ASN.1 write direction (toAsn1) was dropped, and byte
// fields are plain byte[] instead of protobuf ByteString.

package net.uattest.service.keyattestation;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;

/**
 * Representation of the AuthorizationList sequence contained within {@link KeyDescription}.
 *
 * @see <a
 *     href="https://source.android.com/docs/security/features/keystore/attestation#authorizationlist-fields">AuthorizationList</a>
 */
public final class AuthorizationList {
    private Set<BigInteger> purposes;
    private BigInteger algorithms;
    private BigInteger keySize;
    private Set<BigInteger> blockModes;
    private Set<BigInteger> digests;
    private Set<BigInteger> paddings;
    private BigInteger ecCurve;
    private BigInteger mlDsaVariant;
    private BigInteger rsaPublicExponent;
    private Set<BigInteger> rsaOaepMgfDigests;
    private BigInteger activeDateTime;
    private BigInteger originationExpireDateTime;
    private BigInteger usageExpireDateTime;
    private BigInteger usageCountLimit;
    private Boolean noAuthRequired;
    private BigInteger userAuthType;
    private BigInteger authTimeout;
    private Boolean trustedUserPresenceRequired;
    private Boolean trustedConfirmationRequired;
    private Boolean unlockedDeviceRequired;
    private BigInteger creationDateTime;
    private Origin origin;
    private Boolean rollbackResistant;
    private RootOfTrust rootOfTrust;
    private BigInteger osVersion;
    private PatchLevel osPatchLevel;
    private AttestationApplicationId attestationApplicationId;
    private String attestationIdBrand;
    private String attestationIdDevice;
    private String attestationIdProduct;
    private String attestationIdSerial;
    private String attestationIdImei;
    private String attestationIdMeid;
    private String attestationIdManufacturer;
    private String attestationIdModel;
    private PatchLevel vendorPatchLevel;
    private PatchLevel bootPatchLevel;
    private String attestationIdSecondImei;
    private byte[] moduleHash;
    private boolean areTagsOrdered = true;

    private AuthorizationList() {}

    public Set<BigInteger> getPurposes() {
        return purposes;
    }

    public BigInteger getAlgorithms() {
        return algorithms;
    }

    public BigInteger getKeySize() {
        return keySize;
    }

    public Set<BigInteger> getBlockModes() {
        return blockModes;
    }

    public Set<BigInteger> getDigests() {
        return digests;
    }

    public Set<BigInteger> getPaddings() {
        return paddings;
    }

    public BigInteger getEcCurve() {
        return ecCurve;
    }

    public BigInteger getMlDsaVariant() {
        return mlDsaVariant;
    }

    public BigInteger getRsaPublicExponent() {
        return rsaPublicExponent;
    }

    public Set<BigInteger> getRsaOaepMgfDigests() {
        return rsaOaepMgfDigests;
    }

    public BigInteger getActiveDateTime() {
        return activeDateTime;
    }

    public BigInteger getOriginationExpireDateTime() {
        return originationExpireDateTime;
    }

    public BigInteger getUsageExpireDateTime() {
        return usageExpireDateTime;
    }

    public BigInteger getUsageCountLimit() {
        return usageCountLimit;
    }

    public Boolean getNoAuthRequired() {
        return noAuthRequired;
    }

    public BigInteger getUserAuthType() {
        return userAuthType;
    }

    public BigInteger getAuthTimeout() {
        return authTimeout;
    }

    public Boolean getTrustedUserPresenceRequired() {
        return trustedUserPresenceRequired;
    }

    public Boolean getTrustedConfirmationRequired() {
        return trustedConfirmationRequired;
    }

    public Boolean getUnlockedDeviceRequired() {
        return unlockedDeviceRequired;
    }

    public BigInteger getCreationDateTime() {
        return creationDateTime;
    }

    public Origin getOrigin() {
        return origin;
    }

    public Boolean getRollbackResistant() {
        return rollbackResistant;
    }

    public RootOfTrust getRootOfTrust() {
        return rootOfTrust;
    }

    public BigInteger getOsVersion() {
        return osVersion;
    }

    public PatchLevel getOsPatchLevel() {
        return osPatchLevel;
    }

    public AttestationApplicationId getAttestationApplicationId() {
        return attestationApplicationId;
    }

    public String getAttestationIdBrand() {
        return attestationIdBrand;
    }

    public String getAttestationIdDevice() {
        return attestationIdDevice;
    }

    public String getAttestationIdProduct() {
        return attestationIdProduct;
    }

    public String getAttestationIdSerial() {
        return attestationIdSerial;
    }

    public String getAttestationIdImei() {
        return attestationIdImei;
    }

    public String getAttestationIdMeid() {
        return attestationIdMeid;
    }

    public String getAttestationIdManufacturer() {
        return attestationIdManufacturer;
    }

    public String getAttestationIdModel() {
        return attestationIdModel;
    }

    public PatchLevel getVendorPatchLevel() {
        return vendorPatchLevel;
    }

    public PatchLevel getBootPatchLevel() {
        return bootPatchLevel;
    }

    public String getAttestationIdSecondImei() {
        return attestationIdSecondImei;
    }

    public byte[] getModuleHash() {
        return moduleHash;
    }

    public boolean areTagsOrdered() {
        return areTagsOrdered;
    }

    static AuthorizationList from(ASN1Sequence seq, Consumer<String> logFn, InputLimits inputLimits) {
        Map<KeyMintTag, ASN1Encodable> objects = new LinkedHashMap<>();
        List<Integer> tagNumbersInOrder = new ArrayList<>();
        for (int i = 0; i < seq.size(); i++) {
            ASN1Encodable element = seq.getObjectAt(i);
            if (!(element instanceof ASN1TaggedObject)) {
                throw new ExtensionParsingException(
                        "Must be an ASN1TaggedObject, was " + element.getClass().getSimpleName());
            }
            ASN1TaggedObject tagged = (ASN1TaggedObject) element;
            KeyMintTag tag = KeyMintTag.from(tagged.getTagNo());
            objects.put(tag, tagged.getExplicitBaseObject());
            tagNumbersInOrder.add(tagged.getTagNo());
        }

        // X.680 section 8.6: within a class of tags, elements should appear in ascending
        // order of their tag numbers.
        boolean areTagsOrdered = true;
        for (int i = 1; i < tagNumbersInOrder.size(); i++) {
            if (tagNumbersInOrder.get(i) <= tagNumbersInOrder.get(i - 1)) {
                areTagsOrdered = false;
                break;
            }
        }
        if (!areTagsOrdered) {
            logFn.accept("AuthorizationList tags should appear in ascending order");
        }

        AuthorizationList result = new AuthorizationList();
        result.areTagsOrdered = areTagsOrdered;
        result.purposes = parseBigIntegerSet(objects, KeyMintTag.PURPOSE, logFn);
        result.algorithms = parseBigInteger(objects, KeyMintTag.ALGORITHM, logFn);
        result.keySize = parseBigInteger(objects, KeyMintTag.KEY_SIZE, logFn);
        result.blockModes = parseBigIntegerSet(objects, KeyMintTag.BLOCK_MODE, logFn);
        result.digests = parseBigIntegerSet(objects, KeyMintTag.DIGEST, logFn);
        result.paddings = parseBigIntegerSet(objects, KeyMintTag.PADDING, logFn);
        result.ecCurve = parseBigInteger(objects, KeyMintTag.EC_CURVE, logFn);
        result.mlDsaVariant = parseBigInteger(objects, KeyMintTag.ML_DSA_VARIANT, logFn);
        result.rsaPublicExponent = parseBigInteger(objects, KeyMintTag.RSA_PUBLIC_EXPONENT, logFn);
        result.rsaOaepMgfDigests = parseBigIntegerSet(objects, KeyMintTag.RSA_OAEP_MGF_DIGEST, logFn);
        result.activeDateTime = parseBigInteger(objects, KeyMintTag.ACTIVE_DATE_TIME, logFn);
        result.originationExpireDateTime =
                parseBigInteger(objects, KeyMintTag.ORIGINATION_EXPIRE_DATE_TIME, logFn);
        result.usageExpireDateTime = parseBigInteger(objects, KeyMintTag.USAGE_EXPIRE_DATE_TIME, logFn);
        result.usageCountLimit = parseBigInteger(objects, KeyMintTag.USAGE_COUNT_LIMIT, logFn);
        result.noAuthRequired = objects.containsKey(KeyMintTag.NO_AUTH_REQUIRED) ? Boolean.TRUE : null;
        result.userAuthType = parseBigInteger(objects, KeyMintTag.USER_AUTH_TYPE, logFn);
        result.authTimeout = parseBigInteger(objects, KeyMintTag.AUTH_TIMEOUT, logFn);
        result.trustedUserPresenceRequired =
                objects.containsKey(KeyMintTag.TRUSTED_USER_PRESENCE_REQUIRED) ? Boolean.TRUE : null;
        result.trustedConfirmationRequired =
                objects.containsKey(KeyMintTag.TRUSTED_CONFIRMATION_REQUIRED) ? Boolean.TRUE : null;
        result.unlockedDeviceRequired =
                objects.containsKey(KeyMintTag.UNLOCKED_DEVICE_REQUIRED) ? Boolean.TRUE : null;
        result.creationDateTime = parseBigInteger(objects, KeyMintTag.CREATION_DATE_TIME, logFn);
        result.origin = parse(objects, KeyMintTag.ORIGIN, logFn, Asn1Util::toOrigin);
        result.rollbackResistant =
                objects.containsKey(KeyMintTag.ROLLBACK_RESISTANT) ? Boolean.TRUE : null;
        result.rootOfTrust =
                parse(objects, KeyMintTag.ROOT_OF_TRUST, logFn, obj -> RootOfTrust.from(requireSequence(obj)));
        result.osVersion = parseBigInteger(objects, KeyMintTag.OS_VERSION, logFn);
        result.osPatchLevel =
                parse(objects, KeyMintTag.OS_PATCH_LEVEL, logFn, obj -> PatchLevel.from(obj, "OS", logFn));
        result.attestationApplicationId =
                parse(
                        objects,
                        KeyMintTag.ATTESTATION_APPLICATION_ID,
                        logFn,
                        obj -> AttestationApplicationId.from(requireSequence(Asn1Util.toByteArray(obj)), inputLimits));
        result.attestationIdBrand = parseStr(objects, KeyMintTag.ATTESTATION_ID_BRAND, logFn);
        result.attestationIdDevice = parseStr(objects, KeyMintTag.ATTESTATION_ID_DEVICE, logFn);
        result.attestationIdProduct = parseStr(objects, KeyMintTag.ATTESTATION_ID_PRODUCT, logFn);
        result.attestationIdSerial = parseStr(objects, KeyMintTag.ATTESTATION_ID_SERIAL, logFn);
        result.attestationIdImei = parseStr(objects, KeyMintTag.ATTESTATION_ID_IMEI, logFn);
        result.attestationIdMeid = parseStr(objects, KeyMintTag.ATTESTATION_ID_MEID, logFn);
        result.attestationIdManufacturer = parseStr(objects, KeyMintTag.ATTESTATION_ID_MANUFACTURER, logFn);
        result.attestationIdModel = parseStr(objects, KeyMintTag.ATTESTATION_ID_MODEL, logFn);
        result.vendorPatchLevel =
                parse(
                        objects,
                        KeyMintTag.VENDOR_PATCH_LEVEL,
                        logFn,
                        obj -> PatchLevel.from(obj, "vendor", logFn));
        result.bootPatchLevel =
                parse(objects, KeyMintTag.BOOT_PATCH_LEVEL, logFn, obj -> PatchLevel.from(obj, "boot", logFn));
        result.attestationIdSecondImei = parseStr(objects, KeyMintTag.ATTESTATION_ID_SECOND_IMEI, logFn);
        result.moduleHash = parse(objects, KeyMintTag.MODULE_HASH, logFn, Asn1Util::toByteArray);
        return result;
    }

    private interface Parser<T> {
        T parse(ASN1Encodable obj);
    }

    private static <T> T parse(
            Map<KeyMintTag, ASN1Encodable> objects, KeyMintTag tag, Consumer<String> logFn, Parser<T> transform) {
        ASN1Encodable obj = objects.get(tag);
        if (obj == null) {
            return null;
        }
        try {
            return transform.parse(obj);
        } catch (ExtensionParsingException e) {
            logFn.accept("Exception when parsing " + tag.name().toLowerCase() + ": " + e.getMessage());
            return null;
        }
    }

    private static BigInteger parseBigInteger(
            Map<KeyMintTag, ASN1Encodable> objects, KeyMintTag tag, Consumer<String> logFn) {
        return parse(objects, tag, logFn, Asn1Util::toBigInteger);
    }

    private static String parseStr(
            Map<KeyMintTag, ASN1Encodable> objects, KeyMintTag tag, Consumer<String> logFn) {
        return parse(objects, tag, logFn, Asn1Util::toStr);
    }

    private static Set<BigInteger> parseBigIntegerSet(
            Map<KeyMintTag, ASN1Encodable> objects, KeyMintTag tag, Consumer<String> logFn) {
        return parse(
                objects,
                tag,
                logFn,
                obj -> {
                    if (!(obj instanceof ASN1Set)) {
                        throw new ExtensionParsingException(
                                "Object must be an ASN1Set, was " + obj.getClass().getSimpleName());
                    }
                    ASN1Set set = (ASN1Set) obj;
                    Set<BigInteger> values = new LinkedHashSet<>();
                    for (int i = 0; i < set.size(); i++) {
                        ASN1Encodable element = set.getObjectAt(i);
                        if (!(element instanceof ASN1Integer)) {
                            throw new ExtensionParsingException(
                                    "Object must be an ASN1Integer, was " + element.getClass().getSimpleName());
                        }
                        values.add(((ASN1Integer) element).getValue());
                    }
                    return values;
                });
    }

    private static ASN1Sequence requireSequence(ASN1Encodable obj) {
        if (!(obj instanceof ASN1Sequence)) {
            throw new ExtensionParsingException(
                    "Object must be an ASN1Sequence, was " + obj.getClass().getSimpleName());
        }
        return (ASN1Sequence) obj;
    }

    private static ASN1Sequence requireSequence(byte[] bytes) {
        return requireSequence(ASN1Sequence.getInstance(bytes));
    }
}
