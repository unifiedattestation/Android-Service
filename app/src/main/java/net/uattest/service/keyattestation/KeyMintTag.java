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
// Ported from Kotlin to Java.

package net.uattest.service.keyattestation;

/**
 * KeyMint tag names and IDs.
 *
 * @see <a
 *     href="https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl">Tag.aidl</a>
 */
public enum KeyMintTag {
    PURPOSE(1),
    ALGORITHM(2),
    KEY_SIZE(3),
    BLOCK_MODE(4),
    DIGEST(5),
    PADDING(6),
    EC_CURVE(10),
    ML_DSA_VARIANT(11),
    RSA_PUBLIC_EXPONENT(200),
    RSA_OAEP_MGF_DIGEST(203),
    ACTIVE_DATE_TIME(400),
    ORIGINATION_EXPIRE_DATE_TIME(401),
    USAGE_EXPIRE_DATE_TIME(402),
    USAGE_COUNT_LIMIT(405),
    NO_AUTH_REQUIRED(503),
    USER_AUTH_TYPE(504),
    AUTH_TIMEOUT(505),
    ALLOW_WHILE_ON_BODY(506),
    TRUSTED_USER_PRESENCE_REQUIRED(507),
    TRUSTED_CONFIRMATION_REQUIRED(508),
    UNLOCKED_DEVICE_REQUIRED(509),
    CREATION_DATE_TIME(701),
    ORIGIN(702),
    ROLLBACK_RESISTANT(703),
    ROOT_OF_TRUST(704),
    OS_VERSION(705),
    OS_PATCH_LEVEL(706),
    ATTESTATION_APPLICATION_ID(709),
    ATTESTATION_ID_BRAND(710),
    ATTESTATION_ID_DEVICE(711),
    ATTESTATION_ID_PRODUCT(712),
    ATTESTATION_ID_SERIAL(713),
    ATTESTATION_ID_IMEI(714),
    ATTESTATION_ID_MEID(715),
    ATTESTATION_ID_MANUFACTURER(716),
    ATTESTATION_ID_MODEL(717),
    VENDOR_PATCH_LEVEL(718),
    BOOT_PATCH_LEVEL(719),
    ATTESTATION_ID_SECOND_IMEI(723),
    MODULE_HASH(724);

    // The following tags are intentionally unsupported (matches upstream):
    // 7 (callerNonce): Used in symmetric ciphers only
    // 8 (minMacLength): Used in symmetric ciphers only
    // 303 (rollbackResistance): Not usable by 3p apps (framework API is hidden)
    // 305 (earlyBootOnly): Not usable by 3p apps
    // 502 (userSecureId): Not usable by 3p apps (framework API is hidden)
    // 720 (deviceUniqueAttestation): Not widely used.

    public final int value;

    KeyMintTag(int value) {
        this.value = value;
    }

    static KeyMintTag from(int value) {
        for (KeyMintTag tag : values()) {
            if (tag.value == value) {
                return tag;
            }
        }
        throw new ExtensionParsingException(
                "unknown tag number: " + value, KeyAttestationReason.UNKNOWN_TAG_NUMBER);
    }
}
