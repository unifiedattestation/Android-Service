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
// Ported from Kotlin to Java; the ASN.1 write direction (toAsn1) was dropped, and
// verifiedBootKey/verifiedBootHash are plain byte[] instead of protobuf ByteString.

package net.uattest.service.keyattestation;

import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Representation of the RootOfTrust sequence contained within {@link AuthorizationList}.
 *
 * @see <a
 *     href="https://source.android.com/docs/security/features/keystore/attestation#rootoftrust-fields">RootOfTrust</a>
 */
public final class RootOfTrust {
    private final byte[] verifiedBootKey;
    private final boolean deviceLocked;
    private final VerifiedBootState verifiedBootState;
    private final byte[] verifiedBootHash;

    public RootOfTrust(
            byte[] verifiedBootKey,
            boolean deviceLocked,
            VerifiedBootState verifiedBootState,
            byte[] verifiedBootHash) {
        this.verifiedBootKey = verifiedBootKey;
        this.deviceLocked = deviceLocked;
        this.verifiedBootState = verifiedBootState;
        this.verifiedBootHash = verifiedBootHash;
    }

    public byte[] getVerifiedBootKey() {
        return verifiedBootKey;
    }

    public boolean isDeviceLocked() {
        return deviceLocked;
    }

    public VerifiedBootState getVerifiedBootState() {
        return verifiedBootState;
    }

    public byte[] getVerifiedBootHash() {
        return verifiedBootHash;
    }

    static RootOfTrust from(ASN1Sequence seq) {
        if (seq.size() != 3 && seq.size() != 4) {
            throw new ExtensionParsingException(
                    "RootOfTrust sequence must have 3 or 4 elements, had " + seq.size());
        }
        VerifiedBootState state = VerifiedBootState.from(Asn1Util.toEnumerated(seq.getObjectAt(2)));
        byte[] hash = seq.size() > 3 ? Asn1Util.toByteArray(seq.getObjectAt(3)) : null;
        return new RootOfTrust(
                Asn1Util.toByteArray(seq.getObjectAt(0)), Asn1Util.toBoolean(seq.getObjectAt(1)), state, hash);
    }
}
