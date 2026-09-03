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

import org.bouncycastle.asn1.ASN1Enumerated;

/**
 * Representation of the VerifiedBootState enum contained within {@link RootOfTrust}.
 *
 * @see <a
 *     href="https://source.android.com/docs/security/features/keystore/attestation#verifiedbootstate-values">VerifiedBootState</a>
 */
public enum VerifiedBootState {
    VERIFIED(0),
    SELF_SIGNED(1),
    UNVERIFIED(2),
    FAILED(3);

    public final int value;

    VerifiedBootState(int value) {
        this.value = value;
    }

    static VerifiedBootState from(ASN1Enumerated value) {
        int v = value.getValue().intValueExact();
        for (VerifiedBootState state : values()) {
            if (state.value == v) {
                return state;
            }
        }
        throw new IllegalArgumentException("unknown value: " + v);
    }
}
