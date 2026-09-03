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
// Ported from Kotlin to Java; the ASN.1 write direction (toAsn1) was dropped.

package net.uattest.service.keyattestation;

import java.math.BigInteger;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Representation of the AttestationPackageInfo sequence contained within {@link
 * AttestationApplicationId}.
 *
 * @see <a
 *     href="https://source.android.com/docs/security/features/keystore/attestation#attestationapplicationid-schema">AttestationApplicationId</a>
 */
public final class AttestationPackageInfo {
    private final String name;
    private final BigInteger version;

    public AttestationPackageInfo(String name, BigInteger version) {
        this.name = name;
        this.version = version;
    }

    public String getName() {
        return name;
    }

    public BigInteger getVersion() {
        return version;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AttestationPackageInfo)) {
            return false;
        }
        AttestationPackageInfo that = (AttestationPackageInfo) o;
        return Objects.equals(name, that.name) && Objects.equals(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, version);
    }

    static AttestationPackageInfo from(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new ExtensionParsingException(
                    "AttestationPackageInfo sequence must have 2 elements, had " + seq.size());
        }
        return new AttestationPackageInfo(
                Asn1Util.toStr(seq.getObjectAt(0)), Asn1Util.toBigInteger(seq.getObjectAt(1)));
    }
}
