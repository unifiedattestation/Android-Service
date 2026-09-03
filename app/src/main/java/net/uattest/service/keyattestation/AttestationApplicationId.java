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
// Ported from Kotlin to Java; the ASN.1 write direction (toAsn1) was dropped. Signatures
// are a List rather than a Set here: byte[] has identity equality in Java, so a Set would
// not dedupe the way the upstream Set<ByteString> did.

package net.uattest.service.keyattestation;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;

/**
 * Representation of the AttestationApplicationId sequence contained within {@link
 * AuthorizationList}.
 *
 * @see <a
 *     href="https://source.android.com/docs/security/features/keystore/attestation#attestationapplicationid-schema">AttestationApplicationId</a>
 */
public final class AttestationApplicationId {
    private final Set<AttestationPackageInfo> packages;
    private final List<byte[]> signatures;

    public AttestationApplicationId(Set<AttestationPackageInfo> packages, List<byte[]> signatures) {
        this.packages = packages;
        this.signatures = signatures;
    }

    public Set<AttestationPackageInfo> getPackages() {
        return packages;
    }

    public List<byte[]> getSignatures() {
        return signatures;
    }

    static AttestationApplicationId from(ASN1Sequence seq, InputLimits inputLimits) {
        if (seq.size() != 2) {
            throw new ExtensionParsingException("expected sequence of size 2, was " + seq.size());
        }

        ASN1Encodable packagesObj = seq.getObjectAt(0);
        if (!(packagesObj instanceof ASN1Set)) {
            throw new ExtensionParsingException(
                    "packages must be an ASN1Set, was " + packagesObj.getClass().getSimpleName());
        }
        ASN1Set packagesSet = (ASN1Set) packagesObj;
        if (packagesSet.size() > inputLimits.maxPackages) {
            throw new ExtensionParsingException(
                    "AttestationApplicationId contains too many packages ("
                            + packagesSet.size()
                            + " > "
                            + inputLimits.maxPackages
                            + ")");
        }

        ASN1Encodable signaturesObj = seq.getObjectAt(1);
        if (!(signaturesObj instanceof ASN1Set)) {
            throw new ExtensionParsingException(
                    "signatures must be an ASN1Set, was " + signaturesObj.getClass().getSimpleName());
        }
        ASN1Set signaturesSet = (ASN1Set) signaturesObj;
        if (signaturesSet.size() > inputLimits.maxSignatures) {
            throw new ExtensionParsingException(
                    "AttestationApplicationId contains too many signatures ("
                            + signaturesSet.size()
                            + " > "
                            + inputLimits.maxSignatures
                            + ")");
        }

        Set<AttestationPackageInfo> packages = new LinkedHashSet<>();
        for (int i = 0; i < packagesSet.size(); i++) {
            ASN1Encodable obj = packagesSet.getObjectAt(i);
            if (!(obj instanceof ASN1Sequence)) {
                throw new ExtensionParsingException(
                        "package info must be an ASN1Sequence, was " + obj.getClass().getSimpleName());
            }
            packages.add(AttestationPackageInfo.from((ASN1Sequence) obj));
        }

        List<byte[]> signatures = new ArrayList<>();
        for (int i = 0; i < signaturesSet.size(); i++) {
            ASN1Encodable obj = signaturesSet.getObjectAt(i);
            if (!(obj instanceof ASN1OctetString)) {
                throw new ExtensionParsingException(
                        "signature must be an ASN1OctetString, was " + obj.getClass().getSimpleName());
            }
            signatures.add(((ASN1OctetString) obj).getOctets());
        }

        return new AttestationApplicationId(packages, signatures);
    }
}
