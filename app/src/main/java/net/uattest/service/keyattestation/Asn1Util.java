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
// Ported from Kotlin's private ASN1Encodable extension functions to Java static helpers.

package net.uattest.service.keyattestation;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;

/** Small ASN.1 reading helpers shared by the parsing code in this package. */
final class Asn1Util {
    private Asn1Util() {}

    static byte[] toByteArray(ASN1Encodable obj) {
        if (!(obj instanceof ASN1OctetString)) {
            throw new ExtensionParsingException(
                    "Must be an ASN1OctetString, was " + obj.getClass().getSimpleName());
        }
        return ((ASN1OctetString) obj).getOctets();
    }

    static boolean toBoolean(ASN1Encodable obj) {
        if (!(obj instanceof ASN1Boolean)) {
            throw new ExtensionParsingException(
                    "Must be an ASN1Boolean, was " + obj.getClass().getSimpleName());
        }
        return ((ASN1Boolean) obj).isTrue();
    }

    static ASN1Enumerated toEnumerated(ASN1Encodable obj) {
        if (!(obj instanceof ASN1Enumerated)) {
            throw new ExtensionParsingException(
                    "Must be an ASN1Enumerated, was " + obj.getClass().getSimpleName());
        }
        return (ASN1Enumerated) obj;
    }

    static BigInteger toBigInteger(ASN1Encodable obj) {
        if (!(obj instanceof ASN1Integer)) {
            throw new ExtensionParsingException(
                    "Must be an ASN1Integer, was " + obj.getClass().getSimpleName());
        }
        return ((ASN1Integer) obj).getValue();
    }

    static String toStr(ASN1Encodable obj) {
        byte[] bytes = toByteArray(obj);
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new ExtensionParsingException("error decoding ASN.1: " + e.getMessage(), null, e);
        }
    }

    static SecurityLevel toSecurityLevel(ASN1Encodable obj) {
        int v = toEnumerated(obj).getValue().intValueExact();
        for (SecurityLevel level : SecurityLevel.values()) {
            if (level.value == v) {
                return level;
            }
        }
        throw new IllegalStateException("unknown value: " + v);
    }

    static Origin toOrigin(ASN1Encodable obj) {
        BigInteger v = toBigInteger(obj);
        for (Origin origin : Origin.values()) {
            if (BigInteger.valueOf(origin.value).equals(v)) {
                return origin;
            }
        }
        throw new IllegalStateException("unknown value: " + v);
    }
}
