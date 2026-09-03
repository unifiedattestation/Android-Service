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
// Ported from Kotlin to Java; the ASN.1 write direction (toAsn1) was dropped since this
// app only reads patch levels out of a locally generated attestation certificate.

package net.uattest.service.keyattestation;

import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.function.Consumer;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;

public final class PatchLevel {
    private static final DateTimeFormatter YEAR_MONTH_FORMAT = DateTimeFormatter.ofPattern("yyyyMM");

    private final YearMonth yearMonth;
    private final Integer version;

    public PatchLevel(YearMonth yearMonth, Integer version) {
        this.yearMonth = yearMonth;
        this.version = version;
    }

    public YearMonth getYearMonth() {
        return yearMonth;
    }

    public Integer getVersion() {
        return version;
    }

    @Override
    public String toString() {
        String yearMonthString = YEAR_MONTH_FORMAT.format(yearMonth);
        if (version != null) {
            return String.format("%s%02d", yearMonthString, version);
        }
        return yearMonthString;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PatchLevel)) {
            return false;
        }
        PatchLevel that = (PatchLevel) o;
        return Objects.equals(yearMonth, that.yearMonth) && Objects.equals(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(yearMonth, version);
    }

    static PatchLevel from(ASN1Encodable patchLevel, String partitionName, Consumer<String> logFn) {
        if (!(patchLevel instanceof ASN1Integer)) {
            throw new ExtensionParsingException(
                    "Must be an ASN1Integer, was " + patchLevel.getClass().getSimpleName());
        }
        return from(((ASN1Integer) patchLevel).getValue().toString(), partitionName, logFn);
    }

    public static PatchLevel from(String patchLevel, String partitionName, Consumer<String> logFn) {
        if (patchLevel.length() != 6 && patchLevel.length() != 8) {
            logFn.accept("Invalid " + partitionName + " patch level: " + patchLevel);
            return null;
        }
        try {
            YearMonth yearMonth = YearMonth.parse(patchLevel.substring(0, 6), YEAR_MONTH_FORMAT);
            Integer version = patchLevel.length() == 8 ? Integer.valueOf(patchLevel.substring(6)) : null;
            return new PatchLevel(yearMonth, version);
        } catch (DateTimeParseException | NumberFormatException e) {
            logFn.accept("Invalid " + partitionName + " patch level: " + patchLevel);
            return null;
        }
    }
}
