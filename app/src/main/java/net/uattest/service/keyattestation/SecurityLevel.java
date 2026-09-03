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
 * Representation of the SecurityLevel enum contained within {@link KeyDescription}.
 *
 * @see <a
 *     href="https://source.android.com/docs/security/features/keystore/attestation#securitylevel-values">SecurityLevel</a>
 */
public enum SecurityLevel {
    SOFTWARE(0),
    TRUSTED_ENVIRONMENT(1),
    STRONG_BOX(2);

    public final int value;

    SecurityLevel(int value) {
        this.value = value;
    }
}
