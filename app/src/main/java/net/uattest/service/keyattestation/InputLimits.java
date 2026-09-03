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
// Ported from Kotlin to Java and trimmed to attestation-extension parsing only; see
// KeyDescription.java for what was dropped and why.

package net.uattest.service.keyattestation;

/** Limits on input sizes when parsing extensions from attestation certificates. */
public final class InputLimits {
    public final int maxPackages;
    public final int maxSignatures;

    public InputLimits() {
        this(32, 10);
    }

    public InputLimits(int maxPackages, int maxSignatures) {
        if (maxPackages <= 0) {
            throw new IllegalArgumentException("maxPackages must be > 0, was " + maxPackages);
        }
        if (maxSignatures <= 0) {
            throw new IllegalArgumentException("maxSignatures must be > 0, was " + maxSignatures);
        }
        this.maxPackages = maxPackages;
        this.maxSignatures = maxSignatures;
    }
}
