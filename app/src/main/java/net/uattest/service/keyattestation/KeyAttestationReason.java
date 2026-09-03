/*
 * Copyright 2025 Google LLC
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

// Adapted from https://github.com/android/keyattestation (KeyAttestationReason.kt),
// Apache-2.0. Ported from Kotlin to Java; the certificate-chain-verification reasons are
// kept only for fidelity with the upstream enum, only UNKNOWN_TAG_NUMBER is reachable here.

package net.uattest.service.keyattestation;

/** Reasons why a certificate chain could not be verified which are specific to key attestation. */
public enum KeyAttestationReason {
    CHAIN_EXTENDED_FOR_KEY,
    TARGET_MISSING_ATTESTATION_EXTENSION,
    CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION,
    CONSTRAINT_VIOLATION,
    UNKNOWN_TAG_NUMBER,
}
