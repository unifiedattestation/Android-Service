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
// Ported from Kotlin's checked Exception to an unchecked RuntimeException, since every
// caller in this app already wraps parsing in a generic try/catch.

package net.uattest.service.keyattestation;

public final class ExtensionParsingException extends RuntimeException {
    private final KeyAttestationReason reason;

    public ExtensionParsingException(String message) {
        this(message, null, null);
    }

    public ExtensionParsingException(String message, KeyAttestationReason reason) {
        this(message, reason, null);
    }

    public ExtensionParsingException(String message, KeyAttestationReason reason, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public KeyAttestationReason getReason() {
        return reason;
    }
}
