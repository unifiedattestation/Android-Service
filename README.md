# Android-Service

## Overview
Privileged system service that performs KeyMint attestation and calls the backend. Apps never see the certificate chain.

## Config
- Default backend URLs are read from `/product/etc/unifiedattestation.xml` (OEM-provided).

Sample XML (in `/product/etc/unifiedattestation.xml`):
```xml
<backends>
  <backend url="http://localhost:3001" />
</backends>
```

## AIDL
- `IUnifiedAttestationService.getProviderSet(projectId)` returns enabled backendIds.
- `requestIntegrityToken(backendId, projectId, requestHash, callback)` performs attestation and returns token.
- Binding requires `net.uattest.service.BIND_UNIFIED_ATTESTATION` (signature|privileged).

## Keys
- Alias format: `ua:<packageName>:<backendId>`.
- EC P-256, `SIGN|VERIFY`, SHA-256.

## Settings UI
- Add backend by URL (resolves backendId via `/api/v1/info`).
- Enable/disable backend.
- Refresh health checks.
- Sanity check triggers a local request hash and full flow.

## Build/install
```bash
cd Android-Service
./gradlew assembleDebug
```
Install the APK as a privileged system app for production use.
