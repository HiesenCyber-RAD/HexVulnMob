# HexVulnMob
HEXVulnMob is an intentionally vulnerable Android training app developed by Research and Development team at Hiesen Cybersecurity, mapped to OWASP MASVS/MSTG test cases.

> [!CAUTION]
> Use this app only in authorized labs for security training. Do not apply these patterns or techniques to systems you do not own or have explicit permission to test.

Core flow:
- Challenge catalog comes from `app/src/main/assets/mstg_test_cases.json`.
- Category engines (`*ChallengeEngine.kt`) provide instructions, actions, and validation logic.
- Flags are validated via `FlagEngine` using a per-install `install_seed`.
- Dynamic challenges expose evidence through runtime behavior (network, file writes, logs, UI, notifications).
- Static challenges require reverse engineering proof tokens from source/resources and deriving flags.

> [!WARNING]
> This application is developed with the help of AI tools, if you find any issues with the applicaiton, please rainse an issue and we will try to solve them as soon as possible.

## 2. Flag Model

`FlagEngine` (`app/src/main/java/com/hexvulnmob/data/FlagEngine.kt`) computes:

`HEXFLAG{challengeId-first12hex(sha256(install_seed:challengeId:proofToken))}`

Where:
- `install_seed` is stored in `shared_prefs/hexvulnmob_flags.xml`.
- `proofToken` comes from code/resources/manifest or runtime flow.

## 3. Recommended Solve Workflow

1. Open challenge details and read description, steps, and hints.
2. If Run Action exists, execute once.
3. Collect evidence from the correct surface:
- network parameter/response
- app files/databases/shared prefs/datastore
- logcat
- UI/WebView/notification
- runtime hook (`RuntimeFlagSink.emit`)
4. For static tests, extract proof token and derive the flag with `install_seed`.
5. Submit the recovered flag.

## 4. Vulnerability Walkthrough by Category

## MASVS-CODE

### MASTG-TEST-0222 - Position Independent Code (PIC) Not Enabled
- What is vulnerable: native hardening reference is intentionally weak/missing.
- Implementation: static seed `NativeProtectionNotes.picDisabledSeed` in `app/src/main/java/com/hexvulnmob/NativeProtectionNotes.kt`.
- Solve: extract seed + `install_seed`, derive flag using formula.

### MASTG-TEST-0223 - Stack Canaries Not Enabled
- What is vulnerable: stack-smashing protection reference intentionally absent.
- Implementation: static seed `NativeProtectionNotes.stackCanarySeed`.
- Solve: extract seed + `install_seed`, derive flag.

### MASTG-TEST-0245 - References to Platform Version APIs
- What is vulnerable: version-checking reference challenge for static analysis.
- Implementation: static seed `BuildVersionReferences.platformApiSeed` in `app/src/main/java/com/hexvulnmob/BuildVersionReferences.kt`.
- Solve: extract seed + `install_seed`, derive flag.

### MASTG-TEST-0272 - Known Vulnerable Dependencies (Project)
- What is vulnerable: intentionally outdated dependency references.
- Implementation: `DependencyNotes.depsSeed` and sample dependency list in `app/src/main/java/com/hexvulnmob/DependencyNotes.kt`.
- Solve: extract `depsSeed` + `install_seed`, derive flag.

### MASTG-TEST-0274 - Known Vulnerable Dependencies (SBOM)
- What is vulnerable: SBOM references insecure dependency versions.
- Implementation: `DependencyNotes.sbomSeed` and SBOM snippet in `DependencyNotes.kt`.
- Solve: extract `sbomSeed` + `install_seed`, derive flag.

## MASVS-CRYPTO

### MASTG-TEST-0204 - Insecure Random API Usage
- What is vulnerable: insecure PRNG use.
- Implementation: `Random()` in `CryptoActionRunner.useInsecureRandom`.
- Solve: run action, read `flag=...` in output or hook `RuntimeFlagSink.emit`.

### MASTG-TEST-0205 - Non-random Sources Usage
- What is vulnerable: timestamp-based nonce generation.
- Implementation: `System.currentTimeMillis()` in `useNonRandomSource`.
- Solve: run action, capture flag in output/runtime emit.

### MASTG-TEST-0208 - Insufficient Key Sizes
- What is vulnerable: weak RSA key size.
- Implementation: `KeyPairGenerator` initialized with `1024` in `generateWeakKey`.
- Solve: run action, capture flag in output/runtime emit.

### MASTG-TEST-0212 - Hardcoded Cryptographic Keys
- What is vulnerable: static key material and weak key handling.
- Implementation: AES key from flag bytes + hardcoded IV in `useHardcodedKey`; artifacts in `CryptoArtifacts.kt`.
- Solve: hook `RuntimeFlagSink.emit` or cipher APIs; submit captured flag.

### MASTG-TEST-0221 - Broken Symmetric Algorithm
- What is vulnerable: DES usage.
- Implementation: `Cipher.getInstance("DES/ECB/PKCS5Padding")` in `useBrokenAlgorithm`.
- Solve: run action and hook `RuntimeFlagSink.emit`.

### MASTG-TEST-0232 - Broken Symmetric Mode
- What is vulnerable: ECB mode.
- Implementation: `Cipher.getInstance("AES/ECB/PKCS5Padding")` in `useBrokenMode`.
- Solve: run action and hook `RuntimeFlagSink.emit`.

### MASTG-TEST-0307 - Multi-purpose Asymmetric Key (Reference)
- What is vulnerable: same key used for signing and encryption.
- Implementation: `useMultiPurposeKey(flag = null)` performs sign + encrypt.
- Solve: run action, capture emitted flag.

### MASTG-TEST-0308 - Multi-purpose Asymmetric Key (Runtime)
- What is vulnerable: runtime-seeded multi-purpose key usage.
- Implementation: `useMultiPurposeKey(flag)` with `SecureRandom(flag)`.
- Solve: run action, capture emitted flag.

### MASTG-TEST-0309 - Reused IV (Reference)
- What is vulnerable: static IV reuse.
- Implementation: `HardcodedKeys.reusedIv` in `reuseIv(flag = null)`.
- Solve: run action, capture emitted flag.

### MASTG-TEST-0310 - Reused IV (Runtime)
- What is vulnerable: predictable IV from flag-derived bytes.
- Implementation: `flag.toByteArray().copyOf(16)` in `reuseIv(flag)`.
- Solve: run action, capture emitted flag.

### MASTG-TEST-0312 - Explicit Crypto Provider
- What is vulnerable: explicit provider pinning.
- Implementation: `Cipher.getInstance(..., "AndroidOpenSSL")` in `useExplicitProvider`.
- Solve: run action, capture emitted flag.

## MASVS-NETWORK

### MASTG-TEST-0217 - Insecure TLS Protocols Allowed in Code
- What is vulnerable: legacy TLS protocols enabled.
- Implementation: `InsecureTlsConfig.allowedProtocols = ["TLSv1", "TLSv1.1"]`.
- Solve: static analysis of `InsecureTlsConfig.proofToken`, derive with `install_seed`.

### MASTG-TEST-0218 - Insecure TLS Protocols in Traffic
- What is vulnerable: TLSv1 negotiated in probe.
- Implementation: `SSLContext.getInstance("TLSv1")` in `InsecureTlsTrafficProbe.runProbe`.
- Solve: run probe, hook `RuntimeFlagSink.emit`.

### MASTG-TEST-0233 - Hardcoded HTTP URLs
- What is vulnerable: cleartext hardcoded endpoint.
- Implementation: `HardcodedEndpoints.httpBaseUrl` and local server route `/api/public`.
- Solve: run action, intercept request with `?flag=...` and/or response body.

### MASTG-TEST-0234 - Missing Hostname Verification with SSLSocket
- What is vulnerable: raw SSL socket pattern without hostname verification.
- Implementation: `InsecureSslSocketClient.proofToken` + socket creation.
- Solve: static token extraction + `install_seed` derivation.

### MASTG-TEST-0235 - Cleartext Allowed by Configuration
- What is vulnerable: app-level cleartext allowed.
- Implementation: `android:usesCleartextTraffic="true"`, NSC cleartext, and token in manifest/meta-data.
- Solve: inspect `AndroidManifest.xml` + `network_security_config.xml`, use token to derive flag.

### MASTG-TEST-0236 - Cleartext Traffic Observed
- What is vulnerable: login over HTTP.
- Implementation: GET `http://127.0.0.1:8088/api/network/cleartext-login?flag=...`.
- Solve: run action; intercept query parameter or hook runtime emit.

### MASTG-TEST-0237 - Cross-platform Config Allows Cleartext
- What is vulnerable: embedded cross-platform cleartext config.
- Implementation: `assets/cross_platform_config.json` with `proof` token read by `CrossPlatformConfig`.
- Solve: static extract `proof`, derive with `install_seed`.

### MASTG-TEST-0238 - Runtime Network API Cleartext Use
- What is vulnerable: runtime cleartext telemetry call.
- Implementation: GET `/api/network/runtime-cleartext?flag=...`.
- Solve: intercept request param or hook runtime emit.

### MASTG-TEST-0239 - Low-level Socket HTTP
- What is vulnerable: custom raw socket HTTP bypassing safer stacks.
- Implementation: `RawSocketHttpClient.getText` sends manual HTTP over socket.
- Solve: intercept `?flag=...` or hook runtime emit.

### MASTG-TEST-0242 - Missing Certificate Pinning in NSC
- What is vulnerable: unpinned domain accepted.
- Implementation: HTTPS client to `https://nopin.hexvulnmob.local/?flag=...` with no pin enforcement.
- Solve: intercept HTTPS request parameter.

### MASTG-TEST-0243 - Expired Certificate Pins
- What is vulnerable: expired pin-set fallback behavior.
- Implementation: `pin-set expiration="2023-01-01"` in NSC + token `PinningNotes.expiredPinToken`.
- Solve: static inspect NSC + token, derive flag.

### MASTG-TEST-0244 - Missing Pinning in Runtime Traffic
- What is vulnerable: non-pinned HTTPS POST path.
- Implementation: POST body includes `flag=...` in `NonPinnedHttpsClient.fetch(body=...)`.
- Solve: intercept POST body or hook runtime emit.

### MASTG-TEST-0282 - Unsafe Custom Trust Evaluation
- What is vulnerable: trust-all trust manager.
- Implementation: `InsecureTrustManager.checkServerTrusted` accepts all certs.
- Solve: static token `InsecureTrustManager.proofToken`, derive with `install_seed`.

### MASTG-TEST-0283 - Unsafe Hostname Verification
- What is vulnerable: permissive verifier logic.
- Implementation: `BadHostnameVerifier.verify` accepts host containing `hexvulnmob`.
- Solve: static token extraction + derivation.

### MASTG-TEST-0284 - Incorrect WebView SSL Handling
- What is vulnerable: SSL errors ignored.
- Implementation: `InsecureWebViewClient.onReceivedSslError -> handler.proceed()`.
- Solve: static token extraction + derivation.

### MASTG-TEST-0285 - Legacy User-CA Trust Behavior
- What is vulnerable: legacy trust assumptions.
- Implementation: `LegacyTrustNotes.legacyTrustToken` and API-level check helper.
- Solve: static token extraction + derivation.

### MASTG-TEST-0286 - Explicit User-CA Trust in NSC
- What is vulnerable: `<certificates src="user"/>` explicitly trusted.
- Implementation: NSC trust anchors include user CAs + token `NetworkConfigNotes.userCaToken`.
- Solve: static config + token extraction, derive flag.

### MASTG-TEST-0295 - Security Provider Not Updated
- What is vulnerable: stale provider status model.
- Implementation: `SecurityProviderStatus.proofToken` with no real update flow.
- Solve: static token extraction + derivation.

## MASVS-PLATFORM

### MASTG-TEST-0250 - Content Provider Access in WebViews (Reference)
- What is vulnerable: content-access WebView pattern.
- Implementation: WebView launched with content mode and JS alert containing flag.
- Solve: run action, read alert value.

### MASTG-TEST-0251 - Content Provider Access in WebViews (Runtime)
- What is vulnerable: runtime content WebView with sensitive query parameter.
- Implementation: base URL built with `?flag=...` and runtime emit.
- Solve: inspect WebView URL/traffic or hook runtime emit.

### MASTG-TEST-0252 - Local File Access in WebViews (Reference)
- What is vulnerable: local file WebView exposure.
- Implementation: app writes `filesDir/webview_file_flag_0252.html` at startup.
- Solve: open file WebView and read flag from file content.

### MASTG-TEST-0253 - Local File Access in WebViews (Runtime)
- What is vulnerable: file-access WebView + runtime-sensitive flow.
- Implementation: loads `webview_file_flag_0253.html` and emits flag.
- Solve: read file or hook runtime emit.

### MASTG-TEST-0258 - Keyboard Caching Risk
- What is vulnerable: sensitive input rendered without hardening.
- Implementation: opens input UI (`PlatformUiActivity`) and emits runtime flag.
- Solve: hook `RuntimeFlagSink.emit` during action.

### MASTG-TEST-0289 - Screenshot Exposure When Backgrounded
- What is vulnerable: sensitive screen without screenshot protections.
- Implementation: sensitive display shown in `PlatformUiActivity`; flag via runtime emit.
- Solve: hook runtime emit and validate background/screenshot behavior.

### MASTG-TEST-0291 - Screen Capture Prevention API References
- What is vulnerable: reference-only challenge for anti-capture controls.
- Implementation: static token `PlatformProofs.flagSecureRefToken`.
- Solve: extract token + `install_seed`, derive flag.

### MASTG-TEST-0292 - Recents Screenshot Protection Missing
- What is vulnerable: recents snapshot can expose sensitive UI.
- Implementation: recents demo screen + runtime emit.
- Solve: run action, hook runtime emit; verify recents exposure.

### MASTG-TEST-0293 - SurfaceView Secure Flag Missing
- What is vulnerable: `SurfaceView` not secured against capture.
- Implementation: SurfaceView screen + runtime emit.
- Solve: run action, hook runtime emit.

### MASTG-TEST-0294 - Compose SecureOn Missing
- What is vulnerable: compose dialog screenshot protection reference gap.
- Implementation: static token `PlatformProofs.composeToken`.
- Solve: static token extraction + derivation.

### MASTG-TEST-0315 - Sensitive Data in Notifications
- What is vulnerable: notification leaks account data + flag.
- Implementation: `PlatformActionRunner.showNotification` sets `contentText` containing `flag=...`.
- Solve: run action, read notification text (or hook runtime emit).

### MASTG-TEST-0316 - Sensitive Data in Text Inputs
- What is vulnerable: plaintext sensitive value displayed in input field.
- Implementation: input screen shows `flag=...` in `PlatformUiActivity`.
- Solve: run action and read field value (or hook runtime emit).

### MASTG-TEST-0320 - WebView Storage Cleanup Missing
- What is vulnerable: sensitive data survives in WebView storage path.
- Implementation: cleanup mode WebView with `?flag=...` and storage enabled.
- Solve: run action, inspect URL/storage artifacts or hook runtime emit.

## MASVS-PRIVACY

### MASTG-TEST-0206 - Undeclared PII in Traffic
- What is vulnerable: PII sent over cleartext.
- Implementation: request to `/api/privacy/pii?email=...&flag=...`.
- Solve: intercept network request or hook runtime emit.

### MASTG-TEST-0254 - Dangerous Permissions
- What is vulnerable: broad dangerous permission profile.
- Implementation: writes `files/privacy_permissions.txt` including `flag=...`.
- Solve: run action and read generated file.

### MASTG-TEST-0255 - Permission Requests Not Minimized
- What is vulnerable: overbroad permission request set.
- Implementation: requests contacts + location + camera via `ActivityCompat.requestPermissions`.
- Solve: run action and capture runtime-emitted flag.

### MASTG-TEST-0256 - Missing Permission Rationale
- What is vulnerable: permission request flow without rationale.
- Implementation: requests `READ_PHONE_STATE` directly.
- Solve: run action and capture runtime-emitted flag.

### MASTG-TEST-0257 - Unused Permissions Not Reset
- What is vulnerable: stale permission handling pattern.
- Implementation: log-only flow plus runtime emit.
- Solve: run action and capture runtime-emitted flag.

### MASTG-TEST-0318 - Sensitive SDK API References
- What is vulnerable: static reference to sensitive SDK data access.
- Implementation: token `PrivacyTrackingSdk.sdkReferenceToken`.
- Solve: static token extraction + `install_seed` derivation.

### MASTG-TEST-0319 - Sensitive SDK API Runtime Use
- What is vulnerable: runtime profile collection from SDK-like component.
- Implementation: `PrivacyTrackingSdk.collectProfile()` invoked and flag emitted.
- Solve: run action and hook runtime emit.

## MASVS-RESILIENCE

### MASTG-TEST-0224 - Insecure Signature Version Usage
- What is vulnerable: weak signing scheme reference.
- Implementation: writes `files/signing_report.txt` with `flag=...`.
- Solve: run action and read file.

### MASTG-TEST-0225 - Insecure Signature Key Size
- What is vulnerable: weak signing key size reference.
- Implementation: writes `files/signing_keysize.txt` with `flag=...`.
- Solve: run action and read file.

### MASTG-TEST-0226 - Debuggable Manifest Flag Enabled
- What is vulnerable: app debuggable in manifest.
- Implementation: checks `ApplicationInfo.FLAG_DEBUGGABLE`; token in `ResilienceProofs.debuggableToken`.
- Solve: static token + `install_seed` derivation (and verify manifest setting).

### MASTG-TEST-0227 - WebView Debugging Enabled
- What is vulnerable: WebView debugging turned on.
- Implementation: `WebView.setWebContentsDebuggingEnabled(true)`.
- Solve: run action and capture runtime-emitted flag.

### MASTG-TEST-0247 - Secure Screen Lock API References
- What is vulnerable: reference-only secure lock detection path.
- Implementation: token `ResilienceProofs.secureLockRefToken`.
- Solve: static token extraction + derivation.

### MASTG-TEST-0249 - Secure Screen Lock Runtime Use
- What is vulnerable: runtime lock-state dependency.
- Implementation: `KeyguardManager.isDeviceSecure` check and action output may include `flag=...`.
- Solve: run action; read action output or hook runtime emit.

### MASTG-TEST-0263 - StrictMode Violations Logged
- What is vulnerable: strictmode events leak sensitive flow markers.
- Implementation: `StrictMode.noteSlowCall` + log + `flag=...` output path.
- Solve: run action; capture output/runtime emit.

### MASTG-TEST-0264 - Runtime StrictMode API Use
- What is vulnerable: strict mode enabled in runtime-sensitive flow.
- Implementation: `StrictMode.setThreadPolicy(...)` with optional `flag=...` output.
- Solve: run action; capture output/runtime emit.

### MASTG-TEST-0265 - StrictMode API References
- What is vulnerable: reference-only strictmode detection challenge.
- Implementation: token `ResilienceProofs.strictModeRefToken`.
- Solve: static token extraction + derivation.

### MASTG-TEST-0288 - Debug Symbols in Native Binaries
- What is vulnerable: native symbol leakage pattern.
- Implementation: writes `files/native_symbols.txt` with `flag=...`.
- Solve: run action and read file.

## MASVS-STORAGE

### MASTG-TEST-0200 - Files Written to External Storage
- What is vulnerable: external app-specific storage write.
- Implementation: `getExternalFilesDir()` writes `external_flag.txt`; runtime emit.
- Solve: run action, hook emit (file contains sample payload).

### MASTG-TEST-0201 - Runtime External Storage APIs
- What is vulnerable: public external storage API usage.
- Implementation: writes `/sdcard/Download/public_flag.txt`; runtime emit.
- Solve: run action, hook emit (file contains sample payload).

### MASTG-TEST-0202 - External Storage API/Permission References
- What is vulnerable: unprotected external artifact path.
- Implementation: writes real flag as `secret=<flag>` to `Download/public_flag.txt`.
- Solve: run action and read public file.

### MASTG-TEST-0203 - Runtime Logging APIs
- What is vulnerable: sensitive data logged.
- Implementation: `logSensitiveData` writes `flag=...` to logcat/stdout.
- Solve: run action and read logcat.

### MASTG-TEST-0207 - Unencrypted Sandbox Storage at Runtime
- What is vulnerable: plaintext internal file write.
- Implementation: writes `files/internal_flag.txt`; runtime emit.
- Solve: run action and capture runtime-emitted flag.

### MASTG-TEST-0216 - Sensitive Data Not Excluded from Backup
- What is vulnerable: backup-eligible prefs include sensitive marker.
- Implementation: writes `shared_prefs/backup_prefs.xml` with `flag=...`; runtime emit.
- Solve: run action and inspect backup prefs file.

### MASTG-TEST-0231 - Logging API References
- What is vulnerable: logging path statically/runtime reachable.
- Implementation: logs with both payload and flag.
- Solve: run action and read logcat.

### MASTG-TEST-0262 - Backup Config References Not Excluding Sensitive Data
- What is vulnerable: backup config tokenized as insecure reference.
- Implementation: `backup_config_token`/`backup_config_flag` in manifest + backup prefs flow.
- Solve: inspect manifest + backup prefs artifacts.

### MASTG-TEST-0287 - SharedPreferences Unencrypted Sensitive Data
- What is vulnerable: plaintext secret in `SharedPreferences`.
- Implementation: writes `storage_prefs.xml` key `flag`.
- Solve: run action and inspect shared prefs file.

### MASTG-TEST-0304 - SQLite Unencrypted Sensitive Data
- What is vulnerable: plaintext secret in SQLite row.
- Implementation: writes to `storage_plain.db` table `secrets`.
- Solve: run action and inspect DB row.

### MASTG-TEST-0305 - DataStore Unencrypted Sensitive Data
- What is vulnerable: plaintext secret in DataStore preferences.
- Implementation: writes to `storage_datastore.preferences_pb`.
- Solve: run action and inspect datastore file.

### MASTG-TEST-0306 - Room DB Unencrypted Sensitive Data
- What is vulnerable: plaintext secret in Room DB.
- Implementation: inserts into `storage_room.db` via DAO.
- Solve: run action and inspect Room database.

## 5. Useful Locations

- Challenge definitions: `app/src/main/assets/mstg_test_cases.json`
- Flag derivation: `app/src/main/java/com/hexvulnmob/data/FlagEngine.kt`
- Category engines:
- `app/src/main/java/com/hexvulnmob/CodeChallengeEngine.kt`
- `app/src/main/java/com/hexvulnmob/CryptoChallengeEngine.kt`
- `app/src/main/java/com/hexvulnmob/network/NetworkChallengeEngine.kt`
- `app/src/main/java/com/hexvulnmob/PlatformChallengeEngine.kt`
- `app/src/main/java/com/hexvulnmob/PrivacyChallengeEngine.kt`
- `app/src/main/java/com/hexvulnmob/ResilienceChallengeEngine.kt`
- `app/src/main/java/com/hexvulnmob/storage/StorageChallengeEngine.kt`
