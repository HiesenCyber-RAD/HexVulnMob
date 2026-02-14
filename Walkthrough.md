# HEXVulnMob Detailed Walkthrough

This file gives step-by-step solving instructions for every implemented challenge.

> [!WARNING]
> This application is developed with the help of AI tools, if you find any issues with the applicaiton, please rainse an issue and we will try to solve them as soon as possible.

> [!CAUTION]
> Use this app and techniques explained here only in authorized labs for security training. Do not apply these patterns or techniques to systems you do not own or have explicit permission to test.

## 0. Lab Setup (Do Once)

1. Install and launch the debug app build.
2. Keep these tools ready: `adb`, `jadx` (or apktool), Burp/mitmproxy, and Frida (optional but useful).
3. Open terminal and keep logcat filtered:
   ```bash
   adb logcat | grep HEXVulnMob
   ```
4. Pull install seed (needed for static/derived challenges):
   ```bash
   adb shell run-as com.hexvulnmob cat shared_prefs/hexvulnmob_flags.xml
   ```
5. Note `install_seed` value.

## 1. Flag Derivation Formula (For Static/Reference Challenges)

1. Get `install_seed` from `shared_prefs/hexvulnmob_flags.xml`.
2. Extract challenge proof token from code/config/manifest.
3. Compute:
   - payload: `install_seed:MASTG-TEST-XXXX:proofToken`
   - digest: first 12 hex chars of `sha256(payload)`
4. Final flag format:
   - `HEXFLAG{MASTG-TEST-XXXX-<12hex>}`

## 2. MASVS-CODE

### MASTG-TEST-0222 - Position Independent Code (PIC) Not Enabled
1. Open challenge and note ID.
2. Decompile/search `NativeProtectionNotes.picDisabledSeed`.
3. Copy seed from `app/src/main/java/com/hexvulnmob/NativeProtectionNotes.kt`.
4. Derive with formula using `install_seed` + seed.
5. Submit flag.

### MASTG-TEST-0223 - Stack Canaries Not Enabled
1. Open challenge.
2. Extract `NativeProtectionNotes.stackCanarySeed`.
3. Use formula with `install_seed` + `stackCanarySeed`.
4. Build final `HEXFLAG{...}`.
5. Submit.

### MASTG-TEST-0245 - References to Platform Version APIs
1. Open challenge.
2. Extract `BuildVersionReferences.platformApiSeed` from `app/src/main/java/com/hexvulnmob/BuildVersionReferences.kt`.
3. Derive flag with formula.
4. Verify format.
5. Submit.

### MASTG-TEST-0272 - Dependencies with Known Vulnerabilities in Project
1. Open challenge.
2. Extract `DependencyNotes.depsSeed` from `app/src/main/java/com/hexvulnmob/DependencyNotes.kt`.
3. Derive flag with `install_seed` + `depsSeed`.
4. Submit.

### MASTG-TEST-0274 - Dependencies with Known Vulnerabilities in SBOM
1. Open challenge.
2. Extract `DependencyNotes.sbomSeed` in the same file.
3. Derive using formula.
4. Submit.

## 3. MASVS-CRYPTO

### MASTG-TEST-0204 - Insecure Random API Usage
1. Open challenge and tap **Generate Random Token**.
2. Read returned text for `flag=...`.
3. If not visible, hook `RuntimeFlagSink.emit`.
4. Submit flag.

### MASTG-TEST-0205 - Non-random Sources Usage
1. Tap **Generate Timestamp Token**.
2. Capture `flag=...` from action result.
3. Fallback: hook `RuntimeFlagSink.emit`.
4. Submit.

### MASTG-TEST-0208 - Insufficient Key Sizes
1. Tap **Generate Weak Key**.
2. Capture `flag=...` from output.
3. Fallback: runtime hook.
4. Submit.

### MASTG-TEST-0212 - Hardcoded Cryptographic Keys in Code
1. Tap **Use Hardcoded Key**.
2. Hook `RuntimeFlagSink.emit` (recommended).
3. Optional: hook `Cipher.init` / `doFinal` to confirm flow.
4. Submit captured flag.

### MASTG-TEST-0221 - Broken Symmetric Encryption Algorithms
1. Tap **Use Broken Algorithm**.
2. Confirm DES/ECB usage in `CryptoActionRunner.useBrokenAlgorithm`.
3. Hook `RuntimeFlagSink.emit` to get flag.
4. Submit.

### MASTG-TEST-0232 - Broken Symmetric Encryption Modes
1. Tap **Use Broken Mode**.
2. Confirm AES/ECB in `CryptoActionRunner.useBrokenMode`.
3. Hook runtime emit and capture flag.
4. Submit.

### MASTG-TEST-0307 - Asymmetric Key Used for Multiple Purposes (Reference)
1. Tap **Log Multi-Purpose Key**.
2. Validate code path signs and encrypts with same key in `useMultiPurposeKey(null)`.
3. Capture flag via `RuntimeFlagSink.emit`.
4. Submit.

### MASTG-TEST-0308 - Asymmetric Key Used for Multiple Purposes (Runtime)
1. Tap **Use Multi-Purpose Key**.
2. Capture flag via runtime emit.
3. Optionally inspect seed flow with `SecureRandom(flagBytes)`.
4. Submit.

### MASTG-TEST-0309 - Reused IV References
1. Tap **Log Reused IV**.
2. Confirm `HardcodedKeys.reusedIv` in code.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0310 - Reused IV Runtime Use
1. Tap **Use Reused IV**.
2. Confirm IV from `flag.toByteArray().copyOf(16)`.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0312 - Explicit Security Provider in Crypto APIs
1. Tap **Use Explicit Provider**.
2. Confirm provider call in code: `Cipher.getInstance(..., "AndroidOpenSSL")`.
3. Capture flag through runtime emit.
4. Submit.

## 4. MASVS-NETWORK

### MASTG-TEST-0217 - Insecure TLS Protocols Explicitly Allowed in Code
1. Open challenge.
2. Inspect `app/src/main/java/com/hexvulnmob/network/InsecureTlsConfig.kt`.
3. Extract `proofToken` and note weak protocols.
4. Derive flag with formula.
5. Submit.

### MASTG-TEST-0218 - Insecure TLS Protocols in Network Traffic
1. Tap **Run TLS Probe**.
2. Inspect code path in `InsecureTlsTrafficProbe.runProbe` (`TLSv1`).
3. Capture flag via `RuntimeFlagSink.emit` hook.
4. Submit.

### MASTG-TEST-0233 - Hardcoded HTTP URLs
1. Tap **Call Hardcoded HTTP URL**.
2. Intercept request to local server and capture query param `flag=...`.
3. Optionally confirm response body returns flag.
4. Submit.

### MASTG-TEST-0234 - Missing Hostname Verification with SSLSocket
1. Open challenge.
2. Inspect `InsecureSslSocketClient.proofToken` in code.
3. Derive flag with formula.
4. Submit.

### MASTG-TEST-0235 - App Configurations Allowing Cleartext Traffic
1. Inspect `app/src/main/AndroidManifest.xml` (`usesCleartextTraffic=true`).
2. Inspect `app/src/main/res/xml/network_security_config.xml` (cleartext allowed).
3. Extract token from `NetworkConfigNotes.cleartextAllowedToken` or manifest meta-data token.
4. Derive flag.
5. Submit.

### MASTG-TEST-0236 - Cleartext Traffic Observed on Network
1. Tap **Send Cleartext Login**.
2. Intercept request `/api/network/cleartext-login?flag=...`.
3. Capture flag from query or runtime emit.
4. Submit.

### MASTG-TEST-0237 - Cross-Platform Config Allowing Cleartext
1. Open `app/src/main/assets/cross_platform_config.json`.
2. Extract `proof` (or `referenceToken`).
3. Derive flag with formula.
4. Submit.

### MASTG-TEST-0238 - Runtime Network APIs Transmitting Cleartext
1. Tap **Send Cleartext Telemetry**.
2. Intercept `/api/network/runtime-cleartext?flag=...`.
3. Capture query flag or runtime emit.
4. Submit.

### MASTG-TEST-0239 - Low-level Socket HTTP Connection
1. Tap **Send Raw Socket Request**.
2. Confirm raw request path in `RawSocketHttpClient`.
3. Intercept `/api/network/lowlevel?flag=...`.
4. Submit.

### MASTG-TEST-0242 - Missing Certificate Pinning in NSC
1. Tap **Send HTTPS Request**.
2. Intercept request to `https://nopin.hexvulnmob.local/?flag=...`.
3. Capture flag from URL.
4. Submit.

### MASTG-TEST-0243 - Expired Certificate Pins in NSC
1. Inspect `network_security_config.xml`.
2. Note expired pin-set `expiration="2023-01-01"`.
3. Extract `PinningNotes.expiredPinToken`.
4. Derive flag with formula.
5. Submit.

### MASTG-TEST-0244 - Missing Certificate Pinning in Network Traffic
1. Tap **Send HTTPS Request**.
2. Intercept POST body and read `flag=...`.
3. Fallback: hook runtime emit.
4. Submit.

### MASTG-TEST-0282 - Unsafe Custom Trust Evaluation
1. Inspect `InsecureTrustManager.java`.
2. Confirm permissive trust checks.
3. Extract `proofToken`.
4. Derive flag and submit.

### MASTG-TEST-0283 - Incorrect Hostname Verification
1. Inspect `BadHostnameVerifier.java`.
2. Confirm weak verify logic.
3. Extract `proofToken`.
4. Derive flag and submit.

### MASTG-TEST-0284 - Incorrect SSL Error Handling in WebViews
1. Inspect `InsecureWebViewClient.java`.
2. Confirm `handler.proceed()` in `onReceivedSslError`.
3. Extract `proofToken`.
4. Derive and submit.

### MASTG-TEST-0285 - Outdated Android Version Trusting User CAs
1. Inspect `LegacyTrustNotes.kt`.
2. Extract `legacyTrustToken`.
3. Derive with formula.
4. Submit.

### MASTG-TEST-0286 - NSC Explicitly Trusts User CAs
1. Inspect `network_security_config.xml` for `<certificates src="user"/>`.
2. Extract `NetworkConfigNotes.userCaToken`.
3. Derive flag.
4. Submit.

### MASTG-TEST-0295 - GMS Security Provider Not Updated
1. Inspect `SecurityProviderStatus.kt`.
2. Extract `proofToken`.
3. Derive with formula.
4. Submit.

## 5. MASVS-PLATFORM

### MASTG-TEST-0250 - Content Provider Access in WebViews (Reference)
1. Tap **Open WebView Alert**.
2. Read JS alert popup value directly.
3. Submit shown flag.

### MASTG-TEST-0251 - Content Provider Access in WebViews (Runtime)
1. Tap **Open WebView**.
2. Inspect WebView base URL for `?flag=...`.
3. If not visible, hook runtime emit.
4. Submit.

### MASTG-TEST-0252 - Local File Access in WebViews (Reference)
1. Tap **Open File WebView**.
2. App loads `filesDir/webview_file_flag_0252.html`.
3. Read flag rendered in page.
4. Submit.

### MASTG-TEST-0253 - Local File Access in WebViews (Runtime)
1. Tap **Open File WebView**.
2. Read flag from loaded file if shown.
3. Fallback: capture from runtime emit.
4. Submit.

### MASTG-TEST-0258 - Keyboard Caching Attributes in UI Elements
1. Tap **Open Input Screen**.
2. Observe sensitive UI behavior.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0289 - Screenshot Exposure During Backgrounding
1. Tap **Open Sensitive Screen**.
2. Put app in recents/background and observe sensitive rendering behavior.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0291 - Screen Capture Prevention API References
1. Inspect `PlatformProofs.flagSecureRefToken`.
2. Derive flag using formula.
3. Submit.

### MASTG-TEST-0292 - setRecentsScreenshotEnabled Not Used
1. Tap **Open Recents Screen**.
2. Validate recents snapshot behavior.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0293 - setSecure Not Used in SurfaceView
1. Tap **Open SurfaceView Screen**.
2. Observe SurfaceView protection behavior.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0294 - SecureOn Not Used in Compose Dialogs
1. Extract `PlatformProofs.composeToken`.
2. Derive with formula.
3. Submit.

### MASTG-TEST-0315 - Sensitive Data Exposed via Notifications
1. Tap **Send Notification**.
2. Open notification shade.
3. Read `flag=...` in notification content.
4. Submit.

### MASTG-TEST-0316 - Authentication Data Exposed in Text Input
1. Tap **Open Input Screen**.
2. Read input field value containing `flag=...`.
3. Submit.

### MASTG-TEST-0320 - WebViews Not Cleaning Up Sensitive Data
1. Tap **Open WebView**.
2. Inspect base URL/data path for `?flag=...`.
3. Fallback: runtime emit hook.
4. Submit.

## 6. MASVS-PRIVACY

### MASTG-TEST-0206 - Undeclared PII in Network Traffic
1. Tap **Send PII Request**.
2. Intercept `/api/privacy/pii?email=...&flag=...`.
3. Capture flag or runtime emit.
4. Submit.

### MASTG-TEST-0254 - Dangerous App Permissions
1. Tap **Write Permissions Report**.
2. Read `/data/data/com.hexvulnmob/files/privacy_permissions.txt`.
3. Extract `flag=...`.
4. Submit.

### MASTG-TEST-0255 - Permission Requests Not Minimized
1. Tap **Request Permissions**.
2. Observe broad permission prompt set.
3. Capture flag via runtime emit hook.
4. Submit.

### MASTG-TEST-0256 - Missing Permission Rationale
1. Tap **Request Permission**.
2. Observe request flow lacking rationale.
3. Capture runtime emitted flag.
4. Submit.

### MASTG-TEST-0257 - Not Resetting Unused Permissions
1. Tap **Log Unused Permission**.
2. Confirm behavior in logs.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0318 - References to Sensitive SDK API Use
1. Extract `PrivacyTrackingSdk.sdkReferenceToken`.
2. Derive flag using formula.
3. Submit.

### MASTG-TEST-0319 - Runtime Sensitive SDK API Use
1. Tap **Run SDK Usage**.
2. Hook runtime emit and capture flag.
3. Optionally confirm `PrivacyTrackingSdk.collectProfile()` execution.
4. Submit.

## 7. MASVS-RESILIENCE

### MASTG-TEST-0224 - Insecure Signature Version
1. Tap **Write Signing Report**.
2. Open `/data/data/com.hexvulnmob/files/signing_report.txt`.
3. Extract `flag=...`.
4. Submit.

### MASTG-TEST-0225 - Insecure Signature Key Size
1. Tap **Write Key Size Report**.
2. Open `files/signing_keysize.txt`.
3. Extract `flag=...`.
4. Submit.

### MASTG-TEST-0226 - Debuggable Flag Enabled in Manifest
1. Confirm `android:debuggable="true"` in `AndroidManifest.xml`.
2. Extract `ResilienceProofs.debuggableToken`.
3. Derive flag with formula.
4. Submit.

### MASTG-TEST-0227 - WebView Debugging Enabled
1. Tap **Enable WebView Debugging**.
2. Confirm `WebView.setWebContentsDebuggingEnabled(true)` behavior.
3. Capture runtime emitted flag.
4. Submit.

### MASTG-TEST-0247 - Secure Screen Lock API References
1. Inspect token `ResilienceProofs.secureLockRefToken`.
2. Confirm API reference path (`KeyguardManager.isDeviceSecure`).
3. Derive flag.
4. Submit.

### MASTG-TEST-0249 - Runtime Secure Screen Lock Detection
1. Tap **Check Secure Lock**.
2. Capture flag from action output (`flag=...`) or runtime emit.
3. Submit.

### MASTG-TEST-0263 - StrictMode Violation Logging
1. Tap **Log StrictMode**.
2. Capture `flag=...` from result or runtime emit.
3. Optionally inspect logcat for strictmode event.
4. Submit.

### MASTG-TEST-0264 - Runtime StrictMode API Use
1. Tap **Enable StrictMode**.
2. Capture `flag=...` from action output or runtime emit.
3. Submit.

### MASTG-TEST-0265 - StrictMode API References
1. Extract `ResilienceProofs.strictModeRefToken`.
2. Derive with formula.
3. Submit.

### MASTG-TEST-0288 - Debug Symbols in Native Binaries
1. Tap **Write Native Symbols**.
2. Open `/data/data/com.hexvulnmob/files/native_symbols.txt`.
3. Extract `flag=...`.
4. Submit.

## 8. MASVS-STORAGE

### MASTG-TEST-0200 - Files Written to External Storage
1. Tap **Write External File**.
2. Verify file `external_flag.txt` under app external files path.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0201 - Runtime External Storage API Use
1. Tap **Use External Storage API**.
2. Verify `/sdcard/Download/public_flag.txt` written.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0202 - External Storage API/Permission References
1. Tap **Write External API Flag**.
2. Open `/sdcard/Download/public_flag.txt`.
3. Extract `secret=HEXFLAG{...}`.
4. Submit.

### MASTG-TEST-0203 - Runtime Logging APIs
1. Tap **Log Sensitive Data**.
2. Read logcat for `logging secret=... flag=HEXFLAG{...}`.
3. Submit.

### MASTG-TEST-0207 - Runtime Unencrypted Sandbox Storage
1. Tap **Write Internal File**.
2. Confirm `files/internal_flag.txt` exists.
3. Capture flag via runtime emit.
4. Submit.

### MASTG-TEST-0216 - Sensitive Data Not Excluded from Backup
1. Tap **Write Backup Marker**.
2. Read `/data/data/com.hexvulnmob/shared_prefs/backup_prefs.xml`.
3. Extract `flag=...`.
4. Submit.

### MASTG-TEST-0231 - Logging API References
1. Tap **Log Sensitive Data**.
2. Read logcat tag `HEXVulnMob`.
3. Extract flag value.
4. Submit.

### MASTG-TEST-0262 - Backup Configuration References Not Excluding Sensitive Data
1. Tap **Write Backup Marker**.
2. Inspect `backup_prefs.xml`.
3. Inspect `AndroidManifest.xml` meta-data (`backup_config_token`, `backup_config_flag`).
4. Recover flag from stored artifact and submit.

### MASTG-TEST-0287 - SharedPreferences Unencrypted Sensitive Data
1. Tap **Write SharedPreferences**.
2. Open `/data/data/com.hexvulnmob/shared_prefs/storage_prefs.xml`.
3. Extract `flag` entry.
4. Submit.

### MASTG-TEST-0304 - SQLite Unencrypted Sensitive Data
1. Tap **Write SQLite**.
2. Open `/data/data/com.hexvulnmob/databases/storage_plain.db`.
3. Query table `secrets` and read `flag=...` in `secret` column.
4. Submit.

### MASTG-TEST-0305 - DataStore Unencrypted Sensitive Data
1. Tap **Write DataStore**.
2. Inspect `/data/data/com.hexvulnmob/datastore/storage_datastore.preferences_pb`.
3. Extract flag-containing value.
4. Submit.

### MASTG-TEST-0306 - Room DB Unencrypted Sensitive Data
1. Tap **Write Room**.
2. Open `/data/data/com.hexvulnmob/databases/storage_room.db`.
3. Query Room table for row containing `flag=...`.
4. Submit.

## 9. Useful Commands

- Internal files:
  ```bash
  adb shell run-as com.hexvulnmob ls files
  adb shell run-as com.hexvulnmob cat files/<name>
  ```
- Shared preferences:
  ```bash
  adb shell run-as com.hexvulnmob ls shared_prefs
  adb shell run-as com.hexvulnmob cat shared_prefs/<name>.xml
  ```
- Databases:
  ```bash
  adb shell run-as com.hexvulnmob ls databases
  ```
- External storage:
  ```bash
  adb shell ls /sdcard/Download
  adb shell cat /sdcard/Download/public_flag.txt
  ```

## 10. Ethics and Scope

Use only for authorized training. Do not apply these techniques against systems without explicit permission.
