# Native Android checklist (Kotlin / Java; also android/ in React Native and Flutter)

Loaded when `scan.json` lists `android`. `native-config-checks` and semgrep java/kotlin already cover the patterns they can grep; read the code for the rest. Also apply the OWASP Mobile Top 10.

- **Manifest:** no `debuggable`, `allowBackup="false"` (or backup rules excluding secrets), no `usesCleartextTraffic`; every `exported` activity / service / receiver / provider is intended and protected by a permission; intent filters do not expose sensitive actions; `FileProvider` paths are narrow.
- **Network:** `network_security_config` without cleartext or user-CA trust in release; no custom `TrustManager` / `HostnameVerifier` that accepts everything; certificate pinning for high-value APIs.
- **Storage:** tokens and keys in EncryptedSharedPreferences / Keystore, not plain `SharedPreferences`, files or SQLite; nothing sensitive on external storage; no secrets in `strings.xml`, `BuildConfig` or `google-services.json` that grant more than client access.
- **WebView:** `javaScriptEnabled` only for trusted content, `addJavascriptInterface` only with `@JavascriptInterface` methods that validate input, no `setAllowFileAccess(true)` / universal access, `loadUrl` never fed an unvalidated URL or deep-link parameter.
- **Deep links / intents:** parameters validated, no auth bypass by opening an internal screen directly, `PendingIntent` is `FLAG_IMMUTABLE`.
- **Release build:** signed with a release keystore (not the debug key), `minifyEnabled` / R8 on, no logs of tokens or PII (`Log.d`), no test or staging endpoints.
- **Dependencies:** `gradle.lockfile` (or dependency locking) present so the audit can read versions.

## Root, jailbreak and tamper resistance (OWASP Mobile M7, MASVS-RESILIENCE)

- Rooted / jailbroken device detection exists (RootBeer, Play Integrity, freeRASP) and runs at startup and before sensitive actions, not only once on a splash screen.
- The result is acted on: sensitive features (payments, tokens, PII) are blocked or limited, and the decision is enforced server-side where possible. A check that only shows a toast is cosmetic.
- Server-side attestation (Play Integrity / App Attest / DeviceCheck) for high-value APIs; the verdict is verified on the backend, never trusted from the client.
- Debugger, emulator, hooking-framework (Frida / Xposed) and repackaging (signature check) detection for high-risk apps.
- Release builds are obfuscated (R8 / ProGuard, `--obfuscate --split-debug-info` for Flutter, Hermes + minify for React Native) and contain no debug symbols or test endpoints.
- Say plainly in the report that client-side checks can be bypassed: they raise the cost of an attack, they do not stop one.
