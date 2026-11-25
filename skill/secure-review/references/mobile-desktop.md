# Mobile checklist (React Native, native iOS)

## React Native

- Secrets embedded in the JS bundle or `.env` compiled into the app (the
  bundle is readable).
- Tokens in `AsyncStorage` instead of Keychain/Keystore (e.g. a secure-store
  library).
- `WebView` with `originWhitelist={['*']}`, `javaScriptEnabled` on untrusted
  content, or `onMessage` handlers trusting any page.
- Deep link handlers performing actions from URL parameters.
- Certificate pinning absent for high-value APIs (note-only unless required).

## Native iOS side (ios/ in React Native apps)

- Tokens in `UserDefaults` instead of Keychain; secrets in `Info.plist`.
- `NSAllowsArbitraryLoads` in App Transport Security.
- `WKWebView` message handlers exposed to remote pages; universal link / URL
  scheme handlers acting on parameters without validation.
- Sensitive screens not hidden in the app-switcher snapshot.

## Root, jailbreak and tamper resistance (OWASP Mobile M7, MASVS-RESILIENCE)

- Rooted / jailbroken device detection exists (jail-monkey, freeRASP, IOSSecuritySuite) and runs at startup and before sensitive actions, not only once on a splash screen.
- The result is acted on: sensitive features (payments, tokens, PII) are blocked or limited, and the decision is enforced server-side where possible. A check that only shows a toast is cosmetic.
- Server-side attestation (Play Integrity / App Attest / DeviceCheck) for high-value APIs; the verdict is verified on the backend, never trusted from the client.
- Debugger, emulator, hooking-framework (Frida / Xposed) and repackaging (signature check) detection for high-risk apps.
- Release builds are obfuscated (R8 / ProGuard, `--obfuscate --split-debug-info` for Flutter, Hermes + minify for React Native) and contain no debug symbols or test endpoints.
- Say plainly in the report that client-side checks can be bypassed: they raise the cost of an attack, they do not stop one.
