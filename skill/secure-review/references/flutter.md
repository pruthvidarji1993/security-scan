# Flutter checklist (Dart app, android/, ios/)

Loaded only when `scan.json` lists `flutter`. Source: OWASP Top 10:2025 guide,
Flutter angles. Headings show the 2025 id, then the code the report uses
(the report still maps to Top 10:2021). For the app itself also apply the
OWASP Mobile Top 10. `flutter-checks` in `scan.json` already covers the
patterns it can grep; read the code for the rest.

## Access control (2025 A01, report A01)

- A hidden screen or button is not access control: every API the app calls
  must enforce ownership and role on the backend.
- Supabase RLS / Firebase Security Rules present and tested for every
  table / collection the app reads or writes.
- Deep links and route guards cannot reach a protected screen or act on URL
  parameters without a login and server check.

## Misconfiguration (2025 A02, report A05)

- `AndroidManifest.xml`: no `debuggable`, `allowBackup="false"`, no
  needlessly `exported` activities / receivers / providers.
- iOS: no `NSAllowsArbitraryLoads`; no secrets in `Info.plist`.
- Release builds use the production flavor and endpoint, signed with a release
  key (not the debug key); no debug banners, test menus or staging URLs.

## Supply chain (2025 A03, report A06/A08)

- `pubspec.lock` committed; packages checked for maintenance and verified
  publisher; no `git:` / `path:` dependencies without a pinned ref.
- Native side (Gradle, CocoaPods) dependencies audited too.

## Cryptography (2025 A04, report A02)

- Tokens in `flutter_secure_storage`, never `SharedPreferences` / files.
- `Random.secure()` for tokens, OTPs, nonces; no hardcoded keys or IVs; no
  ECB, MD5 or SHA-1 for security.
- Certificate validation never disabled; pinning for high-value APIs.

## Injection (2025 A05, report A03)

- `sqflite` / `drift` raw queries use placeholders, not string building.
- Deep-link and `WebView` input validated; JavaScript off or restricted,
  JS channels validate every message, URLs allow-listed.

## Insecure design (2025 A06, report A04)

- Price, role and discounts are recomputed on the server, never trusted from
  the app. OTP, login and referral flows have server-side attempt limits.

## Authentication (2025 A07, report A07)

- Short-lived access token, refresh rotation, tokens cleared on logout and
  password change; biometric unlock tied to secure storage.

## Integrity (2025 A08, report A08)

- Play Integrity / App Attest if the backend must trust the app; remote
  config and downloaded content verified; webhooks signed server-side.

## Logging (2025 A09, report A09)

- Crashlytics / Sentry / analytics capture no tokens or personal data;
  `debugPrint` / `print` never log secrets.

## Exceptional conditions (2025 A10, report A05)

- `FlutterError.onError` and `PlatformDispatcher.instance.onError` (or
  `runZonedGuarded`) set; users see generic messages, never raw API errors.
- Failed security checks (auth refresh, permission, integrity) fail closed.
- Multi-step flows (payment then order) handle partial failure and retries.
