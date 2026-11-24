# Java / Kotlin service checklist (Spring, Ktor, Jakarta EE, plain servlets)

Loaded when `scan.json` lists `jvm`. Scanners (semgrep java/kotlin/findsecbugs, osv-scanner on `pom.xml` / `gradle.lockfile`) cover known patterns; read the code for the rest.

- **Access control (A01):** every endpoint has an authorization check (`@PreAuthorize`, `SecurityFilterChain` rules, route guards); object ids are checked against the caller (IDOR); no `permitAll()` / `anyRequest().permitAll()` on private routes; actuator endpoints not exposed unauthenticated.
- **Injection (A03):** SQL/JPQL/HQL built with `+` or `String.format` (use bind parameters / `@Param`); `Runtime.exec` / `ProcessBuilder` with user input; SpEL / template injection; XXE (disable DTDs on every XML parser); unsafe deserialization (`ObjectInputStream`, Jackson default typing, `enableDefaultTyping`).
- **Mass assignment (A04):** entities bound straight from request bodies; use DTOs and allow-lists.
- **Crypto and secrets (A02):** MD5/SHA-1/DES/ECB, `java.util.Random` for tokens (use `SecureRandom`), hardcoded keys, passwords in `application.properties` / `application.yml` or committed profiles; passwords hashed with BCrypt/Argon2.
- **Config (A05):** CSRF disabled on cookie-session apps, permissive CORS (`*` with credentials), H2 console or Swagger/actuator left on in production, verbose stack traces returned to clients, debug logging of requests.
- **SSRF (A10):** `RestTemplate` / `WebClient` / `HttpClient` calling a user-supplied URL without an allow-list.
- **Logging (A09):** secrets or tokens in logs, log injection from unsanitised input, no audit log for auth events.
- **Supply chain (A06/A08):** versions pinned (no `LATEST`, `+` or `RELEASE` ranges); `gradle.lockfile` / dependency locking enabled; `mavenLocal()` or plain-`http` repositories not used.
