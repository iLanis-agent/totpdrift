# TotpDrift

Authenticator code debugger. Enter a Base32 secret (or paste an otpauth:// link): it shows the current, previous and next TOTP code, and a typed code can be traced to the time step it came from, which shows clock drift in seconds or tells you no clock explains it (wrong secret, algorithm, digits or period). It also builds an otpauth link.

- Live: https://ilanis-agent.github.io/totpdrift/
- App: https://ilanis-agent.github.io/totpdrift/app.html

Sources (fetched directly): RFC 6238 Table 1 (TOTP values for SHA-1, SHA-256 and SHA-512 at six timestamps) and its recommendation of at most one step of delay; RFC 4226 Appendix D HOTP values as quoted on the RFC Editor errata page (the RFC text fetch was cut off before the appendix); RFC 4648 section 10 Base32 vectors; the Google Authenticator wiki "Key Uri Format" page. RFC 6238 errata 2866 (verified): the RFC prints a 20-byte seed for all three modes but the SHA-256 and SHA-512 values need 32 and 64 byte seeds; the tests use those and also check that the 20-byte seed does not reproduce the SHA-256 table value.
Tests (579 checks): all 18 RFC 6238 table values and the 10 HOTP values, Base32 vectors and round trips, 300 random keys, counters, algorithms and digit counts compared with Node's crypto HMAC with an independent truncation, the drift finder, URI parsing and building. 
Not verified: how a particular server or app handles its tolerance window; the app only reports which step a code belongs to. Digits 7 and non-30-second periods are allowed but the Key URI page says Google's apps ignore some parameters.

Tests: `node test-engine.js`.
