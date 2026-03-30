# DarkSword iOS Exploit Chain

Full-chain iOS exploit kit (iOS 18.4-18.7) leveraging six vulnerabilities
(CVE-2025-31277, CVE-2025-43529, CVE-2026-20700, CVE-2025-14174,
CVE-2025-43510, CVE-2025-43520) to deploy GHOSTKNIFE, GHOSTSABER,
and GHOSTBLADE payloads. Used by UNC6748, PARS Defense, and UNC6353
against targets in Saudi Arabia, Turkey, Malaysia, and Ukraine.

## Sources

- Google Threat Intelligence Group (GTIG): https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain
- iVerify: https://iverify.io/blog/darksword-ios-exploit-kit-explained
- Lookout: https://www.lookout.com/blog/darksword

## Files

- **darksword.stix2** — STIX2 indicators for use with MVT
- **domains.txt** — C2 and delivery domains
- **ip-addresses.txt** — C2 and infrastructure IPs
- **sha256.txt** — File hashes
- **file_paths.txt** — Filesystem artifacts written by the implant
- **file_names.txt** — Exploit chain JavaScript module filenames
