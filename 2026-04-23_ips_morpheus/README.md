# Morpheus Android spyware

Morpheus is an Android spyware likely developed in Italy by IPS Intelligence,
recently analyzed by the Italian NGO Osservatorio Nessuno.

Its capabilities include abusing accessibility features, automatically enabling 
ADB and issuing commands, disabling microphone and camera indicators, pairing 
additional WhatsApp devices, taking screenshots and recording audio and video.

The infection in the analyzed case was performed via social engineering, with the 
target receiving an SMS impersonating an Italian ISP.

Notably, this is the first sample of spyware directly linked to IPS Intelligence.

## Sources

- Osservatorio Nessuno: https://osservatorionessuno.org/blog/2026/04/morpheus-a-new-spyware-linked-to-ips-intelligence
- Media coverage: https://techcrunch.com/2026/04/24/another-spyware-maker-caught-distributing-fake-android-snooping-apps/

## Files

- **morpheus.stix2**: STIX2 indicators for use with MVT
- **domains.txt**:  C2 and delivery domains
- **ip-addresses.txt**:  C2 and infrastructure IPs
- **package_names.txt**: Android package names
