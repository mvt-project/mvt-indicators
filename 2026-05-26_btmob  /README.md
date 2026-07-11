# BTMOB Android RAT

BTMOB RAT, an Android malware family originating from 'SpySolr', was first discovered in 2025 by Cyble Research and Intelligence Labs. 
According to ESET, BTMOB is distributed via a Malware-as-a-Service model with lifetime licenses selling for only 5.000 dollars. It offers advanced malicious capabilities via `Accessibility Services`, including remote control and data exfiltration. 

In contrast to some other MaaS, which often focus only on banking data, it can be used as comparativley low-cost spyware. 
Based on data from any.run BTMOB is still activley deployed. 
 
## Sources
- ESET: https://www.welivesecurity.com/en/malware/btmob-stealthy-rat-burrowing-deep-android-devices/
- Cyble Research: https://cyble.com/blog/btmob-rat-newly-discovered-android-malware/
ANY.RUN: https://any.run/malware-trends/btmob/
- ThreatFox: https://threatfox.abuse.ch/browse/tag/BTMOB/
- Zimperium: https://github.com/Zimperium/IOC/tree/master/2025-04-BTMOB-RAT
- MalwareBazaar: https://bazaar.abuse.ch/browse.php?search=tag%3ABTMOB

## Files

- **btmob.stix2** STIX2 indicators for use with MVT
- **domains.txt** C2 and delivery domains
- **ip-addresses.txt** C2 and delivery IPs
- **sha256.txt** File hashes
