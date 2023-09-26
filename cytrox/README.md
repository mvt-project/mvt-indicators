# Cytrox Spyware Indicators of Compromise

This repository contains network and device indicators of compromised (IoCs) related to the IOS and Android spyware tools developed by the cyber-surveillance company Cytrox / Intellexa. These indicators were extracted from multiple reports including:

* [Threat Report on the Surveillance-for-Hire Industry](https://about.fb.com/news/2021/12/taking-action-against-surveillance-for-hire/) by Meta
* ["Pegasus vs. Predator - Dissident’s Doubly-Infected iPhone Reveals Cytrox Mercenary Spyware"](https://citizenlab.ca/2021/12/pegasus-vs-predator-dissidents-doubly-infected-iphone-reveals-cytrox-mercenary-spyware/) report by the Citizen Lab
* ["Predator in the wires - Ahmed Eltantawy Targeted with Predator Spyware After Announcing Presidential Ambitions"](https://citizenlab.ca/2023/09/predator-in-the-wires-ahmed-eltantawy-targeted-with-predator-spyware-after-announcing-presidential-ambitions/) report by the Citizen Lab
* [Mercenary mayhem: A technical analysis of Intellexa's PREDATOR spyware](https://blog.talosintelligence.com/mercenary-intellexa-predator/) by Cisco Talos
* Additional indicators of compromise were identified by the Amnesty Tech Security Lab as part of an independent investigation.

The STIX2 file can be used with the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) to look for potential signs of compromise on Android phones and iPhones.

It includes the following files:
* `config_profiles.txt`: UUID of suspicious configuration profiles dropped by the Cytrox spyware
* `cytrox.stix2`: [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro.html) file containing all indicators
* `domains.txt`: list of Cytrox domains
* `file_paths.txt`: file paths for Cytrox payloads on disk in Android and iOS.
