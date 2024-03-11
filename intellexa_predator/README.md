# Predator Spyware Indicators of Compromise

This repository contains network and device indicators of compromised (IoCs) related to the IOS and Android Predator spyware tools developed by the cyber-surveillance company Intellexa (formerly Cytrox). These indicators were extracted from multiple reports including:

* [Threat Report on the Surveillance-for-Hire Industry](https://about.fb.com/news/2021/12/taking-action-against-surveillance-for-hire/) by Meta
* ["Pegasus vs. Predator - Dissident’s Doubly-Infected iPhone Reveals Cytrox Mercenary Spyware"](https://citizenlab.ca/2021/12/pegasus-vs-predator-dissidents-doubly-infected-iphone-reveals-cytrox-mercenary-spyware/) report by the Citizen Lab
* ["Predator in the wires - Ahmed Eltantawy Targeted with Predator Spyware After Announcing Presidential Ambitions"](https://citizenlab.ca/2023/09/predator-in-the-wires-ahmed-eltantawy-targeted-with-predator-spyware-after-announcing-presidential-ambitions/) report by the Citizen Lab
* [Mercenary mayhem: A technical analysis of Intellexa's PREDATOR spyware](https://blog.talosintelligence.com/mercenary-intellexa-predator/) by Cisco Talos
* [Predatorgate: Τι έγραφαν τα SMS-παγίδα που έλαβαν επιχειρηματίες, υπουργοί και δημοσιογράφοι](https://insidestory.gr/article/predatorgate-ti-egrafan-ta-sms-pagida-poy-elavan-epiheirimaties-ypoyrgoi-kai-dimosiografoi) by Inside Story
* [Active Lycantrox infrastructure illumination](https://blog.sekoia.io/active-lycantrox-infrastructure-illumination/) by Sekoia
* [Predator Spyware Operators Rebuild Multi-Tier Infrastructure to Target Mobile Devices](https://www.recordedfuture.com/predator-spyware-operators-rebuild-multi-tier-infrastructure-target-mobile-devices) by Recorded Future
* [The Predator spyware ecosystem is not dead](https://blog.sekoia.io/the-predator-spyware-ecosystem-is-not-dead/) by Sekoia
* Additional indicators of compromise were identified by the Amnesty Tech Security Lab as part of an independent investigation.

The STIX2 file can be used with the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) to look for potential signs of compromise on Android phones and iPhones.

It includes the following files:
* `config_profiles.txt`: UUID of suspicious configuration profiles dropped by the Predator spyware
* `predator.stix2`: [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro.html) file containing all indicators
* `domains.txt`: list of Predator domains
* `file_paths.txt`: file paths for Predator payloads on disk in Android and iOS.
