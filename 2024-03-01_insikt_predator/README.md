# Predator Spyware Indicators of Compromise from Instinkt Group

This repository contains network and device indicators of compromise (IoCs) published by Recorded Future’s Insikt Group related to the IOS and Android Predator spyware tools developed by the cyber-surveillance company Intellexa (formerly Cytrox). 

The indicators were published in the following report: [Predator Spyware Operators Rebuild Multi-Tier Infrastructure to Target Mobile Devices] (https://www.recordedfuture.com/predator-spyware-operators-rebuild-multi-tier-infrastructure-target-mobile-devices) report by the Recorded Future 

The STIX2 file can be used with the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) to look for potential signs of compromise on Android phones and iPhones.

It includes the following files:
* `config_profiles.txt`: UUID of suspicious configuration profiles dropped by the Predator spyware
* `predator.stix2`: [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro.html) file containing all indicators
* `domains.txt`: list of Predator domains
* `file_paths.txt`: file paths for Predator payloads on disk in Android and iOS.
