# Coruna / CryptoWaters Indicators of Compromise

This repository contains network and device indicators of compromise (IoCs) related to the Coruna exploit kit, PLASMAGRID implant, and the CryptoWaters campaign targeting iOS devices and cryptocurrency wallet applications. These indicators were compiled from multiple reports including:

* [Campaigns exploiting Signal, Line, and Google Chrome to target devices in multiple countries](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit) by Google Threat Analysis Group (TAG)
* [CryptoWaters: iVerify Discovers New iOS Threat Targeting Crypto Wallets](https://iverify.io/blog/coruna-inside-the-nation-state-grade-ios-exploit-kit-we-ve-been-tracking) by iVerify

The campaign has been attributed to two clusters tracked by Google TAG as UNC6353 and UNC6691. The Coruna exploit kit delivers a post-exploitation implant known as PLASMAGRID, which targets cryptocurrency wallet applications on iOS devices.

The STIX2 file can be used with the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) to look for potential signs of compromise on iPhones.

It includes the following files:

* `coruna.stix2`: [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro.html) file containing all indicators
* `domains.txt`: list of PLASMAGRID C2 domains and Coruna exploit kit delivery domains
* `sha256.txt`: SHA-256 hashes of the PLASMAGRID implant and its cryptocurrency wallet targeting modules
* `file_paths.txt`: iOS filesystem paths for implant artifacts
* `file_names.txt`: filenames associated with implant artifacts on iOS
* `generate_stix.py`: script to regenerate the STIX2 file from the text indicator files
