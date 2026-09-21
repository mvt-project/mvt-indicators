# Coruna and DarkSword proliferation

Source: [iVerify, Proliferation of Coruna and DarkSword](https://www.iverify.com/blog/proliferation-of-coruna-and-darksword), September 15, 2026.

Contains the published delivery/C2 domains and IPv4 addresses, explicit delivery URL, SHA-256 hashes from the configuration and IOC table, and DarkSword filesystem artifacts. The two keychain dump filenames are expanded only into the locations listed in the report. The sandbox-denial target `darksword.log` indicates an attempted operation; a log match does not prove that the file was created.

Generic sample names such as `config.json` and `report.html`, exported sample library names, legitimate injected process names, targeted app bundle IDs, and placeholder URLs are deliberately excluded as standalone indicators. Published hashes identify those samples without treating their names as inherently malicious.

Randomized Coruna preference filenames and app-container `Documents/.devcache` require scoped path/content heuristics; they are not encoded as unsupported regular expressions or unscoped filename indicators here.

The hash list includes both payload and compressed-archive hashes where supplied by the report. Hash matching requires file content; filesystem metadata alone cannot match them.
