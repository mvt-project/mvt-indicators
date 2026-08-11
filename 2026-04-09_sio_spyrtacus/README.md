# Spyrtacus Android spyware

Spyrtacus is an Android spyware likely developed in Italy by SIO S.p.A., recently analyzed by the Italian NGO Osservatorio Nessuno.

Its capabilities include taking screenshots, uploading files, recording calls, exporting WhatsApp messages, and executing downloaded modules dynamically at runtime.

The infection in the analyzed case was performed via social engineering, with the
target receiving an SMS impersonating an Italian ISP.

The IoCs pertain to a 2025 sample of the Spyrtacus spyware, version `8.71`.
IoCs related to older samples of this spyware are included.

It seems that a [newer version](https://www.lawfulinterceptionacademy.eu/clir) (8.72) of the spyware exists.

## Sources

- Osservatorio Nessuno: Sample version 8.71 from 2025, https://osservatorionessuno.org/blog/2026/04/italian-spyware-maker-sio-still-developing-and-distributing-spyrtacus/
- TriageTM: Sample version 8.65 from 10.2024, https://tria.ge/241022-g6l3aatfkj/static1
- TriageTM: Sample version 8.20 from 04.2022, https://tria.ge/220401-nh9xrsbaa7/behavioral1

## Files

- **spyrtacus.stix2**: STIX2 indicators for use with MVT
- **domains.txt**:  C2 and delivery domains
- **ip-addresses.txt**:  C2 and infrastructure IPs
- **package_names.txt**: Android package names
- **favicon_hash.txt**: C2 favicon SHA256 hash
