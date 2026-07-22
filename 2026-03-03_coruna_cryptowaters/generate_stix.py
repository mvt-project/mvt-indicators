import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle)


if __name__ == "__main__":
    stix_name = "coruna.stix2"
    if os.path.isfile(stix_name):
        os.remove(stix_name)

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split() if a.strip()]))

    with open("sha256.txt") as f:
        hashes = list(set([a.strip() for a in f.read().split() if a.strip()]))

    with open("file_paths.txt") as f:
        filepaths = list(set([a.strip() for a in f.read().splitlines() if a.strip()]))

    with open("file_names.txt") as f:
        filenames = list(set([a.strip() for a in f.read().splitlines() if a.strip()]))

    res = []
    malware = Malware(
        name="Coruna",
        is_family=False,
        description="IOCs for the Coruna exploit kit, PLASMAGRID implant, "
        "and CryptoWaters campaign targeting iOS devices and cryptocurrency "
        "wallet apps. Attributed to UNC6353 and UNC6691."
    )
    res.append(malware)

    for d in domains:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern="[domain-name:value='{}']".format(d),
            pattern_type="stix"
        )
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for h in hashes:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern="[file:hashes.'SHA-256'='{}']".format(h),
            pattern_type="stix"
        )
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for fp in filepaths:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern="[file:path='{}']".format(fp),
            pattern_type="stix"
        )
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for fn in filenames:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern="[file:name='{}']".format(fn),
            pattern_type="stix"
        )
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open(stix_name, "w+") as f:
        f.write(bundle.serialize(indent=4))
    print("{} file created with {} indicators".format(
        stix_name,
        len(domains) + len(hashes) + len(filepaths) + len(filenames)
    ))
