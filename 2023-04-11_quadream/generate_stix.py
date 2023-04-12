import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    if os.path.isfile("kingspawn.stix2"):
        os.remove("kingspawn.stix2")

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    with open("file_paths.txt") as f:
        filepaths = list(set([a.strip() for a in f.read().split()]))

    with open("processes.txt") as f:
        processes = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name="KingSpawn", is_family=False, description="IOCs related to Quadream KingsPawn or Reign spyware")
    res.append(malware)
    for d in domains:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for f in filepaths:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[file:path='{}']".format(f), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for p in processes:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[process:name='{}']".format(p), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open("kingspawn.stix2", "w+") as f:
        f.write(bundle.serialize(indent=4))
    print("kingspawn.stix2 file created")
