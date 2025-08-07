import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    malware_name = "Candiru"
    stix_name = "candiru.stix2"
    if os.path.isfile(stix_name):
        os.remove(stix_name)

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name=malware_name, is_family=False, description="IOCs related to Candiru's DevilsTongue as documented by Recorded Future.")
    res.append(malware)
    for d in domains:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open(stix_name, "w+") as f:
        f.write(bundle.serialize(indent=4))
    print("{} file created".format(stix_name))
