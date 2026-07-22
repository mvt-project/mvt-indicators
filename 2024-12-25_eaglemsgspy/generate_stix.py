import sys
import os

from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    if os.path.isfile("eaglemsgspy.stix2"):
        os.remove("eaglemsgspy.stix2")

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    with open("ip-addresses.txt") as f:
        ips = list(set([a.strip() for a in f.read().split()]))

    with open("sha256.txt") as f:
        sha256 = list(set([a.strip() for a in f.read().split()]))    


    res = []
    malware = Malware(name="EagleMsgSpy", is_family=False, description="IOCs for EagleMsgSpy as documented by Lookout Security")
    res.append(malware)
    for d in domains:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for ip in ips:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[ipv4-addr:value='{}']".format(ip),
                      pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for s in sha256:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[file:hashes.sha256='{}']".format(s), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open("eaglemsgspy.stix2", "w+") as f:
        f.write(bundle.serialize(indent=4))
    print("eaglemsgspy.stix2 file created")