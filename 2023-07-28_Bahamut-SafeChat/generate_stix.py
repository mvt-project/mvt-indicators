import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    malware_name = "Bahamut SafeChat"
    stix_name = "bahamut_safechat.stix2"
    if os.path.isfile(stix_name):
        os.remove(stix_name)

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    with open("sha256.txt") as f:
        sha256 = list(set([a.strip() for a in f.read().split()]))

    with open("package_names.txt") as f:
        package_names = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name=malware_name, is_family=False, description="IOCs related to Bahamut's SafeChat Android spyware documented by Cyfirma 2023-07-28.")
    res.append(malware)
    for d in domains:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for s in sha256:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[file:hashes.sha256='{}']".format(s), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for p in package_names:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[app:id='{}']".format(p), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open(stix_name, "w+") as f:
        f.write(bundle.serialize(indent=4))
    print("{} file created".format(stix_name))
