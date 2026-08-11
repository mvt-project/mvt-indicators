import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle)


from stix2 import CustomObservable

# @CustomObservable('x-new-observable-2', [
#     ('a_property', properties.StringProperty(required=True)),
#     ('property_2', properties.IntegerProperty()),
# ], [
#     'a_property'
# ])
# class NewObservable2():
#     pass

def hash_format(hash):
    if len(hash) == 32:
        return "md5"
    elif len(hash) == 40:
        return "sha1"
    elif len(hash) == 64:
        return "sha256"
    else:
        return None

if __name__ == "__main__":
    malware_name = "BTMOB"
    stix2_file_name = "btmob.stix2"
    if os.path.isfile(stix2_file_name):
        os.remove(stix2_file_name)

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    with open("ip-addresses.txt") as f:
        ips = list(set([a.strip() for a in f.read().split()]))

    with open("sha256.txt") as f:
        sha256_hashes = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name=malware_name, is_family=False, description="IOCs for BTMOB")
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

    for sha256_hash in sha256_hashes:
        if not hash_format(sha256_hash) == "sha256":
            raise ValueError("File hash is not in SHA256 format: {}".format(sha256_hash))
        i = Indicator(indicator_types=["malicious-activity"], pattern=f"[file:hashes.sha256='{sha256_hash}']", pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open(stix2_file_name, "w+") as f:
        f.write(bundle.serialize(pretty=True, indent=4))
    print("{} file created".format(stix2_file_name))
