import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle)


from stix2 import CustomObservable

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
    malware_name = "Cellebrite"
    stix2_file_name = "cellebrite.stix2"
    if os.path.isfile(stix2_file_name):
        os.remove(stix2_file_name)

    with open("package_names.txt") as f:
        package_names = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name=malware_name, is_family=False, description="IOCs for Cellebrite")
    res.append(malware)
    for package_name in package_names:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[app:id='{}']".format(package_name), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open(stix2_file_name, "w+") as f:
        f.write(bundle.serialize(pretty=True, indent=4))
    print("{} file created".format(stix2_file_name))
