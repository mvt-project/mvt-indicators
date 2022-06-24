#!/usr/bin/env python3

import os
import argparse

from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)



def generate_stix(iocs):
    res = []

    malware = Malware(name=app["name"], is_family=False, description="Stalkerware applications")
    res.append(malware)
    for d in app.get("c2", {}).get("domains", []):
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for h in app.get("sha256", []):
        i = Indicator(indicator_types=["malicious-activity"], pattern="[file:hashes.sha256='{}']".format(h), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for a in app.get("packages", []):
        i = Indicator(indicator_types=["malicious-activity"], pattern="[app:id='{}']".format(a), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    # for c in app.get("certificates", []):
    #     i = Indicator(indicator_types=["malicious-activity"], pattern="[app:cert.md5='{}']".format(c), pattern_type="stix")

    res.append(i)
    res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open(fpath, "w+", encoding="utf-8") as f:
        f.write(str(bundle))

    print(f"Generated {fpath}")
