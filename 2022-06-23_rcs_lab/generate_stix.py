import os

from stix2.v21 import Bundle, Indicator, Malware, Relationship


def read_indicators(path):
    with open(path) as handle:
        return sorted(set(handle.read().split()))


if __name__ == "__main__":
    stix_name = "rcs.stix2"
    if os.path.isfile(stix_name):
        os.remove(stix_name)

    domains = read_indicators("domains.txt")
    ips = read_indicators("ip-addresses.txt")
    package_names = read_indicators("package_names.txt")
    sha256_hashes = read_indicators("sha256.txt")

    objects = []
    malware = Malware(name="RCSLab", is_family=True)
    objects.append(malware)

    patterns = [
        *(f"[domain-name:value='{domain}']" for domain in domains),
        *(f"[ipv4-addr:value='{ip}']" for ip in ips),
        *(f"[app:id='{package_name}']" for package_name in package_names),
        *(f"[file:hashes.sha256='{sha256_hash}']" for sha256_hash in sha256_hashes),
    ]

    for pattern in patterns:
        indicator = Indicator(
            indicator_types=["malicious-activity"],
            pattern=pattern,
            pattern_type="stix",
        )
        objects.append(indicator)
        objects.append(Relationship(indicator, "indicates", malware))

    bundle = Bundle(objects=objects)
    with open(stix_name, "w+") as handle:
        handle.write(bundle.serialize(indent=4))

    print(f"{stix_name} file created with {len(patterns)} indicators")
