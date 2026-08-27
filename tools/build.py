#!/usr/bin/env python3
"""Build the STIX2 bundle for each indicator collection in this repository.

The goal of this build is to produce deterministic STIX2 files based only on the collection
metadata and the plain text source files. This avoids recreating huge STIX2
files containing different randomised UUIDs each time. Now the same inputs IOCs
yield byte-identical output STIX2 files. Object identifiers are UUIDv5 values
derived from the collection id and the indicator pattern, and every timestamp
is the collection's ``created`` date, so regenerating a bundle only changes the
lines for indicators that were actually added or removed.

Usage:
    python tools/build.py            # rebuild every collection
    python tools/build.py --check    # exit 1 if any committed bundle is stale
    python tools/build.py DIR [DIR]  # only the given collection folders
"""

import argparse
import json
import os
import sys
import uuid

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# uuid5(NAMESPACE_URL, "https://github.com/mvt-project/mvt-indicators").
# FROZEN: changing this value changes every identifier in every bundle.
NAMESPACE = uuid.UUID("83685922-e61e-5ed9-b92c-8c0024d76d1a")

# Source file name -> STIX pattern template. The order of this list is the
# order of indicators in the bundle. FROZEN: changing a template changes the
# identifiers of every indicator built from that file.
SOURCES = [
    ("domains.txt", "[domain-name:value='{}']"),
    ("ip-addresses.txt", "[ipv4-addr:value='{}']"),
    ("urls.txt", "[url:value='{}']"),
    ("emails.txt", "[email-addr:value='{}']"),
    ("processes.txt", "[process:name='{}']"),
    ("file_names.txt", "[file:name='{}']"),
    ("file_paths.txt", "[file:path='{}']"),
    ("md5.txt", "[file:hashes.md5='{}']"),
    ("sha1.txt", "[file:hashes.sha1='{}']"),
    ("sha256.txt", "[file:hashes.sha256='{}']"),
    ("favicon_hash.txt", "[file:hashes.sha256='{}']"),
    ("package_names.txt", "[app:id='{}']"),
    ("package_cert_hashes.txt", None),  # algorithm chosen by hash length, see below
    ("config_profiles.txt", "[configuration-profile:id='{}']"),
    ("android_properties.txt", "[android-property:name='{}']"),
]
SOURCE_FILES = [name for name, _ in SOURCES]

CERT_HASH_TEMPLATES = {
    32: "[app:cert.md5='{}']",
    40: "[app:cert.sha1='{}']",
    64: "[app:cert.sha256='{}']",
}


def read_values(path):
    """Return the non-empty, non-comment lines of a source file, stripped."""
    values = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            values.append(line)
    return values


def load_collection(folder):
    with open(os.path.join(folder, "collection.yaml"), encoding="utf-8") as handle:
        meta = yaml.safe_load(handle)
    meta["created"] = str(meta["created"])
    return meta


def find_collections(root=REPO_ROOT):
    folders = []
    for name in sorted(os.listdir(root)):
        folder = os.path.join(root, name)
        if os.path.isfile(os.path.join(folder, "collection.yaml")):
            folders.append(folder)
    return folders


def pattern_for(file_name, template, value):
    if file_name == "package_cert_hashes.txt":
        try:
            template = CERT_HASH_TEMPLATES[len(value)]
        except KeyError:
            raise ValueError(f"{file_name}: '{value}' is not an MD5, SHA1 or SHA256 hash")
    return template.format(value)


def build_bundle(folder, meta):
    cid = meta["id"]
    timestamp = f"{meta['created']}T00:00:00.000Z"
    malware_id = f"malware--{uuid.uuid5(NAMESPACE, f'malware|{cid}')}"

    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": malware_id,
        "created": timestamp,
        "modified": timestamp,
        "name": meta["name"],
    }
    if meta.get("description"):
        malware["description"] = meta["description"]
    malware["is_family"] = False

    patterns = []
    for file_name, template in SOURCES:
        path = os.path.join(folder, file_name)
        if not os.path.isfile(path):
            continue
        for value in sorted(set(read_values(path))):
            patterns.append(pattern_for(file_name, template, value))

    objects = [malware]
    seen = set()
    for pattern in patterns:
        if pattern in seen:
            continue
        seen.add(pattern)
        indicator_id = f"indicator--{uuid.uuid5(NAMESPACE, f'indicator|{cid}|{pattern}')}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": timestamp,
            "modified": timestamp,
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": timestamp,
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid5(NAMESPACE, f'relationship|{indicator_id}|{malware_id}')}",
            "created": timestamp,
            "modified": timestamp,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": malware_id,
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(NAMESPACE, f'bundle|{cid}')}",
        "objects": objects,
    }


def render(bundle):
    return json.dumps(bundle, indent=4) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("folders", nargs="*", help="collection folders (default: all)")
    parser.add_argument("--check", action="store_true",
                        help="do not write; fail if any committed bundle differs from a fresh build")
    args = parser.parse_args()

    folders = [os.path.abspath(f) for f in args.folders] or find_collections()
    stale = []
    for folder in folders:
        meta = load_collection(folder)
        output = os.path.join(folder, meta["output"])
        rel_output = os.path.relpath(output, REPO_ROOT)
        bundle = build_bundle(folder, meta)
        text = render(bundle)
        indicator_count = sum(1 for o in bundle["objects"] if o["type"] == "indicator")

        if args.check:
            try:
                with open(output, encoding="utf-8") as handle:
                    current = handle.read()
            except FileNotFoundError:
                current = None
            if current != text:
                stale.append(rel_output)
                print(f"STALE   {rel_output}")
            else:
                print(f"ok      {rel_output} ({indicator_count} indicators)")
        else:
            with open(output, "w", encoding="utf-8") as handle:
                handle.write(text)
            print(f"wrote   {rel_output} ({indicator_count} indicators)")

    if stale:
        print(f"\n{len(stale)} bundle(s) do not match their sources. "
              "Run `python tools/build.py` and commit the result.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
