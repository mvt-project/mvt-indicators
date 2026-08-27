#!/usr/bin/env python3
"""Verify every committed bundle the way MVT will use it.

1. Parse it with MVT's own ``Indicators.parse_stix2`` and check that the
   indicators MVT extracts are exactly the values in the source files.
2. Validate it with the ``stix2`` library.

Requires ``mvt`` and ``stix2`` (see tools/requirements-ci.txt).
"""

import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build import REPO_ROOT, SOURCE_FILES, find_collections, load_collection, read_values  # noqa: E402

try:
    import stix2
    from mvt.common.indicators import Indicators
except ImportError as exc:
    print(f"error: {exc}. Install the verification dependencies: pip install -r tools/requirements-ci.txt")
    sys.exit(2)

# Source file -> (list in MVT's collection dict, normalisation MVT applies at parse time)
MVT_LISTS = {
    "domains.txt": ("domains", str.lower),
    "ip-addresses.txt": ("domains", str),
    "urls.txt": ("urls", str),
    "emails.txt": ("emails", str.lower),
    "processes.txt": ("processes", str),
    "file_names.txt": ("file_names", str),
    "file_paths.txt": ("file_paths", str),
    "md5.txt": ("files_md5", str),
    "sha1.txt": ("files_sha1", str),
    "sha256.txt": ("files_sha256", str),
    "favicon_hash.txt": ("files_sha256", str),
    "package_names.txt": ("app_ids", str),
    "package_cert_hashes.txt": ("app_cert_hashes", str),
    "config_profiles.txt": ("ios_profile_ids", str),
    "android_properties.txt": ("android_property_names", str),
}
assert set(MVT_LISTS) == set(SOURCE_FILES)


def expected_sets(folder):
    expected = {}
    for file_name, (list_name, normalise) in MVT_LISTS.items():
        path = os.path.join(folder, file_name)
        if os.path.isfile(path):
            expected.setdefault(list_name, set()).update(normalise(v) for v in read_values(path))
    return {k: v for k, v in expected.items() if v}


def mvt_sets(path):
    log = logging.getLogger("verify")
    log.setLevel(logging.ERROR)
    indicators = Indicators(log=log)
    indicators.parse_stix2(path)
    return indicators.ioc_collections


def main():
    failures = 0
    for folder in find_collections():
        meta = load_collection(folder)
        output = os.path.join(folder, meta["output"])
        rel = os.path.relpath(output, REPO_ROOT)
        problems = []

        collections = mvt_sets(output)
        named = [c for c in collections if c["id"] != "0"]
        if len(named) != 1:
            problems.append(f"MVT found {len(named)} named collections, expected 1")
        if any(c["id"] == "0" for c in collections):
            problems.append("some indicators are not linked to the malware object (MVT put them in its default collection)")
        if named:
            coll = named[0]
            if coll["name"] != meta["name"]:
                problems.append(f"MVT sees collection name '{coll['name']}', collection.yaml says '{meta['name']}'")
            got = {k: set(v) for k, v in coll.items() if isinstance(v, list) and v}
            want = expected_sets(folder)
            for list_name in sorted(set(got) | set(want)):
                missing = want.get(list_name, set()) - got.get(list_name, set())
                extra = got.get(list_name, set()) - want.get(list_name, set())
                if missing:
                    problems.append(f"{list_name}: {len(missing)} value(s) in sources but not loaded by MVT, e.g. {sorted(missing)[:3]}")
                if extra:
                    problems.append(f"{list_name}: {len(extra)} value(s) loaded by MVT but not in sources, e.g. {sorted(extra)[:3]}")

        try:
            with open(output, encoding="utf-8") as handle:
                stix2.parse(json.load(handle), allow_custom=False)
        except Exception as exc:  # stix2 raises a variety of error types
            problems.append(f"stix2 validation failed: {str(exc)[:200]}")

        if problems:
            failures += 1
            print(f"FAIL    {rel}")
            for problem in problems:
                print(f"        - {problem}")
        else:
            total = sum(len(v) for v in expected_sets(folder).values())
            print(f"ok      {rel} ({total} indicators, MVT parse matches sources)")

    print(f"\n{failures} bundle(s) failed verification" if failures else "\nall bundles verified")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
