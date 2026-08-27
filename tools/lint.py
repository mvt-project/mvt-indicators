#!/usr/bin/env python3
"""Check the source files of every indicator collection before building.

Errors (exit 1) are things that would produce a wrong or unusable bundle.
Warnings are printed but do not fail the run.
"""

import ipaddress
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build import REPO_ROOT, SOURCE_FILES, find_collections  # noqa: E402

COLLECTION_KEYS = {"id", "name", "description", "created", "output"}
REQUIRED_KEYS = {"id", "name", "created", "output"}

HEX_LENGTHS = {"md5.txt": (32,), "sha1.txt": (40,), "sha256.txt": (64,), "favicon_hash.txt": (64,),
               "package_cert_hashes.txt": (32, 40, 64)}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
# A STIX pattern holds the value inside a single-quoted string literal; these
# two characters cannot appear there unescaped.
FORBIDDEN = set("'\\")
# Values in these files may legitimately contain spaces (paths, process names).
SPACES_ALLOWED = {"file_paths.txt", "file_names.txt", "processes.txt"}

errors = []
warnings = []


def err(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


HYGIENE = err


def check_value(rel, value):
    """Rules that apply to every value regardless of file type."""
    bad = sorted(FORBIDDEN & set(value))
    if bad:
        err(f"{rel}: '{value}' contains {''.join(bad)}, which cannot be used in a STIX pattern")
        return False
    return True


def check_typed(rel, file_name, value):
    if file_name == "domains.txt":
        if value != value.lower():
            HYGIENE(f"{rel}: domain '{value}' should be lower-case")
        lowered = value.lower()
        if not DOMAIN_RE.match(lowered):
            if re.match(r"^[a-z0-9-]+$", lowered):
                warn(f"{rel}: '{value}' has no top-level domain, is it truncated?")
            else:
                HYGIENE(f"{rel}: '{value}' is not a valid hostname (no scheme, path or port)")
    elif file_name == "ip-addresses.txt":
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            err(f"{rel}: '{value}' is not an IPv4 address (MVT only matches ipv4-addr patterns)")
    elif file_name == "urls.txt":
        if not value.startswith(("http://", "https://")):
            err(f"{rel}: URL '{value}' must start with http:// or https://")
    elif file_name == "emails.txt":
        if value != value.lower():
            HYGIENE(f"{rel}: email '{value}' should be lower-case")
        if not EMAIL_RE.match(value):
            err(f"{rel}: '{value}' is not an email address")
    elif file_name in HEX_LENGTHS:
        lengths = HEX_LENGTHS[file_name]
        if not HEX_RE.match(value) or len(value) not in lengths:
            names = {32: "MD5", 40: "SHA1", 64: "SHA256"}
            err(f"{rel}: '{value}' is not a {' / '.join(names[n] for n in lengths)} hash")
        elif value != value.lower():
            HYGIENE(f"{rel}: hash '{value}' should be lower-case")
    elif file_name == "package_names.txt":
        if not PACKAGE_RE.match(value):
            err(f"{rel}: '{value}' is not an Android package name")
    elif file_name == "file_paths.txt":
        if not value.startswith("/"):
            HYGIENE(f"{rel}: file path '{value}' should be absolute (MVT matches path prefixes)")
    # processes.txt, file_names.txt, config_profiles.txt, android_properties.txt:
    # no format beyond the generic rules.


def check_source_file(folder, file_name):
    path = os.path.join(folder, file_name)
    rel = os.path.relpath(path, REPO_ROOT)
    with open(path, encoding="utf-8") as handle:
        raw = handle.read()
    if raw and not raw.endswith("\n"):
        HYGIENE(f"{rel}: missing trailing newline")
    seen = set()
    count = 0
    for lineno, line in enumerate(raw.split("\n"), 1):
        if line.strip() == "" or line.lstrip().startswith("#"):
            continue
        if line != line.strip():
            HYGIENE(f"{rel}:{lineno}: leading or trailing whitespace")
        value = line.strip()
        if value in seen:
            HYGIENE(f"{rel}:{lineno}: duplicate value '{value}'")
        seen.add(value)
        count += 1
        if file_name not in SPACES_ALLOWED and re.search(r"\s", value):
            err(f"{rel}:{lineno}: whitespace inside value '{value}'")
            continue
        if check_value(rel, value):
            check_typed(rel, file_name, value)
    return count


def check_collection(folder):
    rel = os.path.relpath(folder, REPO_ROOT)
    with open(os.path.join(folder, "collection.yaml"), encoding="utf-8") as handle:
        meta = yaml.safe_load(handle)
    if not isinstance(meta, dict):
        err(f"{rel}/collection.yaml: not a mapping")
        return None
    missing = REQUIRED_KEYS - set(meta)
    unknown = set(meta) - COLLECTION_KEYS
    if missing:
        err(f"{rel}/collection.yaml: missing key(s) {sorted(missing)}")
    if unknown:
        err(f"{rel}/collection.yaml: unknown key(s) {sorted(unknown)}")
    if missing:
        return None
    if not re.match(r"^[a-z0-9_]+$", str(meta["id"])):
        err(f"{rel}/collection.yaml: id '{meta['id']}' must match [a-z0-9_]+")
    if not str(meta["name"]).strip():
        err(f"{rel}/collection.yaml: name is empty")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(meta["created"])):
        err(f"{rel}/collection.yaml: created '{meta['created']}' must be YYYY-MM-DD")
    output = str(meta["output"])
    if "/" in output or not output.endswith(".stix2"):
        err(f"{rel}/collection.yaml: output '{output}' must be a .stix2 file name in this folder")

    total = 0
    present = 0
    for file_name in SOURCE_FILES:
        if os.path.isfile(os.path.join(folder, file_name)):
            present += 1
            total += check_source_file(folder, file_name)
    if present == 0:
        err(f"{rel}: no source files found (expected one of {', '.join(SOURCE_FILES)})")
    elif total == 0:
        warn(f"{rel}: source files are all empty")
    for name in sorted(os.listdir(folder)):
        if name.endswith(".txt") and name not in SOURCE_FILES:
            warn(f"{rel}/{name}: not a recognised source file, it will be ignored by the build")
    return meta


def check_index(collections):
    path = os.path.join(REPO_ROOT, "indicators.yaml")
    with open(path, encoding="utf-8") as handle:
        index = yaml.safe_load(handle)
    outputs = {os.path.relpath(os.path.join(folder, meta["output"]), REPO_ROOT)
               for folder, meta in collections}
    referenced = set()
    for entry in index.get("indicators", []):
        github = entry.get("github", {})
        if entry.get("type") != "github":
            continue
        if github.get("owner") != "mvt-project" or github.get("repo") != "mvt-indicators":
            continue
        ioc_path = github.get("path", "")
        if github.get("branch", "main") != "main":
            warn(f"indicators.yaml: '{entry.get('name')}' points at branch {github.get('branch')}")
        if ioc_path not in outputs:
            err(f"indicators.yaml: '{entry.get('name')}' points at {ioc_path}, "
                "which is not the output of any collection in this repository")
        referenced.add(ioc_path)
    for missing in sorted(outputs - referenced):
        warn(f"{missing} is built but not listed in indicators.yaml, MVT will not download it")


def main():
    collections = []
    ids = {}
    for folder in find_collections():
        meta = check_collection(folder)
        if meta is None:
            continue
        collections.append((folder, meta))
        if meta["id"] in ids:
            err(f"collection id '{meta['id']}' used by both {ids[meta['id']]} and {folder}")
        ids[meta["id"]] = folder
    check_index(collections)

    for msg in warnings:
        print(f"warning: {msg}")
    for msg in errors:
        print(f"error: {msg}")
    print(f"\n{len(collections)} collections checked, {len(errors)} error(s), {len(warnings)} warning(s)")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
