# Building the STIX2 bundles

Every collection folder in this repository contains plain-text source files
(one indicator per line), a small `collection.yaml`, and the `.stix2` bundle
MVT downloads. The bundle is **generated** from the other two by
`tools/build.py` and must never be edited by hand: CI rebuilds every bundle
and fails if the committed file differs.

```
pip install -r tools/requirements.txt
python tools/lint.py            # check the source files
python tools/build.py           # regenerate every bundle
python tools/build.py --check   # what CI runs: fail if any bundle is stale
python tools/verify.py          # parse every bundle with MVT itself (needs requirements-ci.txt)
```

## Adding indicators to an existing collection

1. Add the values to the matching source file (table below), one per line.
2. Run `python tools/build.py`.
3. Commit the source file and the regenerated `.stix2` together.

The diff of the bundle will contain only the indicators you added or removed.

## Adding a new collection

1. Create a folder named `YYYY-MM-DD_short_name` (date of the public report).
2. Add a `collection.yaml`:

   ```yaml
   id: short_name              # [a-z0-9_]+, unique, never changed once published
   name: Short Name            # shown by MVT next to every match
   description: IOCs for ...   # optional
   created: 2026-05-26         # used as the timestamp of every object in the bundle
   output: short_name.stix2
   ```

3. Add the source files, run `python tools/build.py`, and add an entry for the
   new bundle to `indicators.yaml` so MVT downloads it.
4. Add a `README.md` with the sources of the indicators.

## Source files

| File | STIX pattern | Rules |
| --- | --- | --- |
| `domains.txt` | `[domain-name:value='…']` | lower-case hostname, no scheme, path or port |
| `ip-addresses.txt` | `[ipv4-addr:value='…']` | IPv4 only (MVT does not match IPv6) |
| `urls.txt` | `[url:value='…']` | starts with `http://` or `https://` |
| `emails.txt` | `[email-addr:value='…']` | lower-case |
| `processes.txt` | `[process:name='…']` | exact, case-sensitive |
| `file_names.txt` | `[file:name='…']` | exact, case-sensitive |
| `file_paths.txt` | `[file:path='…']` | absolute, exact, case-sensitive |
| `md5.txt` / `sha1.txt` / `sha256.txt` | `[file:hashes.<algo>='…']` | lower-case hex |
| `favicon_hash.txt` | `[file:hashes.sha256='…']` | lower-case hex |
| `package_names.txt` | `[app:id='…']` | Android package name |
| `package_cert_hashes.txt` | `[app:cert.<algo>='…']` | lower-case hex; algorithm chosen by length |
| `config_profiles.txt` | `[configuration-profile:id='…']` | iOS configuration profile identifier |
| `android_properties.txt` | `[android-property:name='…']` | Android system property name |

Blank lines and lines starting with `#` are ignored, so sources and dates can
be noted inline. Values may not contain `'` or `\`, which cannot appear
unescaped inside a STIX pattern string.

## Why the output is deterministic

* Object identifiers are UUIDv5 values: `uuid5(NAMESPACE, "indicator|<collection id>|<pattern>")`
  for indicators, and similarly for the malware, relationship and bundle
  objects. The namespace UUID and the pattern templates in `build.py` are
  frozen; changing either would change every identifier once.
* `created`, `modified` and `valid_from` are all the collection's `created`
  date. MVT does not read them, and a fixed value keeps them out of the diff.
* Values are de-duplicated and sorted, and the JSON layout is fixed.

Two builds from the same sources are byte-identical, so `git diff` on a bundle
shows exactly the indicators that changed, and git stores each revision as a
small delta.
