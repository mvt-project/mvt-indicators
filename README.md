# mvt-indicators

This repository contains the index to known publicly available indicators of compromise compatible with MVT. It also contains indicators file created and contributed by the community, gathered from published research.

## How to contribute new indicators of compromise

To contribute new indicators of compromise, submit a pull request to this repository.

* To extend an existing collection, add the values to the relevant plain-text file in its folder (for example `domains.txt` or `sha256.txt`), run `python tools/build.py`, and commit the source file together with the regenerated `.stix2` bundle.
* To add a new collection, create a folder in the format `YYYY-MM-DD_short_description` containing a `collection.yaml`, one text file per indicator category, a `README.md` with the sources, and add an entry to `indicators.yaml`.

The `.stix2` bundles are generated deterministically from the text files by `tools/build.py` and must not be edited by hand; CI rebuilds them and fails if a committed bundle does not match its sources. See [tools/README.md](tools/README.md) for the list of supported indicator files and their format.

When submitting a new pull request, please include the source of these indicators as well as any reference to related publicly available research and documentation.
