# mvt-indicators

This repository contains the index to known publicly available indicators of compromise comptable with MVT. It also contains indicators file created and contributed by the community, gathered from published research.

## How to contribute new indicators of compromise

To contribute new indicators of compromise you are invited to submit pull requests to this repository including a new folder in the format of `YYYY-MM-DD_short_description`, containing text files for each indicators category as well as a [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro.html) file to be used with MVT. To generate a STIX2 file you can use the utility [stix2gen](https://github.com/botherder/stix2gen) (please refer to its repository for instructions on how to use).

When submitting a new pull request, please include the source of these indicators as well as any reference to related publicly available research and documentation.
