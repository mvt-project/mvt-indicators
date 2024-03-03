import stix2

def read_file_to_list(filename):
    """Read a file and return a list of lines."""
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

def create_indicator_object(pattern_type, value):
    """Create a STIX Indicator object."""
    return stix2.Indicator(
        name=f"Predator {pattern_type.capitalize()} Indicator",
        description=f"Predator {pattern_type} indicator for Mobile Verification Toolkit (MVT) analysis.",
        pattern_type="stix",
        pattern=f"[network-traffic:dst_{pattern_type} = '{value}']",
        valid_from="2023-11-01T00:00:00Z",
    )

def main():
    # Read domains and IPs from files
    domains = read_file_to_list('domains.txt')
    ips = read_file_to_list('ips.txt')

    # Create a list to hold our indicators
    indicators = []

    # Generate domain indicators
    for domain in domains:
        indicators.append(create_indicator_object('ref', domain))

    # Generate IP indicators
    for ip in ips:
        indicators.append(create_indicator_object('ref', ip))

    # Create a STIX bundle with all indicators
    bundle = stix2.Bundle(objects=indicators)

    # Save the bundle to a file
    with open('predator_inspekt.stix', 'w') as outfile:
        outfile.write(str(bundle))

    # Print status message
    print("STIX file 'predator_inspekt.stix' has been successfully generated and is ready for use with MVT.")


if __name__ == "__main__":
    main()

