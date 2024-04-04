#!/bin/bash

# Set the default values for the arguments
DURATION=180
OUTPUT_PATH=/data/capture  # Default base output file path without extension

# Arguments manager
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--duration)
            DURATION="$2"
            shift
            shift
            ;;
        -o|--output)
            OUTPUT_PATH="$2"
            shift
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -d, --duration <duration>  Duration of the capture (default: 180 seconds)"
            echo "  -o, --output <output>      Base output file path without extension (default: /data/capture)"
            echo "  -h, --help                 Show this help message"
            exit 0
            ;;
        *)
            echo "Invalid option: $1"
            echo "See --help for more information"
            exit 1
            ;;
    esac
done

# Construct the full output file name by appending the .pcap extension
PCAP_OUTPUT="${OUTPUT_PATH}.pcap"

# Show the arguments
echo "Entrypoint arguments:"
echo "  Duration:   $DURATION"
echo "  Output PCAP: $PCAP_OUTPUT"
echo "  Interface:  eth0"
echo ""

# Create the output directory if it doesn't exist
echo "Creating output directory: $(dirname $PCAP_OUTPUT)"
mkdir -p $(dirname $PCAP_OUTPUT)

# Run Wireshark for the specified duration and save the traffic directly to a PCAP file
tshark -i eth0 -a duration:${DURATION} -w ${OUTPUT_PATH}.pcapng

# Convert pcap to pcapng format
tcpdump -r ${OUTPUT_PATH}.pcapng -w ${PCAP_OUTPUT}

# Make the output file readable by all users
chmod a+r $PCAP_OUTPUT

# Exit with success
exit 0
