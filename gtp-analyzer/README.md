# GTP Analyzer - Wireshark PCAP Analysis Utility

A comprehensive command-line tool for analyzing GTP (GPRS Tunnelling Protocol) packet captures. Supports both GTPv1 and GTPv2 protocols with features for TEID tracking, session reconstruction, and detailed reporting.

## Features

- **PCAP File Parsing**: Extract and analyze GTP packets from Wireshark captures
- **Multi-Version Support**: Works with both GTPv1 and GTPv2 protocols
- **TEID Lifecycle Tracking**: Monitor TEID allocation, usage, and deallocation
- **Session Reconstruction**: Rebuild complete GTP sessions from packet captures
- **Comprehensive Statistics**: Generate detailed analysis reports
- **Multiple Export Formats**: Export data to JSON or CSV for further analysis
- **Advanced Filtering**: Filter packets by TEID, message type, IP addresses
- **Formatted Output**: Beautiful tables and ASCII diagrams for easy visualization

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install from source

```bash
cd gtp-analyzer
pip install -r requirements.txt
pip install -e .
```

After installation, the `gtp-analyzer` command will be available globally.

## Quick Start

### Parse GTP packets from a PCAP file

```bash
gtp-analyzer parse capture.pcap
```

### Track a specific TEID

```bash
gtp-analyzer teid-track capture.pcap 12345
```

### Reconstruct sessions

```bash
gtp-analyzer session capture.pcap
```

### Generate statistics

```bash
gtp-analyzer stats capture.pcap
```

## Command Reference

### 1. Parse Command

Parse and display GTP packets from a PCAP file.

```bash
gtp-analyzer parse <pcap_file> [OPTIONS]

Options:
  -l, --limit INTEGER         Limit number of packets to display
  -m, --message-type INTEGER  Filter by message type
  --help                      Show this message and exit

Examples:
  gtp-analyzer parse capture.pcap
  gtp-analyzer parse capture.pcap --limit 20
  gtp-analyzer parse capture.pcap --message-type 16
```

**Output**: Formatted table with packet details including:
- Packet number
- Timestamp
- Source/Destination IPs
- GTP version
- Message type
- TEID
- Sequence number

### 2. TEID Track Command

Track the lifecycle of a specific TEID throughout the capture.

```bash
gtp-analyzer teid-track <pcap_file> <teid> [OPTIONS]

Options:
  -e, --export FILE  Export to file (JSON)
  --help            Show this message and exit

Examples:
  gtp-analyzer teid-track capture.pcap 12345
  gtp-analyzer teid-track capture.pcap 12345 --export teid_report.json
```

**Output**:
- ASCII lifecycle diagram showing TEID creation, modifications, and deletion
- Packet statistics (data packets, control packets)
- Source and destination IPs
- Detailed packet table
- Duration information

### 3. Session Command

Reconstruct complete GTP sessions from the packet capture.

```bash
gtp-analyzer session <pcap_file> [OPTIONS]

Options:
  -s, --session-id TEXT  Show specific session
  -e, --export FILE      Export to file (JSON)
  --help                Show this message and exit

Examples:
  gtp-analyzer session capture.pcap
  gtp-analyzer session capture.pcap --session-id Session-1
  gtp-analyzer session capture.pcap --export sessions.json
```

**Output**:
- Session flow summaries
- Timeline of events (create, modify, delete)
- TEID distribution per session
- Endpoint information
- Session duration

### 4. Stats Command

Generate comprehensive statistics from the PCAP file.

```bash
gtp-analyzer stats <pcap_file> [OPTIONS]

Options:
  -t, --teid-summary  Include TEID summary
  --help             Show this message and exit

Examples:
  gtp-analyzer stats capture.pcap
  gtp-analyzer stats capture.pcap --teid-summary
```

**Output**:
- Total packet count
- GTP version distribution
- Message type breakdown
- TEID statistics
- Capture duration
- IP address counts
- Optional TEID lifecycle summary

### 5. Export Command

Export analysis results to JSON or CSV format.

```bash
gtp-analyzer export <pcap_file> <format> <output_file> [OPTIONS]

Arguments:
  format  [json|csv]  Export format

Options:
  --include-packets / --no-packets  Include packet details in JSON export (default: True)
  --help                           Show this message and exit

Examples:
  gtp-analyzer export capture.pcap json output.json
  gtp-analyzer export capture.pcap csv output.csv
  gtp-analyzer export capture.pcap json output.json --no-packets
```

**JSON Export includes**:
- Statistics summary
- Optional: Complete packet details
- PCAP file information

**CSV Export includes**:
- One row per packet
- All packet fields in columnar format

### 6. Filter Command

Apply various filters to GTP packets.

```bash
gtp-analyzer filter <pcap_file> [OPTIONS]

Options:
  -t, --teid INTEGER         Filter by TEID
  -m, --message-type INTEGER Filter by message type
  -s, --src-ip TEXT          Filter by source IP
  -d, --dst-ip TEXT          Filter by destination IP
  -l, --limit INTEGER        Limit number of packets to display
  --help                     Show this message and exit

Examples:
  gtp-analyzer filter capture.pcap --teid 12345
  gtp-analyzer filter capture.pcap --message-type 16
  gtp-analyzer filter capture.pcap --src-ip 192.168.1.1
  gtp-analyzer filter capture.pcap --teid 12345 --limit 10
  gtp-analyzer filter capture.pcap --src-ip 10.0.0.1 --dst-ip 10.0.0.2
```

**Output**: Filtered packet table with match statistics

## GTP Protocol Support

### GTPv1 Message Types

- Echo Request/Response (1, 2)
- Create PDP Context Request/Response (16, 17)
- Update PDP Context Request/Response (18, 19)
- Delete PDP Context Request/Response (20, 21)
- G-PDU (User Data) (255)

### GTPv2 Message Types

- Echo Request/Response (1, 2)
- Create Session Request/Response (32, 33)
- Modify Bearer Request/Response (34, 35)
- Delete Session Request/Response (36, 37)
- Create Bearer Request/Response (95, 96)
- Update Bearer Request/Response (97, 98)
- Delete Bearer Request/Response (99, 100)

## Use Cases

### 1. Troubleshooting GTP Sessions

```bash
# First, get an overview
gtp-analyzer stats capture.pcap --teid-summary

# Identify problematic TEID
gtp-analyzer teid-track capture.pcap 12345

# Reconstruct the session
gtp-analyzer session capture.pcap
```

### 2. Quality Analysis

```bash
# Export for detailed analysis
gtp-analyzer export capture.pcap json detailed_analysis.json

# Filter specific message types
gtp-analyzer filter capture.pcap --message-type 32  # Create Session
```

### 3. Network Monitoring

```bash
# Check traffic between specific endpoints
gtp-analyzer filter capture.pcap --src-ip 10.0.0.1 --dst-ip 10.0.0.2

# Track all TEIDs
gtp-analyzer stats capture.pcap --teid-summary
```

## Architecture

### Module Structure

```
gtp_analyzer/
├── __init__.py           # Package initialization
├── cli.py                # Command-line interface (Click)
├── gtp_parser.py         # PCAP parsing and GTP packet extraction
├── teid_tracker.py       # TEID lifecycle tracking
├── session_reconstructor.py  # Session reconstruction
└── report_generator.py   # Statistics and report generation
```

### Key Classes

- **GTPPacket**: Represents a single GTP packet with parsed fields
- **GTPParser**: Parses PCAP files and extracts GTP packets
- **TEIDLifecycle**: Tracks the lifecycle of a single TEID
- **TEIDTracker**: Manages multiple TEID lifecycles
- **GTPSession**: Represents a complete GTP session
- **SessionReconstructor**: Rebuilds sessions from packets
- **ReportGenerator**: Creates reports and handles exports

## Technical Details

### Packet Parsing

The tool uses Scapy for low-level packet parsing and implements custom GTP header parsing to support both GTPv1 and GTPv2 protocols. It automatically detects:

- GTP version from packet flags
- Message types and their human-readable names
- TEID values (when present)
- Sequence numbers
- QoS parameters (in message payloads)

### TEID Lifecycle Tracking

TEIDs are tracked throughout their lifecycle:

1. **Creation**: Detected from Create Response messages
2. **Usage**: All packets with the TEID are tracked
3. **Modification**: Update/Modify messages are recorded
4. **Deletion**: Delete Response messages mark TEID end
5. **Statistics**: Data vs. control packet counts

### Session Reconstruction

Sessions are reconstructed by:

1. Grouping packets by endpoint pairs (IP addresses)
2. Tracking all TEIDs within each session
3. Recording session events in chronological order
4. Calculating session duration and statistics

## Dependencies

- **scapy**: Packet parsing and PCAP file reading
- **click**: Command-line interface framework
- **tabulate**: Formatted table generation
- **colorama**: Cross-platform colored terminal output

## Limitations

- Requires valid PCAP files with GTP traffic on standard ports (2152, 2123)
- Does not decrypt encrypted GTP payloads
- Session reconstruction is based on IP endpoint pairs (simplified model)
- Very large PCAP files may require significant memory

## Performance Tips

1. **Filter Early**: Use Wireshark to pre-filter captures to GTP traffic only
2. **Limit Output**: Use `--limit` option for large captures
3. **Export for Analysis**: Export to JSON/CSV for processing with other tools
4. **Specific Tracking**: Use TEID tracking for focused analysis

## Troubleshooting

### No packets found

- Ensure the PCAP contains GTP traffic on ports 2152 or 2123
- Verify the capture includes UDP traffic
- Check GTP version compatibility

### Missing TEID information

- Some GTP messages don't include TEIDs (control messages)
- Check if the capture includes the full session establishment

### Session reconstruction issues

- Sessions are grouped by IP pairs
- Captures may need to include full session lifecycle

## Contributing

Contributions are welcome! Please ensure:

1. Code follows Python PEP 8 style guidelines
2. New features include appropriate tests
3. Documentation is updated for new functionality
4. Changes maintain backward compatibility

## License

This tool is part of the Microservice Design Patterns repository.

## Author

Microservice Design Patterns Community

## Version History

- **1.0.0** (2024): Initial release
  - Complete GTPv1 and GTPv2 support
  - TEID tracking and lifecycle analysis
  - Session reconstruction
  - Multiple export formats
  - Comprehensive filtering options
