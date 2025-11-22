# GTP Analyzer - Usage Examples

This document provides comprehensive examples of using the GTP Analyzer tool in various real-world scenarios.

## Installation and Setup

```bash
cd gtp-analyzer
pip install -r requirements.txt
pip install -e .
```

After installation, verify it's working:

```bash
gtp-analyzer --version
gtp-analyzer --help
```

## Generating Sample Data

For testing and demonstration, generate a sample PCAP file:

```bash
python create_sample_pcap.py
```

This creates `sample_pcaps/gtp_sample.pcap` with realistic GTP traffic.

## Basic Commands

### 1. Quick Overview

Get a quick overview of any PCAP file:

```bash
gtp-analyzer parse capture.pcap --limit 20
```

**Output:** First 20 GTP packets in a formatted table showing:
- Packet number and timestamp
- Source/Destination IPs
- GTP version
- Message type
- TEID
- Sequence number

### 2. Complete Statistics

Generate comprehensive statistics:

```bash
gtp-analyzer stats capture.pcap
```

**Shows:**
- Total packet count
- GTP version distribution
- Message type breakdown
- Unique TEIDs and IPs
- Capture duration

### 3. TEID Summary

Include TEID lifecycle summary:

```bash
gtp-analyzer stats capture.pcap --teid-summary
```

**Additional info:**
- Active vs. Deleted TEIDs
- Data vs. Control packet counts
- Per-TEID statistics table

## Advanced Usage

### Tracking a Specific TEID

Track the complete lifecycle of a TEID:

```bash
gtp-analyzer teid-track capture.pcap 12345
```

**Output includes:**
- ASCII lifecycle diagram
- Creation timestamp
- All modifications
- Deletion timestamp (if deleted)
- Duration calculation
- Packet statistics
- Complete packet table

Export TEID analysis to JSON:

```bash
gtp-analyzer teid-track capture.pcap 12345 --export teid_12345.json
```

### Session Reconstruction

Reconstruct all sessions:

```bash
gtp-analyzer session capture.pcap
```

**Shows:**
- All detected sessions
- Session duration and endpoints
- Timeline of events (create, modify, delete)
- TEID distribution per session

View specific session:

```bash
gtp-analyzer session capture.pcap --session-id Session-1
```

Export session data:

```bash
gtp-analyzer session capture.pcap --export sessions.json
```

### Filtering Packets

#### Filter by TEID

```bash
gtp-analyzer filter capture.pcap --teid 12345
```

#### Filter by Message Type

```bash
# GTPv2 Create Session Requests
gtp-analyzer filter capture.pcap --message-type 32

# GTPv1 G-PDU (User Data)
gtp-analyzer filter capture.pcap --message-type 255
```

#### Filter by Source IP

```bash
gtp-analyzer filter capture.pcap --src-ip 192.168.1.10
```

#### Filter by Destination IP

```bash
gtp-analyzer filter capture.pcap --dst-ip 192.168.1.20
```

#### Combine Multiple Filters

```bash
gtp-analyzer filter capture.pcap \
  --teid 12345 \
  --src-ip 192.168.1.10 \
  --limit 10
```

### Exporting Data

#### Export to JSON (with packets)

```bash
gtp-analyzer export capture.pcap json analysis.json
```

#### Export to JSON (statistics only)

```bash
gtp-analyzer export capture.pcap json analysis.json --no-packets
```

#### Export to CSV

```bash
gtp-analyzer export capture.pcap csv packets.csv
```

CSV includes all packet fields in columnar format, perfect for:
- Excel analysis
- Database import
- Custom scripting

## Real-World Scenarios

### Scenario 1: Troubleshooting Failed Session

A user reports a failed session. Let's investigate:

**Step 1:** Get overview of the capture

```bash
gtp-analyzer stats problem_capture.pcap --teid-summary
```

Identify suspicious TEIDs (e.g., created but not deleted, or immediately deleted).

**Step 2:** Track the problematic TEID

```bash
gtp-analyzer teid-track problem_capture.pcap 67890
```

Check the lifecycle diagram for:
- Was creation successful?
- Were there any modifications?
- Was deletion clean?
- Any error indicators?

**Step 3:** Reconstruct the session

```bash
gtp-analyzer session problem_capture.pcap
```

Look at the session timeline to understand the sequence of events.

**Step 4:** Export for detailed analysis

```bash
gtp-analyzer export problem_capture.pcap json detailed_analysis.json
gtp-analyzer teid-track problem_capture.pcap 67890 --export teid_67890.json
```

### Scenario 2: Capacity Planning

Analyze traffic patterns for capacity planning:

**Step 1:** Parse all GTP packets

```bash
gtp-analyzer parse capacity_capture.pcap > all_packets.txt
```

**Step 2:** Get statistics with TEID summary

```bash
gtp-analyzer stats capacity_capture.pcap --teid-summary
```

Analyze:
- How many concurrent sessions?
- Data packet volume
- Control packet overhead

**Step 3:** Export for trending analysis

```bash
gtp-analyzer export capacity_capture.pcap csv capacity_data.csv
```

Import CSV into Excel or database for:
- Time-series analysis
- Peak usage identification
- Growth trends

### Scenario 3: Protocol Compliance Check

Verify GTP protocol implementation:

**Step 1:** Check message type distribution

```bash
gtp-analyzer stats test_capture.pcap
```

Verify expected message types are present and balanced:
- Every Create Request has a Response
- Sessions are properly deleted
- No unexpected message types

**Step 2:** Filter specific message types

```bash
# Check Create Session messages
gtp-analyzer filter test_capture.pcap --message-type 32

# Check Delete Session messages
gtp-analyzer filter test_capture.pcap --message-type 36
```

**Step 3:** Verify TEID lifecycle

```bash
gtp-analyzer teid-track test_capture.pcap <teid>
```

Ensure proper lifecycle:
1. Creation (Response)
2. Usage (Data packets)
3. Deletion (Response)

### Scenario 4: Performance Analysis

Analyze performance of GTP infrastructure:

**Step 1:** Session reconstruction

```bash
gtp-analyzer session performance_capture.pcap --export sessions.json
```

**Step 2:** Analyze session durations

Parse the JSON output to find:
- Average session duration
- Longest/shortest sessions
- Session establishment time

**Step 3:** TEID analysis

```bash
gtp-analyzer stats performance_capture.pcap --teid-summary
```

Check:
- Data packet throughput per TEID
- Control packet overhead
- Session churn rate

### Scenario 5: Network Debugging

Debug connectivity issues between network elements:

**Step 1:** Filter by endpoints

```bash
# Traffic from PGW
gtp-analyzer filter debug_capture.pcap --src-ip 10.0.1.1

# Traffic to SGW
gtp-analyzer filter debug_capture.pcap --dst-ip 10.0.2.1

# Traffic between specific nodes
gtp-analyzer filter debug_capture.pcap \
  --src-ip 10.0.1.1 \
  --dst-ip 10.0.2.1
```

**Step 2:** Session analysis

```bash
gtp-analyzer session debug_capture.pcap
```

Check:
- Are sessions established?
- Are endpoints correct?
- Is traffic bidirectional?

**Step 3:** Message type analysis

```bash
# Check for Echo messages (keepalive)
gtp-analyzer filter debug_capture.pcap --message-type 1
gtp-analyzer filter debug_capture.pcap --message-type 2
```

## Tips and Best Practices

### 1. Working with Large Captures

For very large PCAP files:

```bash
# Use limit to avoid overwhelming output
gtp-analyzer parse huge_capture.pcap --limit 100

# Export to CSV for external analysis
gtp-analyzer export huge_capture.pcap csv data.csv

# Filter to specific TEIDs first
gtp-analyzer filter huge_capture.pcap --teid 12345 --limit 50
```

### 2. Finding Specific TEIDs

Don't know the TEID? Get a list:

```bash
# Get statistics which includes TEID list
gtp-analyzer stats capture.pcap --teid-summary
```

### 3. Batch Processing

Process multiple files:

```bash
#!/bin/bash
for pcap in *.pcap; do
  echo "Processing $pcap..."
  gtp-analyzer stats "$pcap" --teid-summary > "${pcap%.pcap}_stats.txt"
  gtp-analyzer export "$pcap" json "${pcap%.pcap}.json"
done
```

### 4. Pre-filtering in Wireshark

For better performance, pre-filter in Wireshark:

1. Open PCAP in Wireshark
2. Apply filter: `gtp` or `udp.port == 2152 || udp.port == 2123`
3. File → Export Specified Packets
4. Use exported file with gtp-analyzer

### 5. Understanding Output

**TEID Highlighting:**
When tracking a specific TEID, it's highlighted as `>>> 12345 <<<` in tables.

**Status Indicators:**
- Active: TEID created but not deleted
- Deleted: TEID properly torn down

**Version Detection:**
- GTPv1: Typically used for user plane (G-PDU)
- GTPv2: Typically used for control plane

## Integration with Other Tools

### With Wireshark

1. Capture with Wireshark/tshark
2. Analyze with gtp-analyzer
3. Export findings to JSON
4. Cross-reference with Wireshark's detailed protocol view

### With tcpdump

```bash
# Capture GTP traffic
tcpdump -i any -w gtp_capture.pcap "udp port 2152 or udp port 2123"

# Analyze with gtp-analyzer
gtp-analyzer stats gtp_capture.pcap --teid-summary
```

### With Excel/Spreadsheets

1. Export to CSV:
   ```bash
   gtp-analyzer export capture.pcap csv data.csv
   ```

2. Open in Excel for:
   - Pivot tables
   - Charts and graphs
   - Statistical analysis

### With Python Scripts

```python
import json

# Load exported JSON
with open('analysis.json') as f:
    data = json.load(f)

# Process statistics
stats = data['statistics']
print(f"Total packets: {stats['total_packets']}")
print(f"Unique TEIDs: {stats['unique_teids']}")

# Process packets if included
if 'packets' in data:
    for packet in data['packets']:
        if packet['teid'] == 12345:
            print(f"Found packet #{packet['packet_num']}")
```

## Troubleshooting

### No packets found

**Issue:** "No GTP packets found in PCAP file"

**Solutions:**
1. Verify capture contains UDP traffic on ports 2152 or 2123
2. Check if capture is corrupted
3. Ensure capture includes actual GTP protocol data

### Import errors

**Issue:** Module not found errors

**Solution:**
```bash
pip install -r requirements.txt
pip install -e .
```

### Slow performance

**Issue:** Analysis takes too long

**Solutions:**
1. Pre-filter PCAP in Wireshark
2. Use `--limit` option
3. Filter by specific TEIDs or IPs
4. Export to CSV for external processing

## Getting Help

### Command-specific help

```bash
gtp-analyzer parse --help
gtp-analyzer teid-track --help
gtp-analyzer filter --help
```

### General help

```bash
gtp-analyzer --help
```

### Version information

```bash
gtp-analyzer --version
```

## Additional Resources

- **README.md**: Complete reference documentation
- **GTP Protocol Specs**: 3GPP TS 29.060 (GTPv1), 29.274 (GTPv2)
- **Wireshark GTP Wiki**: https://wiki.wireshark.org/GTP
- **Sample PCAPs**: Use `create_sample_pcap.py` to generate test data

## Support

For issues, feature requests, or contributions, please refer to the project repository.
