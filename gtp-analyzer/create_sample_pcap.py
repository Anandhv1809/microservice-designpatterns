#!/usr/bin/env python3
"""
Script to create a sample GTP PCAP file for testing

This creates a synthetic PCAP with GTP packets for demonstration purposes.
"""

from scapy.all import IP, UDP, wrpcap
import struct
import time


def create_gtp_packet(src_ip, dst_ip, version, msg_type, teid, seq_num, payload_data=b""):
    """Create a GTP packet"""
    
    if version == 1:
        # GTPv1 header
        flags = (version << 5) | 0x10  # Version and PT flag
        header = struct.pack('!BBHIHH',
                            flags,          # Flags
                            msg_type,       # Message Type
                            len(payload_data),  # Length
                            teid,           # TEID
                            seq_num,        # Sequence
                            0)              # N-PDU Number and Next Extension Header
        
        gtp_payload = header + payload_data
    
    elif version == 2:
        # GTPv2 header
        flags = (version << 5) | 0x48  # Version, P flag, and T flag
        header = struct.pack('!BBHIBBH',
                            flags,          # Flags
                            msg_type,       # Message Type
                            len(payload_data) + 8,  # Length (includes TEID and sequence)
                            teid,           # TEID
                            (seq_num >> 16) & 0xFF,  # Sequence (3 bytes)
                            (seq_num >> 8) & 0xFF,
                            seq_num & 0xFF)
        
        gtp_payload = header + payload_data
    else:
        raise ValueError("Unsupported GTP version")
    
    # Create IP/UDP packet
    packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=2152, dport=2152) / gtp_payload
    
    return packet


def main():
    """Generate sample PCAP with various GTP messages"""
    
    packets = []
    base_time = time.time()
    
    # Scenario: Create a session with TEID 12345
    print("Creating sample GTP PCAP file...")
    
    # 1. Echo Request/Response (GTPv2)
    print("  - Adding Echo Request/Response")
    packets.append(create_gtp_packet("192.168.1.10", "192.168.1.20", 2, 1, 0, 1))
    packets.append(create_gtp_packet("192.168.1.20", "192.168.1.10", 2, 2, 0, 1))
    
    # 2. Create Session Request/Response (GTPv2)
    print("  - Adding Create Session Request/Response")
    packets.append(create_gtp_packet("192.168.1.10", "192.168.1.20", 2, 32, 0, 100))
    packets.append(create_gtp_packet("192.168.1.20", "192.168.1.10", 2, 33, 12345, 100))
    
    # 3. User Data (GTPv1 G-PDU)
    print("  - Adding User Data packets")
    for i in range(10):
        user_data = f"User data packet {i}".encode()
        packets.append(create_gtp_packet("192.168.1.10", "192.168.1.20", 1, 255, 12345, 200 + i, user_data))
    
    # 4. Modify Bearer Request/Response (GTPv2)
    print("  - Adding Modify Bearer Request/Response")
    packets.append(create_gtp_packet("192.168.1.10", "192.168.1.20", 2, 34, 12345, 300))
    packets.append(create_gtp_packet("192.168.1.20", "192.168.1.10", 2, 35, 12345, 300))
    
    # 5. More user data
    print("  - Adding more User Data packets")
    for i in range(5):
        user_data = f"More user data {i}".encode()
        packets.append(create_gtp_packet("192.168.1.10", "192.168.1.20", 1, 255, 12345, 400 + i, user_data))
    
    # 6. Create another session with TEID 67890
    print("  - Adding second session (TEID 67890)")
    packets.append(create_gtp_packet("192.168.1.30", "192.168.1.40", 2, 32, 0, 500))
    packets.append(create_gtp_packet("192.168.1.40", "192.168.1.30", 2, 33, 67890, 500))
    
    # 7. User data for second session
    for i in range(3):
        user_data = f"Session 2 data {i}".encode()
        packets.append(create_gtp_packet("192.168.1.30", "192.168.1.40", 1, 255, 67890, 600 + i, user_data))
    
    # 8. Delete Session for first TEID (GTPv2)
    print("  - Adding Delete Session Request/Response")
    packets.append(create_gtp_packet("192.168.1.10", "192.168.1.20", 2, 36, 12345, 700))
    packets.append(create_gtp_packet("192.168.1.20", "192.168.1.10", 2, 37, 12345, 700))
    
    # Write to PCAP file
    output_file = "sample_pcaps/gtp_sample.pcap"
    print(f"\nWriting {len(packets)} packets to {output_file}...")
    wrpcap(output_file, packets)
    
    print(f"✓ Sample PCAP created successfully!")
    print(f"\nGenerated capture includes:")
    print(f"  - 2 GTP sessions (TEIDs: 12345, 67890)")
    print(f"  - Echo messages")
    print(f"  - Create/Modify/Delete Session messages")
    print(f"  - User data (G-PDU) packets")
    print(f"  - Both GTPv1 and GTPv2 messages")
    print(f"\nTest the analyzer with:")
    print(f"  gtp-analyzer parse {output_file}")
    print(f"  gtp-analyzer stats {output_file} --teid-summary")
    print(f"  gtp-analyzer teid-track {output_file} 12345")


if __name__ == '__main__':
    main()
