"""
GTP Packet Parser Module

Handles parsing of PCAP files and extraction of GTP packets.
Supports both GTPv1 and GTPv2 protocols.
"""

from scapy.all import rdpcap, IP, UDP
from scapy.contrib.gtp import GTP_U_Header, GTPHeader
from typing import List, Dict, Any, Optional
import struct


class GTPPacket:
    """Represents a parsed GTP packet with relevant information"""
    
    def __init__(self, packet, packet_num: int, timestamp: float):
        self.packet_num = packet_num
        self.timestamp = timestamp
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.version = None
        self.message_type = None
        self.teid = None
        self.sequence = None
        self.length = None
        self.raw_packet = packet
        
        self._parse_packet(packet)
    
    def _parse_packet(self, packet):
        """Parse GTP packet and extract relevant fields"""
        if IP in packet:
            self.src_ip = packet[IP].src
            self.dst_ip = packet[IP].dst
        
        if UDP in packet:
            self.src_port = packet[UDP].sport
            self.dst_port = packet[UDP].dport
            
            # Try to parse GTP header
            payload = bytes(packet[UDP].payload)
            if len(payload) >= 8:
                # Parse GTP header manually
                flags = payload[0]
                self.version = (flags >> 5) & 0x07
                
                if self.version == 1:
                    # GTPv1
                    self.message_type = payload[1]
                    self.length = struct.unpack('!H', payload[2:4])[0]
                    self.teid = struct.unpack('!I', payload[4:8])[0]
                    
                    if len(payload) >= 12:
                        self.sequence = struct.unpack('!H', payload[8:10])[0]
                        
                elif self.version == 2:
                    # GTPv2
                    self.message_type = payload[1]
                    self.length = struct.unpack('!H', payload[2:4])[0]
                    
                    # TEID presence based on message type
                    teid_flag = (flags >> 3) & 0x01
                    if teid_flag:
                        if len(payload) >= 12:
                            self.teid = struct.unpack('!I', payload[4:8])[0]
                            self.sequence = (struct.unpack('!I', payload[8:12])[0] >> 8) & 0xFFFFFF
                    else:
                        if len(payload) >= 8:
                            self.sequence = (struct.unpack('!I', payload[4:8])[0] >> 8) & 0xFFFFFF
    
    def get_message_type_name(self) -> str:
        """Get human-readable message type name"""
        if self.version == 1:
            return self._get_gtpv1_message_type()
        elif self.version == 2:
            return self._get_gtpv2_message_type()
        return f"Unknown ({self.message_type})"
    
    def _get_gtpv1_message_type(self) -> str:
        """Get GTPv1 message type name"""
        types = {
            1: "Echo Request",
            2: "Echo Response",
            16: "Create PDP Context Request",
            17: "Create PDP Context Response",
            18: "Update PDP Context Request",
            19: "Update PDP Context Response",
            20: "Delete PDP Context Request",
            21: "Delete PDP Context Response",
            255: "G-PDU (User Data)"
        }
        return types.get(self.message_type, f"Unknown Type {self.message_type}")
    
    def _get_gtpv2_message_type(self) -> str:
        """Get GTPv2 message type name"""
        types = {
            1: "Echo Request",
            2: "Echo Response",
            32: "Create Session Request",
            33: "Create Session Response",
            34: "Modify Bearer Request",
            35: "Modify Bearer Response",
            36: "Delete Session Request",
            37: "Delete Session Response",
            95: "Create Bearer Request",
            96: "Create Bearer Response",
            97: "Update Bearer Request",
            98: "Update Bearer Response",
            99: "Delete Bearer Request",
            100: "Delete Bearer Response"
        }
        return types.get(self.message_type, f"Unknown Type {self.message_type}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary for export"""
        return {
            'packet_num': self.packet_num,
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'gtp_version': self.version,
            'message_type': self.message_type,
            'message_type_name': self.get_message_type_name(),
            'teid': self.teid,
            'sequence': self.sequence,
            'length': self.length
        }


class GTPParser:
    """Main GTP Parser class for PCAP file analysis"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets: List[GTPPacket] = []
    
    def parse(self) -> List[GTPPacket]:
        """Parse PCAP file and extract GTP packets"""
        try:
            raw_packets = rdpcap(self.pcap_file)
        except Exception as e:
            raise ValueError(f"Failed to read PCAP file: {e}")
        
        for i, packet in enumerate(raw_packets, 1):
            # Check if packet contains UDP with GTP ports (2152, 2123)
            if UDP in packet:
                udp_layer = packet[UDP]
                if udp_layer.dport in [2152, 2123] or udp_layer.sport in [2152, 2123]:
                    gtp_packet = GTPPacket(packet, i, float(packet.time))
                    if gtp_packet.version in [1, 2]:
                        self.packets.append(gtp_packet)
        
        return self.packets
    
    def filter_by_teid(self, teid: int) -> List[GTPPacket]:
        """Filter packets by specific TEID"""
        return [p for p in self.packets if p.teid == teid]
    
    def filter_by_message_type(self, msg_type: int) -> List[GTPPacket]:
        """Filter packets by message type"""
        return [p for p in self.packets if p.message_type == msg_type]
    
    def get_unique_teids(self) -> List[int]:
        """Get list of unique TEIDs in the capture"""
        teids = set()
        for packet in self.packets:
            if packet.teid is not None and packet.teid != 0:
                teids.add(packet.teid)
        return sorted(list(teids))
    
    def get_message_type_counts(self) -> Dict[str, int]:
        """Get count of each message type"""
        counts = {}
        for packet in self.packets:
            msg_name = packet.get_message_type_name()
            counts[msg_name] = counts.get(msg_name, 0) + 1
        return counts
