"""
Report Generator Module

Generates statistics, reports, and exports data in various formats.
"""

from typing import List, Dict, Any
from tabulate import tabulate
from .gtp_parser import GTPPacket, GTPParser
from .teid_tracker import TEIDTracker
from .session_reconstructor import SessionReconstructor
import json
import csv


class ReportGenerator:
    """Main Report Generator class"""
    
    def __init__(self, parser: GTPParser):
        self.parser = parser
    
    def generate_packet_table(self, packets: List[GTPPacket], highlight_teid: int = None) -> str:
        """Generate formatted table of packets"""
        if not packets:
            return "No packets to display"
        
        headers = ['Pkt#', 'Time', 'Src IP', 'Dst IP', 'GTP Ver', 'Message Type', 'TEID', 'Seq']
        rows = []
        
        for packet in packets:
            teid_str = str(packet.teid) if packet.teid else '-'
            
            # Highlight specific TEID if requested
            if highlight_teid and packet.teid == highlight_teid:
                teid_str = f">>> {teid_str} <<<"
            
            row = [
                packet.packet_num,
                f"{packet.timestamp:.3f}",
                packet.src_ip or '-',
                packet.dst_ip or '-',
                packet.version or '-',
                packet.get_message_type_name()[:30],
                teid_str,
                packet.sequence or '-'
            ]
            rows.append(row)
        
        return tabulate(rows, headers=headers, tablefmt='grid')
    
    def generate_statistics(self) -> Dict[str, Any]:
        """Generate comprehensive statistics"""
        packets = self.parser.packets
        
        if not packets:
            return {'error': 'No GTP packets found in PCAP'}
        
        # Basic stats
        total_packets = len(packets)
        version_counts = {}
        for packet in packets:
            ver = f"GTPv{packet.version}" if packet.version else "Unknown"
            version_counts[ver] = version_counts.get(ver, 0) + 1
        
        # Message type statistics
        msg_type_counts = self.parser.get_message_type_counts()
        
        # TEID statistics
        unique_teids = self.parser.get_unique_teids()
        
        # IP statistics
        src_ips = set()
        dst_ips = set()
        for packet in packets:
            if packet.src_ip:
                src_ips.add(packet.src_ip)
            if packet.dst_ip:
                dst_ips.add(packet.dst_ip)
        
        # Timing
        if packets:
            start_time = min(p.timestamp for p in packets)
            end_time = max(p.timestamp for p in packets)
            duration = end_time - start_time
        else:
            start_time = end_time = duration = 0
        
        return {
            'total_packets': total_packets,
            'gtp_versions': version_counts,
            'message_types': msg_type_counts,
            'unique_teids': len(unique_teids),
            'teid_list': unique_teids[:20],  # First 20 TEIDs
            'unique_src_ips': len(src_ips),
            'unique_dst_ips': len(dst_ips),
            'capture_duration_seconds': duration,
            'start_time': start_time,
            'end_time': end_time
        }
    
    def generate_statistics_table(self) -> str:
        """Generate formatted statistics table"""
        stats = self.generate_statistics()
        
        if 'error' in stats:
            return stats['error']
        
        lines = []
        lines.append("\n" + "=" * 80)
        lines.append("GTP PCAP ANALYSIS STATISTICS")
        lines.append("=" * 80)
        
        lines.append(f"\nTotal GTP Packets: {stats['total_packets']}")
        lines.append(f"Capture Duration: {stats['capture_duration_seconds']:.3f} seconds")
        lines.append(f"Unique TEIDs: {stats['unique_teids']}")
        lines.append(f"Unique Source IPs: {stats['unique_src_ips']}")
        lines.append(f"Unique Destination IPs: {stats['unique_dst_ips']}")
        
        lines.append("\n--- GTP Versions ---")
        for version, count in stats['gtp_versions'].items():
            lines.append(f"  {version}: {count} packets")
        
        lines.append("\n--- Message Types ---")
        for msg_type, count in sorted(stats['message_types'].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {msg_type}: {count} packets")
        
        if stats['teid_list']:
            lines.append(f"\n--- Sample TEIDs (first 20) ---")
            lines.append(f"  {', '.join(map(str, stats['teid_list']))}")
        
        lines.append("\n" + "=" * 80)
        return "\n".join(lines)
    
    def export_to_json(self, output_file: str, include_packets: bool = True):
        """Export analysis to JSON format"""
        data = {
            'statistics': self.generate_statistics(),
            'pcap_file': self.parser.pcap_file
        }
        
        if include_packets:
            data['packets'] = [p.to_dict() for p in self.parser.packets]
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def export_to_csv(self, output_file: str):
        """Export packets to CSV format"""
        if not self.parser.packets:
            raise ValueError("No packets to export")
        
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['packet_num', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                         'gtp_version', 'message_type', 'message_type_name', 'teid', 'sequence', 'length']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for packet in self.parser.packets:
                writer.writerow(packet.to_dict())
    
    def generate_teid_lifecycle_report(self, teid: int, tracker: TEIDTracker) -> str:
        """Generate lifecycle report for specific TEID"""
        lifecycle = tracker.get_teid_lifecycle(teid)
        
        if not lifecycle:
            return f"TEID {teid} not found in capture"
        
        # Generate ASCII diagram
        diagram = lifecycle.generate_ascii_diagram()
        
        # Generate detailed info
        lines = [diagram]
        lines.append("\n--- Detailed Information ---")
        lines.append(f"Total Packets: {len(lifecycle.packets)}")
        lines.append(f"Data Packets: {lifecycle.data_packets}")
        lines.append(f"Control Packets: {lifecycle.control_packets}")
        lines.append(f"Source IPs: {', '.join(lifecycle.src_ips)}")
        lines.append(f"Destination IPs: {', '.join(lifecycle.dst_ips)}")
        lines.append(f"Modifications: {len(lifecycle.modifications)}")
        lines.append(f"Status: {'Active' if lifecycle.is_active() else 'Deleted'}")
        
        # Show packet details
        lines.append("\n--- Packet Details ---")
        packet_table = self.generate_packet_table(lifecycle.packets[:50], highlight_teid=teid)
        lines.append(packet_table)
        
        if len(lifecycle.packets) > 50:
            lines.append(f"\n(Showing first 50 of {len(lifecycle.packets)} packets)")
        
        return "\n".join(lines)
