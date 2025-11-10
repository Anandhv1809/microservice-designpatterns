"""
TEID Tracker Module

Tracks TEID allocation, usage, and deallocation throughout packet captures.
Generates lifecycle reports and diagrams.
"""

from typing import List, Dict, Any, Optional
from .gtp_parser import GTPPacket


class TEIDLifecycle:
    """Tracks the lifecycle of a single TEID"""
    
    def __init__(self, teid: int):
        self.teid = teid
        self.created_at: Optional[float] = None
        self.deleted_at: Optional[float] = None
        self.packets: List[GTPPacket] = []
        self.data_packets = 0
        self.control_packets = 0
        self.src_ips = set()
        self.dst_ips = set()
        self.modifications = []
    
    def add_packet(self, packet: GTPPacket):
        """Add a packet to this TEID's lifecycle"""
        self.packets.append(packet)
        
        # Track creation
        if self.created_at is None:
            msg_name = packet.get_message_type_name().lower()
            if 'create' in msg_name and 'response' in msg_name:
                self.created_at = packet.timestamp
        
        # Track modification
        msg_name = packet.get_message_type_name().lower()
        if 'modify' in msg_name or 'update' in msg_name:
            self.modifications.append({
                'timestamp': packet.timestamp,
                'message': packet.get_message_type_name()
            })
        
        # Track deletion
        if 'delete' in msg_name and 'response' in msg_name:
            self.deleted_at = packet.timestamp
        
        # Categorize packets
        if packet.message_type == 255 or 'g-pdu' in msg_name or 'user data' in msg_name:
            self.data_packets += 1
        else:
            self.control_packets += 1
        
        # Track IPs
        if packet.src_ip:
            self.src_ips.add(packet.src_ip)
        if packet.dst_ip:
            self.dst_ips.add(packet.dst_ip)
    
    def get_duration(self) -> Optional[float]:
        """Get the duration of this TEID's lifecycle"""
        if self.created_at and self.deleted_at:
            return self.deleted_at - self.created_at
        elif self.created_at and self.packets:
            return self.packets[-1].timestamp - self.created_at
        return None
    
    def is_active(self) -> bool:
        """Check if TEID is still active"""
        return self.deleted_at is None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert lifecycle to dictionary"""
        duration = self.get_duration()
        return {
            'teid': self.teid,
            'created_at': self.created_at,
            'deleted_at': self.deleted_at,
            'duration_seconds': duration,
            'total_packets': len(self.packets),
            'data_packets': self.data_packets,
            'control_packets': self.control_packets,
            'modifications': len(self.modifications),
            'src_ips': list(self.src_ips),
            'dst_ips': list(self.dst_ips),
            'status': 'Deleted' if not self.is_active() else 'Active'
        }
    
    def generate_ascii_diagram(self) -> str:
        """Generate ASCII art lifecycle diagram"""
        lines = []
        lines.append(f"\nTEID {self.teid} Lifecycle Diagram")
        lines.append("=" * 60)
        
        if self.created_at:
            lines.append(f"[CREATE] @ {self.created_at:.3f}s")
            lines.append("    |")
        
        for mod in self.modifications:
            lines.append(f"    |-- [MODIFY] @ {mod['timestamp']:.3f}s - {mod['message']}")
        
        if self.data_packets > 0:
            lines.append(f"    |-- [DATA] {self.data_packets} packets")
        
        if self.control_packets > 0:
            lines.append(f"    |-- [CONTROL] {self.control_packets} packets")
        
        if self.deleted_at:
            lines.append("    |")
            lines.append(f"[DELETE] @ {self.deleted_at:.3f}s")
            duration = self.get_duration()
            if duration:
                lines.append(f"Duration: {duration:.3f} seconds")
        elif self.created_at:
            lines.append("    |")
            lines.append("[ACTIVE] - Still active at end of capture")
        
        lines.append("=" * 60)
        return "\n".join(lines)


class TEIDTracker:
    """Main TEID Tracker class"""
    
    def __init__(self):
        self.teids: Dict[int, TEIDLifecycle] = {}
    
    def track_packets(self, packets: List[GTPPacket]):
        """Track TEIDs across all packets"""
        for packet in packets:
            if packet.teid is not None and packet.teid != 0:
                if packet.teid not in self.teids:
                    self.teids[packet.teid] = TEIDLifecycle(packet.teid)
                self.teids[packet.teid].add_packet(packet)
    
    def get_teid_lifecycle(self, teid: int) -> Optional[TEIDLifecycle]:
        """Get lifecycle information for specific TEID"""
        return self.teids.get(teid)
    
    def get_all_teids(self) -> List[int]:
        """Get all tracked TEIDs"""
        return sorted(list(self.teids.keys()))
    
    def get_active_teids(self) -> List[int]:
        """Get TEIDs that are still active"""
        return [teid for teid, lifecycle in self.teids.items() if lifecycle.is_active()]
    
    def get_deleted_teids(self) -> List[int]:
        """Get TEIDs that have been deleted"""
        return [teid for teid, lifecycle in self.teids.items() if not lifecycle.is_active()]
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate summary report of all TEIDs"""
        total_teids = len(self.teids)
        active = len(self.get_active_teids())
        deleted = len(self.get_deleted_teids())
        
        total_data_packets = sum(lc.data_packets for lc in self.teids.values())
        total_control_packets = sum(lc.control_packets for lc in self.teids.values())
        
        return {
            'total_teids': total_teids,
            'active_teids': active,
            'deleted_teids': deleted,
            'total_data_packets': total_data_packets,
            'total_control_packets': total_control_packets,
            'teids': [lc.to_dict() for lc in self.teids.values()]
        }
