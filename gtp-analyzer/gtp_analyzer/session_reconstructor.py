"""
Session Reconstructor Module

Reconstructs complete GTP sessions from PCAP files.
Tracks session establishment, modifications, and teardown.
"""

from typing import List, Dict, Any, Optional
from .gtp_parser import GTPPacket
from collections import defaultdict


class GTPSession:
    """Represents a complete GTP session"""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.packets: List[GTPPacket] = []
        self.teids: Dict[int, List[GTPPacket]] = defaultdict(list)
        self.qos_parameters = []
        self.bearers = []
        self.endpoints = set()
        self.events = []
    
    def add_packet(self, packet: GTPPacket):
        """Add packet to session"""
        self.packets.append(packet)
        
        # Track timing
        if self.start_time is None or packet.timestamp < self.start_time:
            self.start_time = packet.timestamp
        if self.end_time is None or packet.timestamp > self.end_time:
            self.end_time = packet.timestamp
        
        # Track TEIDs
        if packet.teid and packet.teid != 0:
            self.teids[packet.teid].append(packet)
        
        # Track endpoints
        if packet.src_ip:
            self.endpoints.add(packet.src_ip)
        if packet.dst_ip:
            self.endpoints.add(packet.dst_ip)
        
        # Track events
        msg_name = packet.get_message_type_name()
        if any(keyword in msg_name.lower() for keyword in ['create', 'modify', 'delete', 'update']):
            self.events.append({
                'timestamp': packet.timestamp,
                'event': msg_name,
                'teid': packet.teid,
                'packet_num': packet.packet_num
            })
    
    def get_duration(self) -> Optional[float]:
        """Get session duration"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None
    
    def get_summary(self) -> Dict[str, Any]:
        """Get session summary"""
        return {
            'session_id': self.session_id,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration_seconds': self.get_duration(),
            'total_packets': len(self.packets),
            'teids': list(self.teids.keys()),
            'teid_count': len(self.teids),
            'endpoints': list(self.endpoints),
            'events': self.events
        }
    
    def generate_flow_summary(self) -> str:
        """Generate human-readable flow summary"""
        lines = []
        lines.append(f"\nSession: {self.session_id}")
        lines.append("=" * 80)
        
        if self.start_time:
            lines.append(f"Start Time: {self.start_time:.3f}s")
        if self.end_time:
            lines.append(f"End Time: {self.end_time:.3f}s")
        
        duration = self.get_duration()
        if duration:
            lines.append(f"Duration: {duration:.3f}s")
        
        lines.append(f"Total Packets: {len(self.packets)}")
        lines.append(f"TEIDs Involved: {len(self.teids)}")
        lines.append(f"Endpoints: {', '.join(self.endpoints)}")
        
        lines.append("\nSession Events:")
        lines.append("-" * 80)
        for event in self.events:
            teid_str = f"TEID={event['teid']}" if event['teid'] else "No TEID"
            lines.append(f"  [{event['timestamp']:.3f}s] {event['event']} ({teid_str}) - Pkt#{event['packet_num']}")
        
        lines.append("\nTEID Distribution:")
        lines.append("-" * 80)
        for teid, teid_packets in sorted(self.teids.items()):
            lines.append(f"  TEID {teid}: {len(teid_packets)} packets")
        
        lines.append("=" * 80)
        return "\n".join(lines)


class SessionReconstructor:
    """Main Session Reconstructor class"""
    
    def __init__(self):
        self.sessions: Dict[str, GTPSession] = {}
    
    def reconstruct_sessions(self, packets: List[GTPPacket]) -> List[GTPSession]:
        """Reconstruct sessions from packets"""
        # Group packets by potential session identifiers
        # For simplicity, we'll use IP pairs and time windows
        
        # Sort packets by timestamp
        sorted_packets = sorted(packets, key=lambda p: p.timestamp)
        
        session_map = {}  # (src_ip, dst_ip) -> session_id
        session_counter = 1
        
        for packet in sorted_packets:
            # Create session key based on endpoints
            if packet.src_ip and packet.dst_ip:
                key1 = (packet.src_ip, packet.dst_ip)
                key2 = (packet.dst_ip, packet.src_ip)
                
                # Check if we've seen this conversation
                session_id = session_map.get(key1) or session_map.get(key2)
                
                if not session_id:
                    # New session
                    session_id = f"Session-{session_counter}"
                    session_counter += 1
                    session_map[key1] = session_id
                    session_map[key2] = session_id
                    self.sessions[session_id] = GTPSession(session_id)
                
                self.sessions[session_id].add_packet(packet)
        
        return list(self.sessions.values())
    
    def get_session(self, session_id: str) -> Optional[GTPSession]:
        """Get specific session"""
        return self.sessions.get(session_id)
    
    def get_all_sessions(self) -> List[GTPSession]:
        """Get all sessions"""
        return list(self.sessions.values())
    
    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all sessions"""
        return [session.get_summary() for session in self.sessions.values()]
