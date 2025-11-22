"""
Unit tests for GTP Parser module
"""

import unittest
from unittest.mock import Mock, patch
from gtp_analyzer.gtp_parser import GTPPacket, GTPParser
import struct


class TestGTPPacket(unittest.TestCase):
    """Test cases for GTPPacket class"""
    
    def create_mock_packet_with_no_layers(self):
        """Create a mock packet that has no IP or UDP layers"""
        mock_packet = Mock()
        mock_packet.__contains__ = Mock(return_value=False)
        return mock_packet
    
    def test_gtpv1_message_type_names(self):
        """Test GTPv1 message type name resolution"""
        mock_packet = self.create_mock_packet_with_no_layers()
        gtp_packet = GTPPacket(mock_packet, 1, 1.0)
        
        # Set GTPv1 fields directly
        gtp_packet.version = 1
        
        # Test known message types
        gtp_packet.message_type = 1
        self.assertEqual(gtp_packet.get_message_type_name(), "Echo Request")
        
        gtp_packet.message_type = 16
        self.assertEqual(gtp_packet.get_message_type_name(), "Create PDP Context Request")
        
        gtp_packet.message_type = 255
        self.assertEqual(gtp_packet.get_message_type_name(), "G-PDU (User Data)")
        
        # Test unknown message type
        gtp_packet.message_type = 99
        self.assertTrue("Unknown" in gtp_packet.get_message_type_name())
    
    def test_gtpv2_message_type_names(self):
        """Test GTPv2 message type name resolution"""
        mock_packet = self.create_mock_packet_with_no_layers()
        gtp_packet = GTPPacket(mock_packet, 1, 1.0)
        
        # Set GTPv2 fields directly
        gtp_packet.version = 2
        
        # Test known message types
        gtp_packet.message_type = 32
        self.assertEqual(gtp_packet.get_message_type_name(), "Create Session Request")
        
        gtp_packet.message_type = 34
        self.assertEqual(gtp_packet.get_message_type_name(), "Modify Bearer Request")
        
        gtp_packet.message_type = 36
        self.assertEqual(gtp_packet.get_message_type_name(), "Delete Session Request")
    
    def test_to_dict(self):
        """Test packet to dictionary conversion"""
        mock_packet = self.create_mock_packet_with_no_layers()
        gtp_packet = GTPPacket(mock_packet, 1, 1.5)
        
        # Set fields directly
        gtp_packet.src_ip = "192.168.1.1"
        gtp_packet.dst_ip = "192.168.1.2"
        gtp_packet.src_port = 2152
        gtp_packet.dst_port = 2152
        gtp_packet.version = 1
        gtp_packet.message_type = 16
        gtp_packet.teid = 12345
        gtp_packet.sequence = 1
        gtp_packet.length = 100
        
        result = gtp_packet.to_dict()
        
        self.assertEqual(result['packet_num'], 1)
        self.assertEqual(result['timestamp'], 1.5)
        self.assertEqual(result['src_ip'], "192.168.1.1")
        self.assertEqual(result['teid'], 12345)
        self.assertEqual(result['gtp_version'], 1)


class TestGTPParser(unittest.TestCase):
    """Test cases for GTPParser class"""
    
    @patch('gtp_analyzer.gtp_parser.rdpcap')
    def test_filter_by_teid(self, mock_rdpcap):
        """Test filtering packets by TEID"""
        # Mock PCAP reading
        mock_rdpcap.return_value = []
        
        parser = GTPParser("test.pcap")
        
        # Create mock packets with different TEIDs
        packet1 = Mock()
        packet1.teid = 100
        packet2 = Mock()
        packet2.teid = 200
        packet3 = Mock()
        packet3.teid = 100
        
        parser.packets = [packet1, packet2, packet3]
        
        # Filter by TEID 100
        filtered = parser.filter_by_teid(100)
        
        self.assertEqual(len(filtered), 2)
        self.assertEqual(filtered[0].teid, 100)
        self.assertEqual(filtered[1].teid, 100)
    
    @patch('gtp_analyzer.gtp_parser.rdpcap')
    def test_get_unique_teids(self, mock_rdpcap):
        """Test getting unique TEIDs"""
        mock_rdpcap.return_value = []
        
        parser = GTPParser("test.pcap")
        
        # Create mock packets
        packet1 = Mock()
        packet1.teid = 100
        packet2 = Mock()
        packet2.teid = 200
        packet3 = Mock()
        packet3.teid = 100
        packet4 = Mock()
        packet4.teid = None
        packet5 = Mock()
        packet5.teid = 0
        
        parser.packets = [packet1, packet2, packet3, packet4, packet5]
        
        unique_teids = parser.get_unique_teids()
        
        self.assertEqual(len(unique_teids), 2)
        self.assertIn(100, unique_teids)
        self.assertIn(200, unique_teids)
        self.assertNotIn(0, unique_teids)
        self.assertNotIn(None, unique_teids)


if __name__ == '__main__':
    unittest.main()
