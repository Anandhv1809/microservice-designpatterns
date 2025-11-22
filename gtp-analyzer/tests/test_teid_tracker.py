"""
Unit tests for TEID Tracker module
"""

import unittest
from unittest.mock import Mock
from gtp_analyzer.teid_tracker import TEIDLifecycle, TEIDTracker


class TestTEIDLifecycle(unittest.TestCase):
    """Test cases for TEIDLifecycle class"""
    
    def test_lifecycle_creation(self):
        """Test TEID lifecycle creation"""
        lifecycle = TEIDLifecycle(12345)
        
        self.assertEqual(lifecycle.teid, 12345)
        self.assertIsNone(lifecycle.created_at)
        self.assertIsNone(lifecycle.deleted_at)
        self.assertEqual(lifecycle.data_packets, 0)
        self.assertEqual(lifecycle.control_packets, 0)
    
    def test_add_packet(self):
        """Test adding packets to lifecycle"""
        lifecycle = TEIDLifecycle(12345)
        
        # Create mock packet
        packet = Mock()
        packet.timestamp = 1.0
        packet.message_type = 17  # Create PDP Context Response
        packet.get_message_type_name = Mock(return_value="Create PDP Context Response")
        packet.src_ip = "192.168.1.1"
        packet.dst_ip = "192.168.1.2"
        
        lifecycle.add_packet(packet)
        
        self.assertEqual(len(lifecycle.packets), 1)
        self.assertEqual(lifecycle.created_at, 1.0)
        self.assertEqual(lifecycle.control_packets, 1)
        self.assertIn("192.168.1.1", lifecycle.src_ips)
        self.assertIn("192.168.1.2", lifecycle.dst_ips)
    
    def test_is_active(self):
        """Test active status check"""
        lifecycle = TEIDLifecycle(12345)
        
        # Initially active (no deletion)
        self.assertTrue(lifecycle.is_active())
        
        # After deletion
        lifecycle.deleted_at = 10.0
        self.assertFalse(lifecycle.is_active())
    
    def test_get_duration(self):
        """Test duration calculation"""
        lifecycle = TEIDLifecycle(12345)
        
        # No duration without timestamps
        self.assertIsNone(lifecycle.get_duration())
        
        # With creation but no deletion
        lifecycle.created_at = 1.0
        packet = Mock()
        packet.timestamp = 5.0
        lifecycle.packets.append(packet)
        
        duration = lifecycle.get_duration()
        self.assertEqual(duration, 4.0)
        
        # With both creation and deletion
        lifecycle.deleted_at = 10.0
        duration = lifecycle.get_duration()
        self.assertEqual(duration, 9.0)


class TestTEIDTracker(unittest.TestCase):
    """Test cases for TEIDTracker class"""
    
    def test_track_packets(self):
        """Test tracking multiple packets"""
        tracker = TEIDTracker()
        
        # Create mock packets
        packet1 = Mock()
        packet1.teid = 100
        packet1.timestamp = 1.0
        packet1.message_type = 17
        packet1.get_message_type_name = Mock(return_value="Create PDP Context Response")
        packet1.src_ip = "10.0.0.1"
        packet1.dst_ip = "10.0.0.2"
        
        packet2 = Mock()
        packet2.teid = 100
        packet2.timestamp = 2.0
        packet2.message_type = 255
        packet2.get_message_type_name = Mock(return_value="G-PDU (User Data)")
        packet2.src_ip = "10.0.0.1"
        packet2.dst_ip = "10.0.0.2"
        
        packet3 = Mock()
        packet3.teid = 200
        packet3.timestamp = 1.5
        packet3.message_type = 17
        packet3.get_message_type_name = Mock(return_value="Create PDP Context Response")
        packet3.src_ip = "10.0.0.3"
        packet3.dst_ip = "10.0.0.4"
        
        packets = [packet1, packet2, packet3]
        tracker.track_packets(packets)
        
        # Check tracking
        self.assertEqual(len(tracker.teids), 2)
        self.assertIn(100, tracker.teids)
        self.assertIn(200, tracker.teids)
        
        # Check TEID 100
        lifecycle_100 = tracker.get_teid_lifecycle(100)
        self.assertEqual(len(lifecycle_100.packets), 2)
        
        # Check TEID 200
        lifecycle_200 = tracker.get_teid_lifecycle(200)
        self.assertEqual(len(lifecycle_200.packets), 1)
    
    def test_get_active_and_deleted_teids(self):
        """Test getting active and deleted TEIDs"""
        tracker = TEIDTracker()
        
        # Create lifecycles
        lc1 = TEIDLifecycle(100)
        lc1.created_at = 1.0
        # lc1 is active (no deleted_at)
        
        lc2 = TEIDLifecycle(200)
        lc2.created_at = 1.0
        lc2.deleted_at = 10.0  # deleted
        
        tracker.teids = {100: lc1, 200: lc2}
        
        active = tracker.get_active_teids()
        deleted = tracker.get_deleted_teids()
        
        self.assertEqual(active, [100])
        self.assertEqual(deleted, [200])
    
    def test_generate_summary_report(self):
        """Test summary report generation"""
        tracker = TEIDTracker()
        
        # Create mock lifecycle
        lc = TEIDLifecycle(100)
        lc.data_packets = 10
        lc.control_packets = 5
        
        tracker.teids = {100: lc}
        
        summary = tracker.generate_summary_report()
        
        self.assertEqual(summary['total_teids'], 1)
        self.assertEqual(summary['total_data_packets'], 10)
        self.assertEqual(summary['total_control_packets'], 5)
        self.assertEqual(len(summary['teids']), 1)


if __name__ == '__main__':
    unittest.main()
