import unittest
from src.core.ip_manager import IPManager
from src.core.threat_intel import ThreatIntel

class TestCore(unittest.TestCase):

    def setUp(self):
        self.ip_manager = IPManager()
        self.threat_intel = ThreatIntel()

    def test_add_ip(self):
        ip = "192.168.1.1"
        self.ip_manager.add_ip(ip)
        self.assertIn(ip, self.ip_manager.get_all_ips())

    def test_remove_ip(self):
        ip = "192.168.1.1"
        self.ip_manager.add_ip(ip)
        self.ip_manager.remove_ip(ip)
        self.assertNotIn(ip, self.ip_manager.get_all_ips())

    def test_threat_intel_fetch(self):
        threats = self.threat_intel.fetch_threats()
        self.assertIsInstance(threats, list)

    def test_ip_blocking_logic(self):
        ip = "192.168.1.1"
        self.ip_manager.add_ip(ip)
        self.threat_intel.add_threat(ip)
        self.ip_manager.block_ip(ip)
        self.assertTrue(self.ip_manager.is_blocked(ip))

if __name__ == '__main__':
    unittest.main()