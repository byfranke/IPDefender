import pytest
from src.models.ip_record import IPRecord
from src.models.threat import Threat
from src.models.rule import Rule

def test_ip_record_creation():
    ip_record = IPRecord(ip="192.168.1.1", reason="Test reason")
    assert ip_record.ip == "192.168.1.1"
    assert ip_record.reason == "Test reason"

def test_threat_creation():
    threat = Threat(id="1", description="Test threat", severity="high")
    assert threat.id == "1"
    assert threat.description == "Test threat"
    assert threat.severity == "high"

def test_rule_creation():
    rule = Rule(id="1", action="block", target="ip", value="192.168.1.1")
    assert rule.id == "1"
    assert rule.action == "block"
    assert rule.target == "ip"
    assert rule.value == "192.168.1.1"