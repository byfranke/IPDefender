class IPRecord:
    def __init__(self, ip: str, reason: str, timestamp: int):
        self.ip = ip
        self.reason = reason
        self.timestamp = timestamp

    def to_dict(self):
        return {
            "ip": self.ip,
            "reason": self.reason,
            "timestamp": self.timestamp
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            ip=data.get("ip"),
            reason=data.get("reason"),
            timestamp=data.get("timestamp")
        )