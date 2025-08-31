class Rule:
    def __init__(self, rule_id: str, ip: str, action: str, created_at: str):
        self.rule_id = rule_id
        self.ip = ip
        self.action = action
        self.created_at = created_at

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "ip": self.ip,
            "action": self.action,
            "created_at": self.created_at
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            rule_id=data.get("rule_id"),
            ip=data.get("ip"),
            action=data.get("action"),
            created_at=data.get("created_at")
        )