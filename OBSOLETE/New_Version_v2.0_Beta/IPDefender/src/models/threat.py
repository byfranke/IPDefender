class Threat:
    def __init__(self, id: str, name: str, description: str, source: str, severity: str, timestamp: str):
        self.id = id
        self.name = name
        self.description = description
        self.source = source
        self.severity = severity
        self.timestamp = timestamp

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "severity": self.severity,
            "timestamp": self.timestamp
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            id=data.get("id"),
            name=data.get("name"),
            description=data.get("description"),
            source=data.get("source"),
            severity=data.get("severity"),
            timestamp=data.get("timestamp")
        )