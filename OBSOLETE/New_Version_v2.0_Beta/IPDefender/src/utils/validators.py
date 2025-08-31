def is_valid_ip(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True

def is_valid_action(action: str) -> bool:
    return action in ("add", "delete", "del")

def validate_input(action: str, ip: str) -> bool:
    return is_valid_action(action) and is_valid_ip(ip)