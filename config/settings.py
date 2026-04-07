# config/settings.py
from dataclasses import dataclass
from enum import Enum

class ScanMode(Enum):
    QUICK = "quick"
    FULL = "full"

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

@dataclass
class ScanConfig:
    target_url: str
    mode: ScanMode = ScanMode.QUICK
    timeout: int = 5
    max_requests: int = 100
    safe_mode: bool = True