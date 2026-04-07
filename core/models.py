# core/models.py
from dataclasses import dataclass
from typing import List

@dataclass
class Vulnerability:
    type: str
    severity: str
    endpoint: str
    payload: str
    description: str

@dataclass
class ScanResult:
    target: str
    vulnerabilities: List[Vulnerability]
    score: int