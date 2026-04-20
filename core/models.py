from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanResult:
    """Enriched vulnerability finding — OWASP ZAP alert structure."""

    vuln_id:     str
    vuln_type:   str
    owasp:       str
    cwe:         str
    severity:    str
    confidence:  str
    endpoint:    str
    method:      str
    parameter:   Optional[str]
    payload:     Optional[str]
    evidence:    str
    description: str
    solution:    str
    reference:   str

    def to_dict(self) -> dict:
        return {
            "vuln_id":     self.vuln_id,
            "vuln_type":   self.vuln_type,
            "owasp":       self.owasp,
            "cwe":         self.cwe,
            "severity":    self.severity,
            "confidence":  self.confidence,
            "endpoint":    self.endpoint,
            "method":      self.method,
            "parameter":   self.parameter,
            "payload":     self.payload,
            "evidence":    self.evidence,
            "description": self.description,
            "solution":    self.solution,
            "reference":   self.reference,
        }

    def __str__(self) -> str:
        lines = [
            f"[{self.severity}] [{self.vuln_id}] {self.vuln_type}",
            f"  Endpoint  : {self.endpoint}",
            f"  Method    : {self.method}",
        ]
        if self.parameter:
            lines.append(f"  Parameter : {self.parameter}")
        if self.payload:
            lines.append(f"  Payload   : {self.payload}")
        lines.append(f"  Evidence  : {self.evidence[:200]}")
        lines.append(f"  OWASP     : {self.owasp}  |  CWE: {self.cwe}  |  Confidence: {self.confidence}")
        lines.append(f"  Solution  : {self.solution}")
        return "\n".join(lines)