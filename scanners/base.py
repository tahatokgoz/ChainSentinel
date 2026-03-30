from abc import ABC, abstractmethod
from typing import Optional


class BaseScanner(ABC):
    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.findings: list[dict] = []

    @abstractmethod
    def run(self) -> list[dict]:
        pass

    def add_finding(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
        cvss_score: Optional[float] = None,
    ):
        self.findings.append({
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "cvss_score": cvss_score,
        })

    @property
    def base_url(self) -> str:
        return f"http://{self.target_host}:{self.target_port}"
