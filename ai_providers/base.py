from abc import ABC, abstractmethod


class BaseAIProvider(ABC):

    @abstractmethod
    def analyze_findings(self, findings: list[dict], scan_info: dict) -> dict:
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        pass
