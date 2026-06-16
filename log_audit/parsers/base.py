from abc import ABC, abstractmethod
from typing import List

from log_audit.models import LogRecord


class BaseParser(ABC):

    @property
    @abstractmethod
    def source_type(self) -> str:
        pass

    @abstractmethod
    def can_parse(self, file_path: str) -> bool:
        pass

    @abstractmethod
    def parse(self, file_path: str) -> List[LogRecord]:
        pass
