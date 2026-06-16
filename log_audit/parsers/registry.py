import os
from typing import Dict, List, Optional

from log_audit.models import LogRecord
from log_audit.parsers.base import BaseParser
from log_audit.parsers.gateway import GatewayParser
from log_audit.parsers.app import AppParser
from log_audit.parsers.login import LoginParser
from log_audit.parsers.resource import ResourceParser


class ParserRegistry:

    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}

    def register(self, parser: BaseParser) -> None:
        self._parsers[parser.source_type] = parser

    def get_parser(self, source_type: str) -> Optional[BaseParser]:
        return self._parsers.get(source_type)

    def auto_detect(self, file_path: str) -> Optional[BaseParser]:
        for parser in self._parsers.values():
            if parser.can_parse(file_path):
                return parser
        return None

    def parse_file(self, file_path: str) -> List[LogRecord]:
        parser = self.auto_detect(file_path)
        if parser is None:
            return []
        return parser.parse(file_path)

    def parse_directory(self, directory: str) -> List[LogRecord]:
        records: List[LogRecord] = []
        for root, _dirs, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                file_records = self.parse_file(fpath)
                records.extend(file_records)
        records.sort(key=lambda r: r.timestamp)
        return records

    @property
    def registered_types(self) -> List[str]:
        return list(self._parsers.keys())


def create_default_registry() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register(GatewayParser())
    registry.register(AppParser())
    registry.register(LoginParser())
    registry.register(ResourceParser())
    return registry
