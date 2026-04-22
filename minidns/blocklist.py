"""Domain blocklist support with exact and suffix matching."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


def _normalize_domain(name: str) -> str:
    return name.strip().rstrip(".").lower()


class DomainBlocklist:
    """A file-backed blocklist using exact and suffix domain matching."""

    def __init__(self, domains: Iterable[str] | None = None) -> None:
        self._domains: set[str] = set()
        if domains is not None:
            for domain in domains:
                self.add(domain)

    @classmethod
    def from_file(cls, path: str | Path) -> "DomainBlocklist":
        blocklist = cls()
        blocklist.load_file(path)
        return blocklist

    def load_file(self, path: str | Path) -> None:
        for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            self.add(line)

    def add(self, domain: str) -> None:
        normalized = _normalize_domain(domain)
        if normalized:
            self._domains.add(normalized)

    def reason(self, qname: str) -> str | None:
        normalized = _normalize_domain(qname)
        if not normalized:
            return None
        labels = normalized.split(".")
        for index in range(len(labels)):
            suffix = ".".join(labels[index:])
            if suffix in self._domains:
                return suffix
        return None

    def is_blocked(self, qname: str) -> bool:
        return self.reason(qname) is not None

    def __bool__(self) -> bool:
        return bool(self._domains)
