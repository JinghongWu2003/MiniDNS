"""A tiny TTL-based in-memory cache for DNS results."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Dict, Generic, Optional, TypeVar

T = TypeVar("T")


def _normalize_qname(qname: str) -> str:
    return qname.strip().rstrip(".").lower()


def _normalize_qtype(qtype: str) -> str:
    return qtype.strip().upper()


@dataclass
class CacheEntry(Generic[T]):
    value: T
    expires_at: float
    original_ttl: int
    cached_at: float


class TTLCache(Generic[T]):
    """A small DNS-oriented TTL cache."""

    def __init__(self) -> None:
        self._entries: Dict[str, CacheEntry[T]] = {}
        self._hits = 0
        self._misses = 0

    def _key(self, qname: str, qtype: str) -> str:
        return f"{_normalize_qname(qname)}|{_normalize_qtype(qtype)}"

    def _purge_expired(self) -> None:
        now = time.time()
        expired_keys = [
            key for key, entry in self._entries.items() if entry.expires_at <= now
        ]
        for key in expired_keys:
            self._entries.pop(key, None)

    def get_entry(self, qname: str, qtype: str) -> Optional[CacheEntry[T]]:
        self._purge_expired()
        key = self._key(qname, qtype)
        entry = self._entries.get(key)
        if entry is None:
            self._misses += 1
            return None
        self._hits += 1
        return entry

    def get(self, qname: str, qtype: str) -> Optional[T]:
        entry = self.get_entry(qname, qtype)
        if entry is None:
            return None
        return entry.value

    def put(self, qname: str, qtype: str, value: T, ttl: int) -> None:
        ttl = int(ttl)
        if ttl <= 0:
            return
        now = time.time()
        self._entries[self._key(qname, qtype)] = CacheEntry(
            value=value,
            expires_at=now + ttl,
            original_ttl=ttl,
            cached_at=now,
        )

    def clear(self) -> None:
        self._entries.clear()
        self._hits = 0
        self._misses = 0

    def stats(self) -> dict[str, int]:
        self._purge_expired()
        return {
            "entries": len(self._entries),
            "hits": self._hits,
            "misses": self._misses,
        }
