"""Simple counters and latency summaries for MiniDNS."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Metrics:
    total_client_queries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    blocked_queries: int = 0
    upstream_queries: int = 0
    upstream_timeouts: int = 0
    servfail_count: int = 0
    nxdomain_count: int = 0
    total_resolution_latency_ms: float = 0.0
    latency_samples_ms: list[float] = field(default_factory=list)

    def record_query(
        self,
        *,
        latency_ms: float,
        cache_result: str | None = None,
        blocked: bool = False,
        upstream_queries: int = 0,
        timeout_count: int = 0,
        servfail: bool = False,
        nxdomain: bool = False,
    ) -> None:
        self.total_client_queries += 1
        if cache_result == "hit":
            self.cache_hits += 1
        elif cache_result == "miss":
            self.cache_misses += 1
        if blocked:
            self.blocked_queries += 1
        self.upstream_queries += upstream_queries
        self.upstream_timeouts += timeout_count
        if servfail:
            self.servfail_count += 1
        if nxdomain:
            self.nxdomain_count += 1
        self.total_resolution_latency_ms += latency_ms
        self.latency_samples_ms.append(latency_ms)

    def average_latency_ms(self) -> float:
        if not self.latency_samples_ms:
            return 0.0
        return self.total_resolution_latency_ms / len(self.latency_samples_ms)

    def summary(self) -> dict[str, float | int]:
        return {
            "total_client_queries": self.total_client_queries,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "blocked_queries": self.blocked_queries,
            "upstream_queries": self.upstream_queries,
            "upstream_timeouts": self.upstream_timeouts,
            "servfail_count": self.servfail_count,
            "nxdomain_count": self.nxdomain_count,
            "average_latency_ms": round(self.average_latency_ms(), 2),
        }

    def summary_text(self) -> str:
        summary = self.summary()
        return "\n".join(
            [
                "MiniDNS metrics:",
                f"  total_client_queries: {summary['total_client_queries']}",
                f"  cache_hits: {summary['cache_hits']}",
                f"  cache_misses: {summary['cache_misses']}",
                f"  blocked_queries: {summary['blocked_queries']}",
                f"  upstream_queries: {summary['upstream_queries']}",
                f"  upstream_timeouts: {summary['upstream_timeouts']}",
                f"  servfail_count: {summary['servfail_count']}",
                f"  nxdomain_count: {summary['nxdomain_count']}",
                f"  average_latency_ms: {summary['average_latency_ms']}",
            ]
        )
