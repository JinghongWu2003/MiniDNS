"""Iterative DNS resolver implementation for MiniDNS."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
import time
from typing import Iterable

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .cache import CacheEntry, TTLCache
from .errors import (
    MalformedUpstreamResponseError,
    MaxDepthExceededError,
    NoGlueError,
    ResolutionError,
    UpstreamTimeoutError,
)
from .metrics import Metrics
from .root_hints import ROOT_SERVER_IPS


@dataclass
class ResolutionResult:
    qname: str
    qtype: str
    response: dns.message.Message | None
    answer_rrsets: list[dns.rrset.RRset]
    authority_rrsets: list[dns.rrset.RRset]
    additional_rrsets: list[dns.rrset.RRset]
    rcode: int
    trace: list[str]
    from_cache: bool
    blocked: bool
    latency_ms: float
    upstream_queries: int
    error: str | None = None


@dataclass
class _LookupContext:
    trace: list[str] = field(default_factory=list)
    upstream_queries: int = 0
    timeout_count: int = 0
    visited: set[tuple[str, str, str]] = field(default_factory=set)
    resolving_ns_hosts: set[str] = field(default_factory=set)


class IterativeResolver:
    """A small DNS resolver that walks the tree iteratively."""

    def __init__(
        self,
        cache: TTLCache[ResolutionResult] | None = None,
        metrics: Metrics | None = None,
        timeout: float = 2.0,
        max_depth: int = 20,
        trace: bool = False,
    ) -> None:
        self.cache = cache if cache is not None else TTLCache()
        self.metrics = metrics if metrics is not None else Metrics()
        self.timeout = timeout
        self.max_depth = max_depth
        self.trace_enabled = trace

    def resolve(self, qname: str, qtype: str = "A") -> ResolutionResult:
        start = time.time()
        ctx = _LookupContext()
        canonical_name = self._absolute_name(qname)
        canonical_type = self._normalize_qtype(qtype)
        ctx.trace.append(f"start {canonical_name.rstrip('.')} {canonical_type}")

        try:
            result = self._resolve_with_cache(canonical_name, canonical_type, ctx, depth=0)
        except ResolutionError as exc:
            ctx.trace.append(f"resolution failed: {exc}")
            result = ResolutionResult(
                qname=canonical_name,
                qtype=canonical_type,
                response=None,
                answer_rrsets=[],
                authority_rrsets=[],
                additional_rrsets=[],
                rcode=dns.rcode.SERVFAIL,
                trace=list(ctx.trace),
                from_cache=False,
                blocked=False,
                latency_ms=0.0,
                upstream_queries=ctx.upstream_queries,
                error=str(exc),
            )

        result.latency_ms = (time.time() - start) * 1000.0
        result.upstream_queries = ctx.upstream_queries
        result.trace = list(ctx.trace)

        self.metrics.record_query(
            latency_ms=result.latency_ms,
            cache_result="hit" if result.from_cache else "miss",
            upstream_queries=result.upstream_queries,
            timeout_count=ctx.timeout_count,
            servfail=result.rcode == dns.rcode.SERVFAIL,
            nxdomain=result.rcode == dns.rcode.NXDOMAIN,
        )
        return result

    def _resolve_with_cache(
        self,
        qname: str,
        qtype: str,
        ctx: _LookupContext,
        depth: int,
    ) -> ResolutionResult:
        if depth > self.max_depth:
            raise MaxDepthExceededError(
                f"max referral depth exceeded while resolving {qname} {qtype}"
            )

        entry = self.cache.get_entry(qname, qtype)
        if entry is not None:
            return self._result_from_cache_entry(qname, qtype, entry, ctx)

        ctx.trace.append(f"cache miss {qname.rstrip('.')} {qtype}")
        result = self._iterative_lookup(qname, qtype, ROOT_SERVER_IPS, ctx, depth)

        ttl = self._cache_ttl_for_result(result)
        if ttl is not None and result.response is not None and result.rcode != dns.rcode.SERVFAIL:
            self.cache.put(qname, qtype, self._clone_result(result), ttl)
            ctx.trace.append(f"cached {qname.rstrip('.')} {qtype} ttl={ttl}s")

        return result

    def _result_from_cache_entry(
        self,
        qname: str,
        qtype: str,
        entry: CacheEntry[ResolutionResult],
        ctx: _LookupContext,
    ) -> ResolutionResult:
        remaining_ttl = max(1, int(entry.expires_at - time.time()))
        ctx.trace.append(
            f"cache hit {qname.rstrip('.')} {qtype} remaining_ttl={remaining_ttl}s"
        )
        cached = entry.value
        response = self._clone_response(cached.response)
        if response is not None:
            self._cap_message_ttls(response, remaining_ttl)

        answer_rrsets = self._clone_rrsets(cached.answer_rrsets)
        authority_rrsets = self._clone_rrsets(cached.authority_rrsets)
        additional_rrsets = self._clone_rrsets(cached.additional_rrsets)
        self._cap_rrset_ttls(answer_rrsets, remaining_ttl)
        self._cap_rrset_ttls(authority_rrsets, remaining_ttl)
        self._cap_rrset_ttls(additional_rrsets, remaining_ttl)

        return ResolutionResult(
            qname=qname,
            qtype=qtype,
            response=response,
            answer_rrsets=answer_rrsets,
            authority_rrsets=authority_rrsets,
            additional_rrsets=additional_rrsets,
            rcode=cached.rcode,
            trace=[],
            from_cache=True,
            blocked=False,
            latency_ms=0.0,
            upstream_queries=ctx.upstream_queries,
            error=cached.error,
        )

    def _iterative_lookup(
        self,
        qname: str,
        qtype: str,
        nameserver_ips: Iterable[str],
        ctx: _LookupContext,
        depth: int,
    ) -> ResolutionResult:
        if depth > self.max_depth:
            raise MaxDepthExceededError(
                f"max referral depth exceeded while resolving {qname} {qtype}"
            )

        last_error: ResolutionError | None = None
        candidate_ips = self._deduplicate_ips(nameserver_ips)
        if not candidate_ips:
            raise NoGlueError(f"no nameserver IPs available for {qname} {qtype}")

        for nameserver_ip in candidate_ips:
            visit_key = (nameserver_ip, qname, qtype)
            if visit_key in ctx.visited:
                continue
            ctx.visited.add(visit_key)
            ctx.trace.append(
                f"querying {nameserver_ip} for {qname.rstrip('.')} {qtype}"
            )

            try:
                response = self._query_upstream(qname, qtype, nameserver_ip, ctx)
            except (UpstreamTimeoutError, MalformedUpstreamResponseError) as exc:
                last_error = exc
                ctx.trace.append(f"upstream failure from {nameserver_ip}: {exc}")
                continue

            rcode = response.rcode()
            rcode_text = dns.rcode.to_text(rcode)
            ctx.trace.append(f"response from {nameserver_ip}: {rcode_text}")

            if rcode == dns.rcode.NXDOMAIN:
                ctx.trace.append(f"final response NXDOMAIN for {qname.rstrip('.')}")
                return self._build_result(qname, qtype, response, from_cache=False)

            if self._has_requested_answer(response, qtype):
                ctx.trace.append(
                    f"final answer {self._summarize_answers(response.answer)}"
                )
                return self._build_result(qname, qtype, response, from_cache=False)

            cname_target = self._extract_cname_target(response)
            if cname_target is not None:
                ctx.trace.append(
                    f"following CNAME {qname.rstrip('.')} -> {cname_target.rstrip('.')}"
                )
                cname_result = self._resolve_with_cache(cname_target, qtype, ctx, depth + 1)
                combined_response = self._combine_cname_result(
                    qname, qtype, response, cname_result
                )
                return self._build_result(
                    qname,
                    qtype,
                    combined_response,
                    from_cache=cname_result.from_cache,
                    error=cname_result.error,
                )

            if self._is_nodata_response(response):
                ctx.trace.append(f"received NODATA for {qname.rstrip('.')}")
                return self._build_result(qname, qtype, response, from_cache=False)

            ns_targets = self._extract_ns_targets(response)
            if not ns_targets:
                ctx.trace.append(
                    f"no referral or answer from {nameserver_ip}; returning best effort response"
                )
                return self._build_result(qname, qtype, response, from_cache=False)

            ctx.trace.append(
                f"referral targets: {', '.join(target.rstrip('.') for target in ns_targets)}"
            )
            glue_ips = self._extract_glue_ips(response.additional, ns_targets)
            if glue_ips:
                ctx.trace.append(f"using glue IPs: {', '.join(glue_ips)}")
                try:
                    return self._iterative_lookup(qname, qtype, glue_ips, ctx, depth + 1)
                except ResolutionError as exc:
                    last_error = exc
                    ctx.trace.append(f"glue referral failed: {exc}")
                    continue

            ctx.trace.append("no glue records; resolving nameserver hostnames")
            resolved_ns_ips = self._resolve_nameserver_ips(ns_targets, ctx, depth + 1)
            if not resolved_ns_ips:
                last_error = NoGlueError(
                    f"could not resolve referral nameservers for {qname} {qtype}"
                )
                ctx.trace.append(str(last_error))
                continue
            ctx.trace.append(f"resolved referral IPs: {', '.join(resolved_ns_ips)}")
            try:
                return self._iterative_lookup(
                    qname, qtype, resolved_ns_ips, ctx, depth + 1
                )
            except ResolutionError as exc:
                last_error = exc
                ctx.trace.append(f"resolved referral failed: {exc}")

        if last_error is not None:
            raise last_error
        raise UpstreamTimeoutError(f"all candidate nameservers failed for {qname} {qtype}")

    def _query_upstream(
        self,
        qname: str,
        qtype: str,
        nameserver_ip: str,
        ctx: _LookupContext,
    ) -> dns.message.Message:
        query = dns.message.make_query(qname, qtype, use_edns=True, payload=1232)
        ctx.upstream_queries += 1

        try:
            return dns.query.udp(
                query,
                nameserver_ip,
                timeout=self.timeout,
                raise_on_truncation=True,
            )
        except TypeError:
            return dns.query.udp(query, nameserver_ip, timeout=self.timeout)
        except dns.exception.Timeout as exc:
            ctx.timeout_count += 1
            raise UpstreamTimeoutError(f"timeout contacting {nameserver_ip}") from exc
        except Exception as exc:
            if self._is_truncation_exception(exc):
                ctx.trace.append(f"udp truncation from {nameserver_ip}; retrying TCP")
                try:
                    return dns.query.tcp(query, nameserver_ip, timeout=self.timeout)
                except dns.exception.Timeout as tcp_exc:
                    ctx.timeout_count += 1
                    raise UpstreamTimeoutError(
                        f"timeout contacting {nameserver_ip} over TCP"
                    ) from tcp_exc
                except Exception as tcp_exc:
                    raise MalformedUpstreamResponseError(
                        f"tcp fallback failed against {nameserver_ip}: {tcp_exc}"
                    ) from tcp_exc
            raise MalformedUpstreamResponseError(
                f"invalid response from {nameserver_ip}: {exc}"
            ) from exc

    def _resolve_nameserver_ips(
        self,
        ns_targets: Iterable[str],
        ctx: _LookupContext,
        depth: int,
    ) -> list[str]:
        resolved_ips: list[str] = []
        for ns_target in ns_targets:
            normalized_target = self._absolute_name(ns_target)
            if normalized_target in ctx.resolving_ns_hosts:
                continue

            ctx.resolving_ns_hosts.add(normalized_target)
            try:
                a_result = self._resolve_with_cache(normalized_target, "A", ctx, depth)
                a_ips = self._rrset_values_for_type(a_result.answer_rrsets, dns.rdatatype.A)
                if a_ips:
                    ctx.trace.append(
                        f"resolved nameserver {normalized_target.rstrip('.')} to {', '.join(a_ips)}"
                    )
                    resolved_ips.extend(a_ips)
                    continue

                aaaa_result = self._resolve_with_cache(normalized_target, "AAAA", ctx, depth)
                aaaa_ips = self._rrset_values_for_type(
                    aaaa_result.answer_rrsets, dns.rdatatype.AAAA
                )
                if aaaa_ips:
                    ctx.trace.append(
                        f"resolved nameserver {normalized_target.rstrip('.')} to {', '.join(aaaa_ips)}"
                    )
                    resolved_ips.extend(aaaa_ips)
            except ResolutionError as exc:
                ctx.trace.append(
                    f"failed to resolve nameserver {normalized_target.rstrip('.')}: {exc}"
                )
            finally:
                ctx.resolving_ns_hosts.discard(normalized_target)

        return self._deduplicate_ips(resolved_ips)

    def _build_result(
        self,
        qname: str,
        qtype: str,
        response: dns.message.Message,
        *,
        from_cache: bool,
        error: str | None = None,
    ) -> ResolutionResult:
        return ResolutionResult(
            qname=qname,
            qtype=qtype,
            response=response,
            answer_rrsets=self._clone_rrsets(response.answer),
            authority_rrsets=self._clone_rrsets(response.authority),
            additional_rrsets=self._clone_rrsets(response.additional),
            rcode=response.rcode(),
            trace=[],
            from_cache=from_cache,
            blocked=False,
            latency_ms=0.0,
            upstream_queries=0,
            error=error,
        )

    def _combine_cname_result(
        self,
        qname: str,
        qtype: str,
        cname_response: dns.message.Message,
        resolved_target: ResolutionResult,
    ) -> dns.message.Message:
        synthetic_query = dns.message.make_query(qname, qtype, use_edns=True, payload=1232)
        combined = dns.message.make_response(synthetic_query)
        combined.flags |= dns.flags.RA
        combined.set_rcode(resolved_target.rcode)

        seen_rrsets: set[str] = set()
        for rrset in list(cname_response.answer) + list(resolved_target.answer_rrsets):
            key = rrset.to_text()
            if key in seen_rrsets:
                continue
            combined.answer.append(copy.deepcopy(rrset))
            seen_rrsets.add(key)

        for rrset in resolved_target.authority_rrsets:
            combined.authority.append(copy.deepcopy(rrset))
        for rrset in resolved_target.additional_rrsets:
            combined.additional.append(copy.deepcopy(rrset))
        return combined

    def _cache_ttl_for_result(self, result: ResolutionResult) -> int | None:
        if result.response is None or result.rcode == dns.rcode.SERVFAIL:
            return None

        ttls = [rrset.ttl for rrset in result.answer_rrsets if rrset.ttl > 0]
        if ttls:
            return max(1, min(ttls))

        for rrset in result.authority_rrsets:
            if rrset.rdtype == dns.rdatatype.SOA and rrset:
                minimums = [getattr(rdata, "minimum", rrset.ttl) for rdata in rrset]
                return max(1, min([rrset.ttl] + [value for value in minimums if value > 0]))

        return 60 if result.rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) else None

    def _has_requested_answer(self, response: dns.message.Message, qtype: str) -> bool:
        rdtype = dns.rdatatype.from_text(qtype)
        return any(rrset.rdtype == rdtype for rrset in response.answer)

    def _extract_cname_target(self, response: dns.message.Message) -> str | None:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME and rrset:
                first_rdata = next(iter(rrset))
                return first_rdata.target.to_text()
        return None

    def _extract_ns_targets(self, response: dns.message.Message) -> list[str]:
        targets: list[str] = []
        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.NS:
                continue
            for rdata in rrset:
                targets.append(rdata.target.to_text())
        return self._deduplicate_names(targets)

    def _extract_glue_ips(
        self,
        additional_rrsets: Iterable[dns.rrset.RRset],
        ns_targets: Iterable[str],
    ) -> list[str]:
        target_names = {self._absolute_name(target) for target in ns_targets}
        ipv4: list[str] = []
        ipv6: list[str] = []

        for rrset in additional_rrsets:
            owner = rrset.name.to_text()
            if owner not in target_names:
                continue
            if rrset.rdtype == dns.rdatatype.A:
                ipv4.extend(rdata.address for rdata in rrset)
            elif rrset.rdtype == dns.rdatatype.AAAA:
                ipv6.extend(rdata.address for rdata in rrset)

        return self._deduplicate_ips(ipv4 + ipv6)

    def _is_nodata_response(self, response: dns.message.Message) -> bool:
        if response.rcode() != dns.rcode.NOERROR:
            return False
        if response.answer:
            return False
        return any(rrset.rdtype == dns.rdatatype.SOA for rrset in response.authority)

    def _clone_result(self, result: ResolutionResult) -> ResolutionResult:
        return ResolutionResult(
            qname=result.qname,
            qtype=result.qtype,
            response=self._clone_response(result.response),
            answer_rrsets=self._clone_rrsets(result.answer_rrsets),
            authority_rrsets=self._clone_rrsets(result.authority_rrsets),
            additional_rrsets=self._clone_rrsets(result.additional_rrsets),
            rcode=result.rcode,
            trace=list(result.trace),
            from_cache=result.from_cache,
            blocked=result.blocked,
            latency_ms=result.latency_ms,
            upstream_queries=result.upstream_queries,
            error=result.error,
        )

    def _clone_response(
        self, response: dns.message.Message | None
    ) -> dns.message.Message | None:
        if response is None:
            return None
        return dns.message.from_wire(response.to_wire())

    def _clone_rrsets(
        self, rrsets: Iterable[dns.rrset.RRset]
    ) -> list[dns.rrset.RRset]:
        return [copy.deepcopy(rrset) for rrset in rrsets]

    def _cap_message_ttls(self, message: dns.message.Message, ttl: int) -> None:
        for rrset in list(message.answer) + list(message.authority) + list(message.additional):
            rrset.ttl = min(rrset.ttl, ttl)

    def _cap_rrset_ttls(self, rrsets: Iterable[dns.rrset.RRset], ttl: int) -> None:
        for rrset in rrsets:
            rrset.ttl = min(rrset.ttl, ttl)

    def _summarize_answers(self, rrsets: Iterable[dns.rrset.RRset]) -> str:
        values: list[str] = []
        for rrset in rrsets:
            for rdata in rrset:
                values.append(rdata.to_text())
        return ", ".join(values) if values else "<empty>"

    def _rrset_values_for_type(
        self, rrsets: Iterable[dns.rrset.RRset], rdtype: int
    ) -> list[str]:
        values: list[str] = []
        for rrset in rrsets:
            if rrset.rdtype != rdtype:
                continue
            for rdata in rrset:
                if hasattr(rdata, "address"):
                    values.append(rdata.address)
                else:
                    values.append(rdata.to_text())
        return values

    def _deduplicate_ips(self, ips: Iterable[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)
            ordered.append(ip)
        return ordered

    def _deduplicate_names(self, names: Iterable[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for name in names:
            canonical = self._absolute_name(name)
            if canonical in seen:
                continue
            seen.add(canonical)
            ordered.append(canonical)
        return ordered

    def _absolute_name(self, qname: str) -> str:
        return dns.name.from_text(qname).to_text()

    def _normalize_qtype(self, qtype: str) -> str:
        return qtype.strip().upper()

    def _is_truncation_exception(self, exc: Exception) -> bool:
        return exc.__class__.__name__ == "Truncated"
