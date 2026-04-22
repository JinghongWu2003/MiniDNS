"""UDP DNS server that exposes the iterative resolver locally."""

from __future__ import annotations

import copy
import socket
from typing import Iterable

import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .blocklist import DomainBlocklist
from .metrics import Metrics
from .resolver import IterativeResolver, ResolutionResult


class UDPDNSServer:
    """A very small UDP recursive DNS server."""

    def __init__(
        self,
        host: str,
        port: int,
        resolver: IterativeResolver,
        blocklist: DomainBlocklist | None = None,
        metrics: Metrics | None = None,
        trace: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.resolver = resolver
        self.blocklist = blocklist
        self.metrics = metrics if metrics is not None else resolver.metrics
        self.trace = trace

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((self.host, self.port))
            print(f"MiniDNS listening on {self.host}:{self.port}")
            try:
                while True:
                    data, addr = sock.recvfrom(4096)
                    self.handle_packet(data, addr, sock)
            except KeyboardInterrupt:
                print("\nShutting down MiniDNS.")
                print(self.metrics.summary_text())

    def handle_packet(
        self,
        data: bytes,
        addr: tuple[str, int],
        sock: socket.socket,
    ) -> None:
        try:
            query = dns.message.from_wire(data)
        except Exception:
            response = dns.message.Message(id=int.from_bytes(data[:2], "big") if len(data) >= 2 else 0)
            response.flags |= dns.flags.QR | dns.flags.RA
            response.set_rcode(dns.rcode.FORMERR)
            sock.sendto(response.to_wire(), addr)
            return

        if len(query.question) != 1:
            response = self.build_error_response(query, dns.rcode.FORMERR)
            sock.sendto(response.to_wire(), addr)
            return

        question = query.question[0]
        qname = question.name.to_text()
        qtype = dns.rdatatype.to_text(question.rdtype)

        try:
            if self.blocklist is not None and self.blocklist.is_blocked(qname):
                matched_rule = self.blocklist.reason(qname)
                response = self.build_blocked_response(query)
                self.metrics.record_query(
                    latency_ms=0.0,
                    blocked=True,
                    cache_result=None,
                    upstream_queries=0,
                )
                sock.sendto(response.to_wire(), addr)
                target = "0.0.0.0" if question.rdtype == dns.rdatatype.A else "::"
                print(
                    f"[BLOCK] {qname.rstrip('.')} {qtype} -> {target}"
                    + (f" (rule={matched_rule})" if matched_rule else "")
                )
                return

            result = self.resolver.resolve(qname, qtype)
            response = self._build_response_from_result(query, result)
            sock.sendto(response.to_wire(), addr)
            self._log_result(qname, qtype, result)
            if self.trace:
                for line in result.trace:
                    print(f"  {line}")
        except Exception as exc:
            response = self.build_error_response(query, dns.rcode.SERVFAIL)
            sock.sendto(response.to_wire(), addr)
            print(f"[FAIL] {qname.rstrip('.')} {qtype} SERVFAIL {exc}")

    def build_blocked_response(self, query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        question = query.question[0]
        owner = question.name.to_text()

        if question.rdtype == dns.rdatatype.A:
            response.answer.append(
                dns.rrset.from_text(owner, 60, dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0")
            )
        elif question.rdtype == dns.rdatatype.AAAA:
            response.answer.append(
                dns.rrset.from_text(owner, 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "::")
            )
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)
        return response

    def build_error_response(
        self, query: dns.message.Message, rcode: int
    ) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        response.set_rcode(rcode)
        return response

    def _build_response_from_result(
        self, query: dns.message.Message, result: ResolutionResult
    ) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        response.set_rcode(result.rcode)
        self._append_rrsets(response.answer, result.answer_rrsets)
        self._append_rrsets(response.authority, result.authority_rrsets)
        self._append_rrsets(response.additional, result.additional_rrsets)
        return response

    def _append_rrsets(
        self,
        section: list[dns.rrset.RRset],
        rrsets: Iterable[dns.rrset.RRset],
    ) -> None:
        for rrset in rrsets:
            section.append(copy.deepcopy(rrset))

    def _log_result(self, qname: str, qtype: str, result: ResolutionResult) -> None:
        label = "[HIT]" if result.from_cache else "[MISS]"
        if result.rcode == dns.rcode.SERVFAIL:
            label = "[FAIL]"
        message = (
            f"{label} {qname.rstrip('.')} {qtype} {int(result.latency_ms)}ms"
            f" upstream={result.upstream_queries}"
        )
        if result.rcode == dns.rcode.NXDOMAIN:
            message += " NXDOMAIN"
        if result.error:
            message += f" error={result.error}"
        print(message)
