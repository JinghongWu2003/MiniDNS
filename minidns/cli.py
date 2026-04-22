"""Command line interface for MiniDNS."""

from __future__ import annotations

import argparse
from pathlib import Path

import dns.rcode

from .blocklist import DomainBlocklist
from .cache import TTLCache
from .metrics import Metrics
from .resolver import IterativeResolver, ResolutionResult
from .server import UDPDNSServer


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minidns",
        description="MiniDNS: a local iterative DNS resolver with caching and blocking.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve_parser = subparsers.add_parser("resolve", help="Perform an iterative lookup")
    resolve_parser.add_argument("domain", help="Domain name to resolve")
    resolve_parser.add_argument("rtype", nargs="?", default="A", help="Record type")
    resolve_parser.add_argument("--trace", action="store_true", help="Print trace output")
    resolve_parser.add_argument(
        "--timeout", type=float, default=2.0, help="Per-upstream timeout in seconds"
    )
    resolve_parser.set_defaults(func=run_resolve)

    serve_parser = subparsers.add_parser("serve", help="Run the local UDP DNS server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    serve_parser.add_argument("--port", type=int, default=5353, help="Bind port")
    serve_parser.add_argument("--trace", action="store_true", help="Print detailed traces")
    serve_parser.add_argument(
        "--blocklist",
        default=None,
        help="Path to blocklist file",
    )
    serve_parser.add_argument(
        "--timeout", type=float, default=2.0, help="Per-upstream timeout in seconds"
    )
    serve_parser.set_defaults(func=run_serve)

    return parser


def run_resolve(args: argparse.Namespace) -> None:
    metrics = Metrics()
    resolver = IterativeResolver(
        cache=TTLCache(),
        metrics=metrics,
        timeout=args.timeout,
        trace=args.trace,
    )
    result = resolver.resolve(args.domain, args.rtype)
    print_result(result, show_trace=args.trace)
    print()
    print(metrics.summary_text())


def run_serve(args: argparse.Namespace) -> None:
    metrics = Metrics()
    resolver = IterativeResolver(
        cache=TTLCache(),
        metrics=metrics,
        timeout=args.timeout,
        trace=args.trace,
    )
    blocklist = None
    if args.blocklist:
        blocklist_path = Path(args.blocklist)
        blocklist = DomainBlocklist.from_file(blocklist_path)
    server = UDPDNSServer(
        host=args.host,
        port=args.port,
        resolver=resolver,
        blocklist=blocklist,
        metrics=metrics,
        trace=args.trace,
    )
    try:
        server.serve_forever()
    except OSError as exc:
        raise SystemExit(
            f"failed to bind UDP server on {args.host}:{args.port}: {exc}"
        ) from exc


def print_result(result: ResolutionResult, *, show_trace: bool) -> None:
    if show_trace:
        print("Trace:")
        for line in result.trace:
            print(f"  - {line}")
        print()

    print(f"Query: {result.qname.rstrip('.')} {result.qtype}")
    print(f"RCODE: {dns.rcode.to_text(result.rcode)}")
    print(f"Cache: {'HIT' if result.from_cache else 'MISS'}")
    print(f"Latency: {result.latency_ms:.2f} ms")
    print(f"Upstream queries: {result.upstream_queries}")

    if result.answer_rrsets:
        print("Answers:")
        for rrset in result.answer_rrsets:
            print(f"  {rrset.to_text()}")
    elif result.authority_rrsets:
        print("Authority:")
        for rrset in result.authority_rrsets:
            print(f"  {rrset.to_text()}")
    else:
        print("Answers: <none>")

    if result.additional_rrsets:
        print("Additional:")
        for rrset in result.additional_rrsets:
            print(f"  {rrset.to_text()}")

    if result.error:
        print(f"Error: {result.error}")
