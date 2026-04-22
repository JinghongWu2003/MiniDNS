# MiniDNS

MiniDNS is a local iterative DNS resolver and UDP DNS server written in Python for a Brown CSCI 1680 final project. It resolves names by walking the DNS hierarchy itself, starting from root hints and following referrals down to authoritative nameservers. It also includes TTL-based caching, a suffix-aware domain blocklist, trace logging, and lightweight metrics.

## Why This Counts as a Networking Project

This project lives squarely in networking systems territory:

- It speaks DNS over UDP directly.
- It implements iterative resolution logic instead of delegating to the operating system.
- It follows root, TLD, and authoritative referrals.
- It handles protocol-level details like NXDOMAIN, NODATA, CNAME chains, glue records, and TTLs.
- It exposes a local recursive DNS service that tools like `dig` and `nslookup` can query.

## Features

- Iterative DNS resolution using `dnspython` packet parsing and transport primitives
- Local UDP DNS server on `127.0.0.1:5353`
- TTL-based in-memory cache
- Domain blocklist with exact and suffix matching
- Trace logs for resolution steps
- Metrics for cache hits, misses, blocked queries, timeouts, and latency
- Offline unit tests for cache, blocklist, metrics, and response building

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI Iterative Resolver

Resolve a domain iteratively and print the full trace:

```bash
python -m minidns resolve example.com A --trace
python -m minidns resolve brown.edu A --trace
python -m minidns resolve google.com AAAA --trace
```

Trace output includes:

- query name and type
- cache hit or miss
- nameserver queried
- referral targets
- glue IP selection
- final answer or NXDOMAIN
- latency
- upstream query count

## UDP DNS Server

Start the local recursive DNS server:

```bash
python -m minidns serve --host 127.0.0.1 --port 5353 --trace --blocklist blocked.txt
```

If port `5353` is already occupied on your machine, use a different local port such as `5533` and update the `dig` commands to match.

Then query it from another terminal:

```bash
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 brown.edu A
dig @127.0.0.1 -p 5353 google.com AAAA
dig @127.0.0.1 -p 5353 blocked.example.com A
```

Expected demo behavior:

- The first `example.com` query is usually a cache miss.
- The second `example.com` query should be a cache hit.
- `blocked.example.com A` returns `0.0.0.0`.
- Blocked AAAA queries return `::`.

The server prints concise one-line summaries such as:

```text
[MISS] example.com A 187ms upstream=3
[HIT] example.com A 1ms upstream=0
[BLOCK] blocked.example.com A -> 0.0.0.0
```

## Project Layout

```text
minidns/
  __init__.py
  __main__.py
  cli.py
  resolver.py
  server.py
  cache.py
  blocklist.py
  root_hints.py
  metrics.py
  errors.py

tests/
  test_cache.py
  test_blocklist.py
  test_metrics.py
  test_response_building.py
```

## Testing

Run the test suite:

```bash
pytest
```

You can also verify Python syntax compilation:

```bash
python -m compileall minidns
```

## Cache Behavior

- Cache keys normalize names without the trailing dot.
- Positive answers use the minimum answer TTL.
- NXDOMAIN and NODATA responses are cached using SOA-derived TTLs when available.
- SERVFAIL responses are not cached.

## Blocklist Behavior

- Blank lines and `#` comments are ignored.
- Matching is case-insensitive.
- `example.com` blocks both `example.com` and `ads.example.com`.
- `example.com` does not block `badexample.com`.

## Known Limitations

- This is not a production DNS resolver.
- DNSSEC is not validated.
- Record type support is best-effort outside the core set of `A`, `AAAA`, `TXT`, `NS`, and `CNAME`.
- The server is single-threaded and not hardened against malicious traffic.
- CNAME handling is best-effort.
- TCP fallback is limited to truncated upstream responses.
- Metrics are in-memory only.

## Academic Constraint

MiniDNS uses `dnspython` for DNS packet parsing, response construction, and DNS transport primitives, but it does not call `dns.resolver.resolve()`, `socket.getaddrinfo()`, or the operating system's resolver to perform the actual lookup.
