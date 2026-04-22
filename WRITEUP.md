# MiniDNS Final Project Writeup Skeleton

## 1. Introduction

- Briefly describe the DNS problem space.
- Explain what MiniDNS does.
- State the course-relevant learning goals:
  iterative resolution, protocol parsing, caching, and local server behavior.
- Mention the academic constraint that the resolver logic was implemented manually rather than using the system resolver.

## 2. Design and Implementation

### 2.1 Iterative Resolver

- Describe how the resolver starts from root hints.
- Explain the resolution loop:
  root referral -> TLD referral -> authoritative answer.
- Describe how the resolver interprets answer, authority, and additional sections.
- Explain how query depth limits and visited-state tracking prevent loops.

### 2.2 Referrals and Glue Records

- Explain NS referrals from authority sections.
- Describe how glue A/AAAA records are extracted from additional sections.
- Explain what happens when glue is missing.
- Note how nameserver hostnames are resolved recursively when needed.

### 2.3 UDP DNS Server

- Describe the UDP server binding to `127.0.0.1:5353`.
- Explain request parsing with `dns.message.from_wire()`.
- Explain why the server supports one question per query.
- Describe response construction with `dns.message.make_response(query)`.
- Mention `RA=True` and error handling behavior.

### 2.4 Cache

- Explain the cache key format.
- Describe TTL storage and expiration.
- Explain positive caching and negative caching behavior.
- Include a note about why SERVFAIL is not cached.

### 2.5 Blocklist

- Describe the blocklist file format.
- Explain exact matching and suffix matching.
- Describe the blocked response strategy:
  `0.0.0.0` for `A`, `::` for `AAAA`, NXDOMAIN for other types.

## 3. Results

### 3.1 Commands Used

```bash
python -m minidns resolve example.com A --trace
python -m minidns serve --host 127.0.0.1 --port 5353 --trace --blocklist blocked.txt
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 blocked.example.com A
```

### 3.2 Sample Trace

Paste a short real trace here, for example:

```text
start example.com A
cache miss example.com A
querying 198.41.0.4 for example.com A
referral targets: a.gtld-servers.net, b.gtld-servers.net
using glue IPs: 192.5.6.30
querying 192.5.6.30 for example.com A
final answer 93.184.216.34
```

### 3.3 Cache Miss vs Cache Hit

| Query | First Query Latency | Second Query Latency | Notes |
| --- | --- | --- | --- |
| `example.com A` | fill in | fill in | second query should hit cache |
| `brown.edu A` | fill in | fill in | depends on TTL and timing |

### 3.4 Blocked Query Demo

- Show a blocked query using `blocked.example.com A`.
- Include the returned `0.0.0.0` answer.
- Mention the matching blocklist rule.

## 4. Challenges

- Handling referrals without glue records
- Picking a cache TTL for negative responses
- Combining CNAME chains with final answers cleanly
- Deciding when to fall back from UDP to TCP
- Building syntactically valid DNS responses even on failure paths

## 5. Future Work

- DNSSEC validation
- Better TCP fallback
- More complete negative caching
- Full record type support
- Concurrency or async request handling
- Persistent metrics and cache introspection

## 6. AI and Tooling Disclosure

Replace this placeholder with your actual disclosure policy and summary of how you used AI, coding assistants, debuggers, or other tools while building MiniDNS.
