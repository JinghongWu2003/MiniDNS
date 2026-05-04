# MiniDNS: A Local Iterative DNS Resolver

**Demo video:** https://drive.google.com/file/d/10xurodpXUo_D7PyoSeBssmgd72uv9rIv/view?usp=sharing

## 1. Introduction

MiniDNS is a local iterative DNS resolver and UDP DNS server written in Python
for our CSCI 1680 final project. The project goal was to build a small
end-to-end DNS system that performs the main work of a recursive resolver
itself: starting from root hints, following referrals, contacting authoritative
nameservers, caching results, and returning DNS responses to local clients.

The main learning goal was to understand DNS resolution as a network protocol,
not just as a library call. MiniDNS uses `dnspython` for packet parsing,
message construction, and DNS transport helpers, but it does not use the
operating system resolver or `dns.resolver.resolve()` to perform lookups. The
resolver logic that chooses which nameserver to query next, how to interpret
referrals, and when to cache a result is implemented in our code.

The final system supports two modes. The CLI mode performs one iterative lookup
and can print a trace of the resolution path. The server mode listens on a
local UDP port, so standard tools such as `dig` can query MiniDNS as a DNS
server. We also implemented TTL-based caching, a small blocklist feature, trace
logging, lightweight metrics, and tests for the cache, blocklist, metrics, and
response-building logic.

## 2. Design and Implementation

MiniDNS is organized around a shared resolver. The command-line interface in
`minidns/cli.py` creates the resolver and either runs a single query or starts
the UDP server. The main iterative lookup logic is in `minidns/resolver.py`.
The local DNS server is implemented in `minidns/server.py`, while the cache,
blocklist, metrics, and root hints are separated into smaller helper modules.

The resolver begins each lookup by normalizing the query name and record type,
then checking the TTL cache. If the answer is not cached, it starts from a list
of root nameserver IP addresses. It sends a DNS query to an upstream
nameserver, inspects the response, and either returns a final answer or follows
a referral to the next level of the DNS hierarchy. For a normal query such as
`example.com A`, this usually means querying a root server, then a TLD server,
and finally an authoritative server.

Referral handling is the most important part of the design. When a DNS response
contains `NS` records in the authority section, MiniDNS treats them as the next
nameservers to ask. If the response also includes matching `A` or `AAAA`
records in the additional section, MiniDNS uses those glue records directly. If
glue is missing, MiniDNS recursively resolves the nameserver hostname using its
own resolver logic instead of asking the operating system. This keeps the
project focused on implementing the recursive-resolution behavior ourselves.

MiniDNS handles the main response cases needed for this proof of concept. It
returns final answers when the requested record type appears in the answer
section, follows CNAMEs when a response aliases the requested name, returns
NXDOMAIN for nonexistent names, and treats no-answer SOA responses as NODATA.
It also tracks visited query/nameserver combinations and limits recursion depth
to avoid getting stuck in referral loops.

The UDP server exposes the resolver as a local DNS service. It binds to a local
address such as `127.0.0.1:5353`, parses incoming packets with
`dns.message.from_wire()`, supports one-question DNS queries, and builds
responses with `dns.message.make_response()`. For normal queries, it calls the
iterative resolver and copies the answer, authority, and additional RRsets into
the response. For malformed requests or internal failures, it returns an
appropriate DNS error response such as `FORMERR` or `SERVFAIL`.

The cache stores results by normalized query name and type, such as
`example.com|A`. Positive answers are cached using DNS TTLs, expired entries are
removed, and SERVFAIL responses are not cached because they may represent
temporary upstream problems. MiniDNS also supports simple negative caching for
NXDOMAIN or NODATA responses. In server mode, the cache lets repeated queries
return quickly without walking the DNS hierarchy again.

The blocklist is a small application-level extension. It reads domains from
`blocked.txt`, ignores comments and blank lines, and matches both exact domains
and subdomains. For blocked `A` queries, the server returns `0.0.0.0`; for
blocked `AAAA` queries, it returns `::`; and for other blocked record types, it
returns NXDOMAIN. Trace logs and metrics make these behaviors visible during
testing and in the demo video.

## 3. Results and Discussion

We evaluated MiniDNS using live command-line traces, `dig` queries against the
local server, blocklist queries, and offline tests. The main result is that
MiniDNS can resolve real domains through iterative DNS lookup and can also
serve local DNS clients over UDP.

The main manual commands were:

```bash
python -m minidns resolve example.com A --trace
python -m minidns resolve brown.edu A --trace
python -m minidns serve --host 127.0.0.1 --port 5533 --trace --blocklist blocked.txt
dig @127.0.0.1 -p 5533 example.com A
dig @127.0.0.1 -p 5533 example.com A
dig @127.0.0.1 -p 5533 blocked.example.com A
```

Port `5353` was already in use on the test machine, so this run used the
alternate local port `5533`.

The following trace shows an iterative lookup:

```text
Trace:
  - start example.com A
  - cache miss example.com A
  - querying 198.41.0.4 for example.com A
  - response from 198.41.0.4: NOERROR
  - referral targets: l.gtld-servers.net, j.gtld-servers.net, h.gtld-servers.net, d.gtld-servers.net, b.gtld-servers.net, f.gtld-servers.net, k.gtld-servers.net, m.gtld-servers.net, i.gtld-servers.net, g.gtld-servers.net, a.gtld-servers.net, c.gtld-servers.net, e.gtld-servers.net
  - using glue IPs: 192.41.162.30, 192.48.79.30, 192.54.112.30, 192.31.80.30, 192.33.14.30, 192.35.51.30, 192.52.178.30, 192.55.83.30, 192.43.172.30, 192.42.93.30, 192.5.6.30, 192.26.92.30, 192.12.94.30
  - querying 192.41.162.30 for example.com A
  - response from 192.41.162.30: NOERROR
  - referral targets: hera.ns.cloudflare.com, elliott.ns.cloudflare.com
  - using glue IPs: 108.162.192.162, 172.64.32.162, 173.245.58.162, 108.162.195.228, 162.159.44.228, 172.64.35.228
  - querying 108.162.192.162 for example.com A
  - response from 108.162.192.162: NOERROR
  - final answer 104.20.23.154, 172.66.147.243
  - cached example.com A ttl=300s

Query: example.com A
RCODE: NOERROR
Cache: MISS
Latency: 110.62 ms
Upstream queries: 3
```

In this run, MiniDNS first contacted root server `198.41.0.4`, followed a
referral to the `.com` TLD server at `192.41.162.30`, then queried the
authoritative nameserver at `108.162.192.162` to obtain the final answer. The
lookup used `3` upstream queries and completed in `110.62` ms. This trace is
the clearest evidence that the resolver is walking the DNS hierarchy itself
rather than delegating the lookup to the system resolver.

The local UDP server was tested with `dig`. We used two identical queries to
show the difference between a cache miss and a cache hit:

| Query | Run | Result | Latency | Upstream Queries |
| --- | --- | --- | --- | --- |
| `example.com A` | 1 | MISS | `170 ms` | `3` |
| `example.com A` | 2 | HIT | `0 ms` | `0` |

The first query is expected to do more work because MiniDNS has to contact
upstream nameservers and follow referrals. The second query can be answered
from the local cache, so it should require fewer or no upstream queries.
Latency varies depending on network conditions, but the cache behavior is
visible in the server logs and metrics.

We also tested the blocklist feature:

```text
; <<>> DiG 9.10.6 <<>> @127.0.0.1 -p 5533 blocked.example.com A
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5880
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;blocked.example.com.          IN      A

;; ANSWER SECTION:
blocked.example.com.   60      IN      A       0.0.0.0

;; Query time: 0 msec
;; SERVER: 127.0.0.1#5533(127.0.0.1)
```

The matching blocklist rule was `blocked.example.com`. For this blocked `A`
query, MiniDNS returned `0.0.0.0` instead of performing normal recursive
resolution. This demonstrates how the local resolver can apply policy before
sending any upstream DNS traffic.

We used the following validation checks:

| Check | Command | Result |
| --- | --- | --- |
| Unit tests | `pytest` | Passed: `8 passed in 0.03s` |
| Syntax check | `python -m compileall minidns` | Passed with no compile errors |
| CLI lookup | `python -m minidns resolve example.com A --trace` | Passed: `NOERROR`, 2 `A` records, 3 upstream queries |
| UDP server | `dig @127.0.0.1 -p 5533 example.com A` | Passed: `NOERROR`, answer returned from `127.0.0.1#5533` |
| Blocklist | `dig @127.0.0.1 -p 5533 blocked.example.com A` | Passed: returned `0.0.0.0` with rule `blocked.example.com` |

The main implementation challenges were referral handling, cache correctness,
and valid DNS response construction. Referrals required MiniDNS to combine
authority-section NS records with additional-section glue records, and missing
glue required recursive resolution of nameserver hostnames. Caching required
respecting TTLs and avoiding unstable entries such as SERVFAIL. Server response
construction required returning packets that external clients such as `dig`
could parse correctly, including success responses, blocked responses, and
error responses.

## 4. AI and Tooling Reflection

We used AI tools, including Codex, as a programming assistant during the
project. AI helped with initial code structure, test ideas, debugging
hypotheses, and organizing the report. It was useful for ordinary Python
scaffolding and for suggesting edge cases we should think about.

However, the protocol-level behavior still required human checking. We had to
inspect traces, run real `dig` queries, verify cache hit/miss behavior, and
confirm that the resolver was actually following referrals instead of relying
on the system resolver. The most important learning came from reading the
trace output and connecting it back to DNS concepts such as root servers, TLD
servers, authoritative servers, glue records, CNAMEs, TTLs, and response codes.

## 5. Conclusion and Future Work

MiniDNS demonstrates the core behavior of a small recursive DNS resolver. It
can perform iterative resolution from root hints, follow referrals, use glue
records, resolve nameserver hostnames when needed, cache DNS results, and
answer local UDP DNS queries. It also includes a simple blocklist and enough
metrics to make the resolver's behavior visible during testing.

If we continued the project, the main improvements would be DNSSEC validation,
more complete TCP fallback, broader record-type support, concurrent or async
request handling, persistent cache/metrics storage, and better tools for
inspecting resolver state. Even without those extensions, MiniDNS gave us a
much more concrete understanding of what recursive DNS resolvers do internally.
