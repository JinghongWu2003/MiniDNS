import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from minidns.cache import TTLCache
from minidns.metrics import Metrics
from minidns.resolver import IterativeResolver
from minidns.server import UDPDNSServer


def build_server() -> UDPDNSServer:
    metrics = Metrics()
    resolver = IterativeResolver(cache=TTLCache(), metrics=metrics)
    return UDPDNSServer("127.0.0.1", 5353, resolver=resolver, metrics=metrics)


def test_build_blocked_response_for_a_query():
    server = build_server()
    query = dns.message.make_query("blocked.example.com", "A")

    response = server.build_blocked_response(query)
    reparsed = dns.message.from_wire(response.to_wire())

    assert reparsed.rcode() == dns.rcode.NOERROR
    assert reparsed.flags & dns.flags.RA
    assert len(reparsed.answer) == 1
    rrset = reparsed.answer[0]
    assert rrset.rdtype == dns.rdatatype.A
    assert rrset[0].address == "0.0.0.0"


def test_build_error_response_sets_requested_rcode():
    server = build_server()
    query = dns.message.make_query("example.com", "A")

    response = server.build_error_response(query, dns.rcode.SERVFAIL)

    assert response.rcode() == dns.rcode.SERVFAIL
    assert response.flags & dns.flags.RA
