"""MiniDNS package exports."""

from .blocklist import DomainBlocklist
from .cache import TTLCache
from .metrics import Metrics
from .resolver import IterativeResolver, ResolutionResult
from .server import UDPDNSServer

__all__ = [
    "DomainBlocklist",
    "IterativeResolver",
    "Metrics",
    "ResolutionResult",
    "TTLCache",
    "UDPDNSServer",
]

__version__ = "0.1.0"
