"""Custom error types for MiniDNS."""


class MiniDNSError(Exception):
    """Base class for all MiniDNS exceptions."""


class ResolutionError(MiniDNSError):
    """Generic iterative resolution failure."""


class MaxDepthExceededError(ResolutionError):
    """Raised when the resolver exceeds its referral depth budget."""


class NoGlueError(ResolutionError):
    """Raised when a referral cannot be followed because no server IPs are available."""


class UpstreamTimeoutError(ResolutionError):
    """Raised when all candidate upstream servers time out."""


class MalformedUpstreamResponseError(ResolutionError):
    """Raised when an upstream nameserver sends an invalid or unusable response."""
