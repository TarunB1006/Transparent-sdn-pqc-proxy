"""Domain-specific exceptions."""


class PQCSdnError(Exception):
    """Base error for the platform."""


class CryptoError(PQCSdnError):
    """Cryptographic operation failed."""


class SessionError(PQCSdnError):
    """Secure session operation failed."""


class HandshakeError(PQCSdnError):
    """TLS handshake failed."""


class PolicyError(PQCSdnError):
    """Policy evaluation failed."""


class ProxyError(PQCSdnError):
    """Proxy operation failed."""


class ConfigurationError(PQCSdnError):
    """Invalid or missing configuration."""


class FrameError(ProxyError):
    """Malformed or unauthenticated tunnel frame; the connection must be closed."""
