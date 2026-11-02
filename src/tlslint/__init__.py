"""tlslint - a TLS / X.509 audit that carries its own evidence.

Zero third-party dependencies: the X.509 reader is DER parsed here, the
protocol and cipher probes are the standard library's ``ssl`` module, and the
HTTP checks are a hand written request over a socket.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
