"""Interposition layer: transports, session state, and JSON-RPC handling."""

from airlock.gateway.jsonrpc import ProtocolError, error_response
from airlock.gateway.session import SessionContext
from airlock.gateway.stdio_proxy import ProxyStats, StdioProxy, UpstreamSpec

__all__ = [
    "ProtocolError",
    "ProxyStats",
    "SessionContext",
    "StdioProxy",
    "UpstreamSpec",
    "error_response",
]
