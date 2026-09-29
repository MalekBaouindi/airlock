"""Provenance: tracking where untrusted values came from and where they go."""

from airlock.provenance.inspector import ProvenanceInspector, is_sensitive_request
from airlock.provenance.model import EgressMatch, TaintSource, TaintStore, is_internal_host

__all__ = [
    "EgressMatch",
    "ProvenanceInspector",
    "TaintSource",
    "TaintStore",
    "is_internal_host",
    "is_sensitive_request",
]
