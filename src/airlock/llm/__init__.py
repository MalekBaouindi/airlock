"""Client for the locally-hosted model the semantic layer judges with."""

from airlock.llm.client import (
    DEFAULT_ENDPOINT,
    JudgeStats,
    JudgeUnavailable,
    LocalModel,
)

__all__ = ["DEFAULT_ENDPOINT", "JudgeStats", "JudgeUnavailable", "LocalModel"]
