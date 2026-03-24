#!/usr/bin/env python3
"""
huntertrace/analysis/profiler.py
==================================
SHIM — re-exports everything from actorProfiler.py (the canonical module).

This file exists for backwards compatibility only.
All development happens in actorProfiler.py.

Importing from profiler.py is equivalent to importing from actorProfiler.py.
"""

from actorProfiler import (
    MITREMapping,
    TemporalPattern,
    InfrastructurePattern,
    ContentPattern,
    ActorTTPProfile,
    ActorProfiler,
)

__all__ = [
    "MITREMapping",
    "TemporalPattern",
    "InfrastructurePattern",
    "ContentPattern",
    "ActorTTPProfile",
    "ActorProfiler",
]