"""Response cache -- never pay twice for the same model call.

A scan re-sends the same prompt constantly: the verification engine replays a
probe N times, the judge re-classifies the same response, and a re-run of the
same case repeats every call.  Against a metered API that is pure cost, and
against a free tier it is the fastest way to get rate-limited.

This module is a small, dependency-free, content-addressed cache:

* the key is a SHA-256 of ``(model, temperature, max_tokens, json_mode,
  messages)``, so two calls that would produce the same completion share an
  entry and two that would not never collide;
* entries are stored in memory and, optionally, on disk, so a re-run of the same
  case is free;
* a TTL bounds staleness, and a size cap bounds growth;
* it is **off by default** in the client, so nothing changes unless a caller
  opts in -- a cache that silently changes behaviour is worse than no cache.

The cache never stores a failed call, so a transient error is retried rather
than being frozen into the run.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Default lifetime of a cached completion, in seconds (1 hour).
DEFAULT_TTL_S = 3600.0

#: Default maximum number of entries held in memory.
DEFAULT_MAX_ENTRIES = 2048


def cache_key(
    *,
    model: str,
    messages: List[Dict[str, str]],
    temperature: float,
    max_tokens: int,
    json_mode: bool,
) -> str:
    """Content-addressed key for one completion request."""
    payload = {
        "model": model,
        "messages": messages,
        "temperature": round(float(temperature), 6),
        "max_tokens": int(max_tokens),
        "json_mode": bool(json_mode),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class CacheEntry:
    """One cached completion."""

    text: str
    model: str
    stored_at: float = field(default_factory=time.time)
    hits: int = 0

    def expired(self, ttl: float) -> bool:
        return ttl > 0 and (time.time() - self.stored_at) > ttl


@dataclass
class CacheStats:
    """Hit/miss counters, so the saving is measurable rather than claimed."""

    hits: int = 0
    misses: int = 0
    stores: int = 0
    evictions: int = 0

    @property
    def total(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        return self.hits / self.total if self.total else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "stores": self.stores,
            "evictions": self.evictions,
            "total": self.total,
            "hit_rate": round(self.hit_rate, 3),
        }


class ResponseCache:
    """A bounded, thread-safe, optionally persistent completion cache."""

    def __init__(
        self,
        *,
        ttl_s: float = DEFAULT_TTL_S,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        path: Optional[str] = None,
    ) -> None:
        self.ttl_s = ttl_s
        self.max_entries = max(1, int(max_entries))
        self.path = Path(path) if path else None
        self._entries: Dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        self.stats = CacheStats()
        if self.path is not None:
            self._load()

    # -- public API -------------------------------------------------------- #

    def get(self, key: str) -> Optional[CacheEntry]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.stats.misses += 1
                return None
            if entry.expired(self.ttl_s):
                del self._entries[key]
                self.stats.misses += 1
                return None
            entry.hits += 1
            self.stats.hits += 1
            return entry

    def put(self, key: str, text: str, model: str) -> None:
        if not (text or "").strip():
            # Never cache an empty completion: it is a failure, not an answer.
            return
        with self._lock:
            self._entries[key] = CacheEntry(text=text, model=model)
            self.stats.stores += 1
            self._evict_locked()
        if self.path is not None:
            self._save()

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
        if self.path is not None:
            self._save()

    def __len__(self) -> int:
        return len(self._entries)

    # -- internals --------------------------------------------------------- #

    def _evict_locked(self) -> None:
        """Drop expired entries, then the oldest, until under the cap."""
        if self.ttl_s > 0:
            for key in [k for k, e in self._entries.items() if e.expired(self.ttl_s)]:
                del self._entries[key]
                self.stats.evictions += 1
        while len(self._entries) > self.max_entries:
            oldest = min(self._entries.items(), key=lambda kv: kv[1].stored_at)[0]
            del self._entries[oldest]
            self.stats.evictions += 1

    def _load(self) -> None:
        assert self.path is not None
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        for key, raw in (data.get("entries") or {}).items():
            if not isinstance(raw, dict):
                continue
            entry = CacheEntry(
                text=str(raw.get("text", "")),
                model=str(raw.get("model", "")),
                stored_at=float(raw.get("stored_at", 0.0)),
            )
            if not entry.expired(self.ttl_s):
                self._entries[key] = entry

    def _save(self) -> None:
        assert self.path is not None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 1,
                "entries": {
                    k: {"text": e.text, "model": e.model, "stored_at": e.stored_at}
                    for k, e in self._entries.items()
                },
            }
            self.path.write_text(
                json.dumps(payload, sort_keys=True), encoding="utf-8"
            )
        except OSError:
            # A cache that cannot be written is still a working in-memory cache.
            pass


#: Process-wide default cache, used when a caller asks for caching but does not
#: supply its own.  Kept module-level so a CLI run and a UI run share it.
DEFAULT_CACHE: Optional[ResponseCache] = None


def default_cache() -> ResponseCache:
    """Return (and lazily create) the process-wide cache."""
    global DEFAULT_CACHE
    if DEFAULT_CACHE is None:
        DEFAULT_CACHE = ResponseCache()
    return DEFAULT_CACHE
