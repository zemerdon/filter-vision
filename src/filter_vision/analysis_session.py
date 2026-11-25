"""Short-lived, bounded server-RAM evidence for per-browser manual evaluation.

No mailbox messages, raw MIME, full URLs or OAuth credentials are persisted.
Only parsed metadata, bounded header values and normalized link hosts are held.
"""
from __future__ import annotations

import threading
import time

TTL_SECONDS = 15 * 60
MAX_SESSIONS = 16


class AnalysisMemory:
    def __init__(self):
        self._lock = threading.RLock()
        self._sessions: dict[str, dict] = {}

    def _expire(self):
        now = time.monotonic()
        for key, value in list(self._sessions.items()):
            if now - value["at"] > TTL_SECONDS:
                del self._sessions[key]
    def read(self, key: str) -> dict:
        with self._lock:
            self._expire()
            state = self._sessions.get(key)
            if state is None:
                return {"catalog": [], "samples": [], "catalog_scanned": False,
                        "batch": None, "rules_batch": None}
            return {"catalog": list(state["catalog"]), "samples": list(state["samples"]),
                    "catalog_scanned": state["catalog_scanned"],
                     "batch": dict(state["batch"]) if state.get("batch") else None,
                    "rules_batch": dict(state["rules_batch"]) if state.get("rules_batch") else None}

    def write(self, key: str, *, catalog=None, samples=None, catalog_scanned=None):
        with self._lock:
            self._expire()
            existing = self._sessions.get(
                key, {"catalog": [], "samples": [], "catalog_scanned": False, "batch": None, "rules_batch": None})
            if key not in self._sessions and len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions, key=lambda name: self._sessions[name]["at"])
                del self._sessions[oldest]
            self._sessions[key] = {
                "at": time.monotonic(),
                "catalog": list(catalog) if catalog is not None else existing["catalog"],
                "samples": list(samples) if samples is not None else existing["samples"],
                "catalog_scanned": (bool(catalog_scanned) if catalog_scanned is not None
                                    else existing["catalog_scanned"]),
                "batch": existing.get("batch"),
                "rules_batch": existing.get("rules_batch"),
            }


    def set_batch(self, key: str, batch: dict) -> None:
        """Keep only opaque batch ID/fingerprints in a bounded browser session."""
        with self._lock:
            self._expire()
            if key not in self._sessions:
                return
            self._sessions[key]["batch"] = dict(batch)
            self._sessions[key]["at"] = time.monotonic()


    def set_rules_batch(self, key: str, batch: dict) -> None:
        """Track only IDs/digests and desired state for in-page verification."""
        with self._lock:
            self._expire()
            if key not in self._sessions:
                self.write(key)
            self._sessions[key]["rules_batch"] = dict(batch)
            self._sessions[key]["at"] = time.monotonic()
