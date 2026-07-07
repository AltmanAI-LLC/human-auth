"""A hash-chained, append-only, tamper-evident audit log.

Every entry embeds the hash of the entry before it (like a minimal
blockchain). Modify or delete any past entry and every subsequent hash stops
matching — `verify()` will tell you exactly where the chain broke. This is
the log a human (or an auditor, or a court) should be able to trust without
trusting the server operator.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field


GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    index: int
    timestamp: float
    summary: str          # plain-language: "Blake authorized: wire $5,000 to Acme LLC"
    data: dict
    prev_hash: str
    entry_hash: str = field(default="")

    def compute_hash(self) -> str:
        payload = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "summary": self.summary,
                "data": self.data,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
            default=str,
        ).encode()
        return hashlib.sha256(payload).hexdigest()


class AuditChain:
    def __init__(self):
        self._entries: list[AuditEntry] = []

    def append(self, summary: str, data: dict) -> AuditEntry:
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        entry = AuditEntry(
            index=len(self._entries),
            timestamp=time.time(),
            summary=summary,
            data=data,
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        return entry

    def all(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify(self) -> tuple[bool, int | None]:
        """Returns (is_intact, index_of_first_break_or_None)."""
        prev_hash = GENESIS_HASH
        for entry in self._entries:
            if entry.prev_hash != prev_hash or entry.compute_hash() != entry.entry_hash:
                return False, entry.index
            prev_hash = entry.entry_hash
        return True, None

    def render(self) -> str:
        lines = []
        for e in self._entries:
            ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(e.timestamp))
            lines.append(f"[{ts}] #{e.index} {e.summary} (hash {e.entry_hash[:12]}...)")
        return "\n".join(lines)
