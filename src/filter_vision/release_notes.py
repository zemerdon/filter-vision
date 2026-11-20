"""Render bounded, plain-text GitHub stable notes as an in-app bullet list."""
from __future__ import annotations
import re


def changelog_items(body) -> list[str]:
    if not isinstance(body, str):
        return []
    body = body[:16_384]
    text = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith((chr(96) * 3, "#", "---")):
            continue
        item = re.sub(r"^(?:[-*+] |[0-9]+[.)] )", "", line)
        item = re.sub(r"^\[(?:x| )\]\s*", "", item, flags=re.IGNORECASE)
        item = re.sub(r"\[([^\]]+)\]\((?:https?://)[^)]*\)", r"\1", item)
        item = re.sub(r"[" + chr(96) + r"*_]+", "", item)
        if item and not line.startswith((">", "![", "http://", "https://")):
            text.append(item)
    if len(text) == 1 and len(text[0]) > 220:
        text = re.split(r"(?<=[.!?])\s+(?=[A-Z])", text[0])
    return [line[:360] for line in text if line.strip()][:12]
