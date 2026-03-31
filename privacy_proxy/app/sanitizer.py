"""
Privacy sanitization engine.

Replaces PII with stable, deterministic tokens on the way OUT to Claude,
and restores original values on the way IN from Claude back to the agent.

Token format: [CATEGORY_NNNN]  e.g. [NAME_4821], [IP_3047]
Mappings are persisted to /data/privacy_mapping.json so they survive restarts.
"""

import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MAPPING_FILE = "/data/privacy_mapping.json"

# ── PII patterns ──────────────────────────────────────────────────────────────
# Ordered: more-specific patterns first to avoid partial matches.
_PATTERNS: List[tuple] = [
    # MAC address (before IP so "aa:bb:cc:dd:ee:ff" is not partially matched as IP)
    ("MAC", re.compile(
        r"\b[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}\b"
    )),
    # IPv4
    ("IP", re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )),
    # Email
    ("EMAIL", re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    )),
    # Phone (US-style; disable via config if too aggressive)
    ("PHONE", re.compile(
        r"(?<!\d)(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]\d{4}(?!\d)"
    )),
    # GPS lat/lon values in JSON  e.g. "latitude": 51.5074
    # Group 1 = key prefix (preserved), Group 2 = the numeric value (redacted)
    ("GPS", re.compile(
        r'("(?:latitude|longitude|lat|lon|lng)":\s*)(-?\d{1,3}\.\d{4,})',
        re.IGNORECASE,
    )),
]


class PrivacySanitizer:
    """Thread-safe sanitization engine with persistent token mapping."""

    def __init__(
        self,
        personal_names: Optional[List[str]] = None,
        custom_words: Optional[List[str]] = None,
        entity_domains: Optional[List[str]] = None,
        redact_ips: bool = True,
        redact_macs: bool = True,
        redact_emails: bool = True,
        redact_phones: bool = False,
        redact_gps: bool = True,
    ):
        self._enabled: Dict[str, bool] = {
            "MAC": redact_macs,
            "IP": redact_ips,
            "EMAIL": redact_emails,
            "PHONE": redact_phones,
            "GPS": redact_gps,
        }
        self._entity_domains = set(entity_domains or ["person"])

        # forward: original → token,  reverse: token → original
        self._fwd: Dict[str, str] = {}
        self._rev: Dict[str, str] = {}
        self._load_mapping()

        # Words to redact (user-defined + entity names added later)
        # Kept sorted longest-first so "John Smith" replaces before "John"
        raw_words = list(filter(None, (personal_names or []) + (custom_words or [])))
        self._words: List[str] = sorted(set(raw_words), key=len, reverse=True)

    # ── Public API ─────────────────────────────────────────────────────────────

    def add_entity_names(self, entities: List[Dict]) -> None:
        """
        Call once at startup with the entity list from the agent.
        Extracts names from person.* (and other configured domains) so their
        friendly names and ID slugs are automatically redacted.
        """
        new_words: List[str] = []
        for ent in entities:
            entity_id: str = ent.get("entity_id", "")
            domain = entity_id.split(".")[0] if "." in entity_id else ""
            if domain not in self._entity_domains:
                continue
            # e.g. "person.john_smith" → "john smith", "john_smith"
            slug = entity_id.split(".", 1)[1] if "." in entity_id else entity_id
            new_words.append(slug.replace("_", " "))
            new_words.append(slug)
            # Friendly name
            attrs = ent.get("attributes", {})
            friendly = attrs.get("friendly_name", "")
            if friendly:
                new_words.append(friendly)

        added = [w for w in new_words if w and w not in self._words]
        if added:
            self._words = sorted(set(self._words + added), key=len, reverse=True)
            logger.info("Privacy proxy: added %d entity-derived words to redaction list", len(added))

    def sanitize(self, value: Any) -> Any:
        """Redact PII in outbound data (agent → Claude)."""
        return self._transform(value, direction="sanitize")

    def restore(self, value: Any) -> Any:
        """Restore tokens in inbound data (Claude → agent)."""
        return self._transform(value, direction="restore")

    def get_mapping_summary(self) -> Dict:
        """Return a safe summary of current mappings (tokens only, no originals)."""
        return {
            "token_count": len(self._fwd),
            "categories": sorted({t.split("_")[0].lstrip("[") for t in self._rev}),
            "tokens": list(self._rev.keys()),
        }

    # ── Internals ──────────────────────────────────────────────────────────────

    def _transform(self, value: Any, direction: str) -> Any:
        if isinstance(value, str):
            return self._sanitize_str(value) if direction == "sanitize" else self._restore_str(value)
        if isinstance(value, dict):
            return {k: self._transform(v, direction) for k, v in value.items()}
        if isinstance(value, list):
            return [self._transform(item, direction) for item in value]
        return value

    def _sanitize_str(self, text: str) -> str:
        # 1. User-defined words/names (longest first for correct greedy replacement)
        for word in self._words:
            if word and word.lower() in text.lower():
                token = self._get_token(word, "NAME")
                text = re.sub(re.escape(word), token, text, flags=re.IGNORECASE)

        # 2. Pattern-based PII
        for category, pattern in _PATTERNS:
            if not self._enabled.get(category, True):
                continue

            if category == "GPS":
                # GPS pattern has 2 groups: (key_prefix, numeric_value)
                # Preserve the key, only replace the value
                def _replace_gps(m: re.Match, cat: str = category) -> str:
                    return m.group(1) + self._get_token(m.group(2), cat)
                text = pattern.sub(_replace_gps, text)
            else:
                def _replace(m: re.Match, cat: str = category) -> str:
                    return self._get_token(m.group(0), cat)
                text = pattern.sub(_replace, text)

        return text

    def _restore_str(self, text: str) -> str:
        if not self._rev:
            return text
        # Longest tokens first to avoid partial substitution
        for token in sorted(self._rev, key=len, reverse=True):
            if token in text:
                text = text.replace(token, self._rev[token])
        return text

    def _get_token(self, original: str, category: str) -> str:
        if original in self._fwd:
            return self._fwd[original]

        # Deterministic 4-digit suffix based on hash of category + original
        h = int(hashlib.sha256(f"{category}:{original}".encode()).hexdigest()[:8], 16)
        n = (h % 9000) + 1000  # 1000–9999
        token = f"[{category}_{n}]"

        # Collision resolution
        while token in self._rev and self._rev[token] != original:
            n = (n % 9000) + 1000 + 1
            token = f"[{category}_{n}]"

        self._fwd[original] = token
        self._rev[token] = original
        self._save_mapping()
        return token

    def _load_mapping(self) -> None:
        if not os.path.exists(MAPPING_FILE):
            return
        try:
            with open(MAPPING_FILE) as f:
                data = json.load(f)
            self._fwd = data.get("forward", {})
            self._rev = data.get("reverse", {})
            logger.info("Privacy proxy: loaded %d existing token mappings", len(self._fwd))
        except Exception as exc:
            logger.warning("Privacy proxy: could not load mapping file: %s", exc)

    def _save_mapping(self) -> None:
        try:
            os.makedirs(os.path.dirname(MAPPING_FILE), exist_ok=True)
            with open(MAPPING_FILE, "w") as f:
                json.dump({"forward": self._fwd, "reverse": self._rev}, f, indent=2)
        except Exception as exc:
            logger.warning("Privacy proxy: could not save mapping file: %s", exc)
