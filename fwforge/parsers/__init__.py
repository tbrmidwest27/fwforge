"""Vendor parser registry and source auto-detection."""
from __future__ import annotations

import re

from . import cisco_asa, paloalto  # noqa: F401

# cross-vendor parsers by vendor id
CROSS_PARSERS = {
    "cisco-asa": cisco_asa.parse,
    "paloalto": paloalto.parse,
}


def detect_fortios(text: str) -> float:
    score = 0.0
    if re.search(r"^#config-version=", text, re.M):
        score += 0.8
    if re.search(r"^config system global", text, re.M):
        score += 0.3
    if re.search(r"^\s*set vdom ", text, re.M):
        score += 0.1
    return min(score, 1.0)


def detect_vendor(text: str) -> tuple[str, float]:
    """Returns (vendor, confidence).
    vendor in {cisco-asa, paloalto, fortios, unknown}."""
    scores = {
        "cisco-asa": cisco_asa.detect(text),
        "paloalto": paloalto.detect(text),
        "fortios": detect_fortios(text),
    }
    vendor = max(scores, key=lambda k: scores[k])
    conf = scores[vendor]
    if conf < 0.3:
        return "unknown", conf
    return vendor, conf
