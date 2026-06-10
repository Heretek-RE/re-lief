"""Keyword categorizers for re-lief.categorize_strings.

Categories are loaded from data/drm-indicators.yaml::string_categories
at module import time. Two seed categories (``anti_debug`` and
``hwid``) inherit their keyword lists from existing catalog
sections via a ``seed_from`` / ``seed_field`` pointer — when a
future agent adds a new HWID API to ``hwid_apis.high_signal``, the
categorizer picks it up on next MCP-server reload with zero Python
change.

The YAML catalog includes section-name regex patterns like
``"\\.vm"`` and ``"\\.xtls"`` that are *deliberately* invalid YAML
double-quoted escapes (they are regex literals, not YAML escapes).
The catalog is read by the LLM as plain text per
``data/drm-indicators.yaml:5-8``, so the broken escapes never
affected existing functionality. To make the catalog parseable
for machine consumption, this module pre-processes the file to
convert those double-quoted strings to single-quoted strings
(where backslashes are literal).

Categories are descriptive — they describe observable string
content, not specific commercial products. The catalog is
vendor-neutral per ``CLAUDE.md``.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as _yaml_exc:  # noqa: BLE001
    raise ImportError(
        "re-lief.categorize_strings requires PyYAML. "
        "The re-lief venv is missing the `pyyaml` dep. "
        "Re-run `./install.sh` (or `pip install pyyaml>=6.0` in the re-lief venv). "
        f"Underlying error: {_yaml_exc}"
    ) from _yaml_exc

# Locate the catalog relative to this file.
# servers/re-lief/src/re_lief/categorizers.py  →  ../../../../data/drm-indicators.yaml
_PLUGIN_ROOT = Path(__file__).resolve().parents[4]
_CATALOG_PATH = _PLUGIN_ROOT / "data" / "drm-indicators.yaml"


# Pre-process the catalog to make it safe_load-compatible. The catalog
# contains section-name regex literals like "\.vm", "\.xtls" inside
# YAML double-quoted strings, which are invalid YAML escapes (only
# specific ones like \n, \t, \\, \" are recognized). Convert those
# double-quoted strings to single-quoted strings where backslashes
# are literal. This is a no-op for the `string_categories:` block
# (which doesn't use the regex syntax) and a no-op for blocks that
# already use single-quoted strings.
#
# The pattern requires a backslash IMMEDIATELY after the opening
# quote (this is what distinguishes an unknown-escape string from
# a normal one). We capture the backslash + content + closing
# quote, then rewrite as a single-quoted string. Using a non-
# greedy `[^"]*?` and a required trailing `"` ensures we match the
# NEAREST closing quote, not a later one.
_DOUBLE_QUOTED_WITH_BACKSLASH = re.compile(r'"(\\[^"]*)"')


def _preprocess_yaml(text: str) -> str:
    """Neutralize unknown-escape double-quoted strings for safe_load."""

    def _to_single(m: re.Match[str]) -> str:
        # In single-quoted YAML strings, only '' is an escape (for a
        # literal apostrophe). Backslashes are literal. We have to
        # also double any embedded single quotes.
        body = m.group(1).replace("'", "''")
        return f"'{body}'"

    return _DOUBLE_QUOTED_WITH_BACKSLASH.sub(_to_single, text)


@lru_cache(maxsize=1)
def _load_catalog() -> dict[str, Any]:
    """Parse the catalog once. Subsequent calls return the cached dict."""
    return yaml.safe_load(_preprocess_yaml(_CATALOG_PATH.read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def load_categories() -> dict[str, list[str]]:
    """Return ``{category_name: [keyword, ...]}`` resolved from the YAML.

    Categories with a ``seed_from:`` pointer inherit their keyword
    list from another catalog list at this list (e.g. the
    ``anti_debug`` category gets the ``name`` field of every entry
    in ``anti_debug_indicators.checks``). Categories with an inline
    ``keywords:`` list use that list directly.

    Cycle 3 (2026-06-06): when the seeded source is
    ``anti_debug_indicators.checks``, the resolved keyword list
    is filtered to only entries whose ``confirmation:`` field is
    ``string_only`` or ``import_only`` — the
    ``requires_disasm`` checks (RDTSC, INT 2D, INT 3,
    exception-hooking decoys) are not string-table evidence and
    are dropped; the ``requires_xref`` check (scattered-bit
    register storage) is also dropped. The dropped checks are
    surfaced in ``load_confirmations()`` so the disasm/xref
    stages of the drm-fingerprint skill can still consult them.

    The result is cached via ``lru_cache``; restart the MCP server
    to pick up YAML edits.
    """
    cat = _load_catalog()
    out: dict[str, list[str]] = {}
    for entry in cat.get("string_categories", {}).get("categories", []):
        name = entry["name"]
        if "seed_from" in entry:
            node: Any = cat
            for part in entry["seed_from"].split("."):
                node = node[part]
            # Cycle 3 (C6): when the seeded source is the
            # anti_debug_indicators.checks block, drop the entries
            # whose confirmation is `requires_disasm` /
            # `requires_xref` from the string-categorizer keyword
            # list. Those checks are scored by the disasm / xref
            # stages of the drm-fingerprint skill, not here.
            if entry["seed_from"] == "anti_debug_indicators.checks":
                out[name] = [
                    str(e[entry["seed_field"]])
                    for e in node
                    if e.get("confirmation", "string_only")
                    in ("string_only", "import_only")
                ]
            else:
                out[name] = [str(e[entry["seed_field"]]) for e in node]
        else:
            out[name] = list(entry.get("keywords", []))
    return out


@lru_cache(maxsize=1)
def load_confirmations() -> dict[str, str]:
    """Return ``{check_name: confirmation}`` for the anti_debug catalog.

    Cycle 3 (C6, 2026-06-06): the disasm / xref stages of
    ``re-drm-fingerprint`` need to know which anti_debug checks
    are deferred from the string-categorizer so they can be
    scored in their respective stages. The mapping is read once
    at MCP-server load time; restart the server to pick up
    YAML edits.

    The returned dict covers all 10 entries in
    ``anti_debug_indicators.checks[]`` — the four values are
    ``string_only``, ``import_only``, ``requires_disasm``, and
    ``requires_xref`` (see the docstring at
    ``data/drm-indicators.yaml:347-363``).
    """
    cat = _load_catalog()
    out: dict[str, str] = {}
    for check in cat.get("anti_debug_indicators", {}).get("checks", []):
        out[check["name"]] = check.get("confirmation", "string_only")
    return out


@lru_cache(maxsize=1)
def load_excludes() -> dict[str, list[str]]:
    """Return ``{category_name: [exclude_keyword, ...]}`` resolved from the YAML.

    Cycle 2 fix: added support for ``exclude_keywords:`` per category
    entry. A match that hits an *include* keyword for a category
    but also hits an *exclude* keyword for the same category is
    filtered out. Used to eliminate the false-positive categorizer
    hits that surfaced during the 2026-06-06-r01 stress test
    (e.g. the ``*asian*`` / ``*albanian*`` / ``*width*`` Unicode
    UCD constants firing on ``telemetry_leak``, the OpenSSL
    static-link compiler invocations firing on ``hwid``, the
    ``__TBB_*`` / ``C:\\ci\\builds\\*`` paths firing on
    ``obfuscation``).
    """
    cat = _load_catalog()
    out: dict[str, list[str]] = {}
    for entry in cat.get("string_categories", {}).get("categories", []):
        excludes = entry.get("exclude_keywords")
        if excludes:
            out[entry["name"]] = list(excludes)
    return out


@lru_cache(maxsize=1)
def load_thresholds() -> dict[str, int]:
    """Return ``{category_name: min_evidence_int}`` resolved from the YAML.

    Cycle 3 (2026-06-06): each ``string_categories.categories[]``
    entry may carry a ``min_evidence:`` field. The categorizer
    surfaces ``meets_threshold: bool`` per category in its output,
    where ``meets_threshold = count >= min_evidence``. A missing
    ``min_evidence:`` defaults to 0 (no gate) and is omitted from
    the returned dict; ``categorize()`` then reports
    ``meets_threshold: True`` for any non-zero count.

    Two categories are gated today: ``anti_debug`` (min 2) and
    ``obfuscation`` (min 3). The ``anti_debug`` gate suppresses
    one-off matches (a binary that only imports ``IsDebuggerPresent``
    for legitimate reasons is not anti-tamper). The
    ``obfuscation`` gate suppresses single-keyword hits (e.g. a
    binary that mentions ``xor`` in a string but has no actual
    VM-pack shape).
    """
    cat = _load_catalog()
    out: dict[str, int] = {}
    for entry in cat.get("string_categories", {}).get("categories", []):
        threshold = entry.get("min_evidence")
        if threshold is None:
            continue
        try:
            value = int(threshold)
        except (TypeError, ValueError):
            continue
        if value > 0:
            out[entry["name"]] = value
    return out


def categorize(
    matches: list[dict[str, Any]],
    categories: list[str] | None = None,
    max_per_category: int = 200,
    samples_per_category: int = 5,
) -> dict[str, dict[str, Any]]:
    """Bucket *matches* into the configured categories.

    Each ``match`` is a dict with at least ``"string"`` and
    ``"section"`` keys. A match can be counted in multiple
    categories (substring match is permissive). Each category's
    ``count`` is the number of *unique* (string, section) pairs;
    ``samples`` is a list of up to ``samples_per_category``
    example matches; ``meets_threshold`` is a boolean that is
    ``True`` iff the bucket's ``count`` is at or above the
    category's ``min_evidence:`` threshold from the YAML
    (default 0, which is always satisfied by any count >= 0).

    Parameters
    ----------
    matches
        List of ``{"string": ..., "offset": ..., "section": ...}`` dicts.
    categories
        If given, restrict to this subset of category names.
    max_per_category
        If a category has more than this many unique matches, the
        count is still reported honestly but ``samples`` is capped.
    samples_per_category
        Cap on the number of sample matches returned per category.

    Cycle 2 fix: a match is filtered out of a category if it hits
    any of the category's ``exclude_keywords``. The exclude check
    runs *after* the include check, so the user sees honest counts
    on real anti-tamper / fingerprint / telemetry signals while
    the 700+ false-positive hits that surfaced in the 2026-06-06-r01
    stress test are suppressed.

    Cycle 3 fix: every category's dict now carries
    ``meets_threshold: bool`` (additive — does not break callers
    that only read ``count`` / ``samples``). The boolean lets the
    ``re-drm-fingerprint`` Stage 5 synthesis gate the score on
    the bucket having at least ``min_evidence`` distinct catalog
    primitives, not just one-off matches.
    """
    cats = load_categories()
    excludes = load_excludes()
    thresholds = load_thresholds()
    if categories is not None:
        cats = {k: v for k, v in cats.items() if k in categories}
        excludes = {k: v for k, v in excludes.items() if k in categories}
        thresholds = {k: v for k, v in thresholds.items() if k in categories}
    out: dict[str, dict[str, Any]] = {
        name: {"count": 0, "samples": [], "meets_threshold": False} for name in cats
    }
    seen_in_cat: dict[str, set[tuple[str, str]]] = {
        name: set() for name in cats
    }
    for m in matches:
        s = m.get("string", "")
        if not s:
            continue
        s_lower = s.lower()
        section = m.get("section", "")
        for name, keywords in cats.items():
            matched_include = False
            for kw in keywords:
                if kw and kw.lower() in s_lower:
                    matched_include = True
                    break
            if not matched_include:
                continue
            # Cycle 2 fix: honor the exclude list. If the same string
            # also hits any exclude keyword for this category, the
            # match is filtered out. This eliminates the Unicode
            # UCD-constant and OpenSSL-static-link false positives.
            cat_excludes = excludes.get(name, [])
            if any(ex and ex.lower() in s_lower for ex in cat_excludes):
                continue
            key = (s, section)
            if key in seen_in_cat[name]:
                continue
            seen_in_cat[name].add(key)
            out[name]["count"] += 1
            if len(out[name]["samples"]) < samples_per_category:
                out[name]["samples"].append(
                    {"string": s, "section": section}
                )
    # Cycle 3 fix: apply the per-category min_evidence threshold.
    # A `min_evidence: 0` value (the default for categories without
    # the field) means "no gate" — the effective threshold is 1
    # (any non-zero count meets it). An empty bucket is always
    # `meets_threshold: False` because there is nothing to confirm.
    for name, info in out.items():
        threshold = max(thresholds.get(name, 0), 1)
        info["meets_threshold"] = info["count"] >= threshold
    return out
