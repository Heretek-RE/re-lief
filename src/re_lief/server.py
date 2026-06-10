"""MCP server entry point for re-lief.

Exposes the LIEF-based binary analysis tools to Claude Code via the
Model Context Protocol stdio transport.
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from re_lief import disasm, parsers

logger = logging.getLogger("re_lief")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-lief")


# ── Health ──────────────────────────────────────────────────────────────


@mcp.tool()
def check_lief() -> dict:
    """Return LIEF version, supported formats, and a green/yellow status.

    Returns a JSON-serializable dict suitable for `scripts/check_deps.py`.
    """
    import lief

    supported = [f.name for f in lief.Binary.FORMATS]
    return {
        "server": "re-lief",
        "lief_version": lief.__version__,
        "supported_formats": supported,
        "status": "OK",
    }


# ── Top-level parse ────────────────────────────────────────────────────


@mcp.tool()
def parse_binary(path: str) -> dict:
    """Auto-detect the format of *path* and return a normalized header dict.

    Returns hashes, format name, architecture, entrypoint, and format-specific
    fields (imphash for PE, PIE/NX/RELRO for ELF, code signature for MachO, etc.).
    """
    return parsers.parse_binary(path)


@mcp.tool()
def get_sections(path: str) -> list[dict]:
    """Return section list with permissions, virtual vs raw size, and entropy.

    Works for PE (.text/.rdata/.data/.rsrc), ELF (.text/.rodata/.data), and
    MachO (__TEXT/__DATA/__LINKEDIT).
    """
    return parsers.get_sections(path)


@mcp.tool()
def get_imports_exports(
    path: str,
    max_imports: int = 0,
    max_exports: int = 0,
    library_filter: str = "",
) -> dict:
    """Return symbol-level import and export tables for *path*.

    Args:
        path: PE / ELF / MachO to analyze.
        max_imports: cap the returned imports list to this many
            entries. 0 = no cap (the v2.9.0 default).
        max_exports: same cap for the exports list.
        library_filter: optional substring filter against the
            library name (pipe-separated for OR). e.g.
            ``"kernel32|user32"`` to keep only those two.

    Added in v2.9.1+ to fix Gap 27 (the response-size ceiling
    on the 4 large VM-protected targets). The response includes
    a ``truncated`` flag + ``original_count`` / ``returned_count``
    when the caps fire. The v2.9.0 callers (no kwargs) are
    unaffected.
    """
    return parsers.get_imports_exports(
        path,
        max_imports=max_imports,
        max_exports=max_exports,
        library_filter=library_filter,
    )


@mcp.tool()
def get_imphash(path: str) -> dict:
    """Return the PE import hash (imphash) for *path*.

    Imphash is the MD5 of the normalized import table — used for
    malware variant identification. Returns an empty string for
    non-PE formats.
    """
    return {"path": path, "imphash": parsers.get_imphash(path)}


@mcp.tool()
def get_overlay(path: str) -> dict:
    """Return appended data after the last section (PE overlay)."""
    return parsers.get_overlay(path)


@mcp.tool()
def get_authenticode(path: str) -> dict:
    """Return Authenticode signature details for PE binaries."""
    return parsers.get_authenticode(path)


@mcp.tool()
def get_debug_directory(path: str) -> dict:
    """Return the PE debug directory entries (incl. IMAGE_DEBUG_TYPE_POGO).

    The POGO entry (type 10) is the third-party-ATD
    layer's trigger-arming metadata (per
    ANTI-TAMPER-TAXONOMY.md Pattern A-DW). Surfaced
    with ``kind: "POGO"`` in the response dict. The
    CODEVIEW entry (type 2) is the PDB pointer; the
    canonical vendor-tag signal lives
    in the RSDS CodeView stream (resolved by re-pdb
    `parse_pdb` rather than this read-path).

    The skill-side fallback ``references/pogo_debug_check.py``
    in ``skills/re-drm-fingerprint/`` mirrors this same
    shape for hosts that don't have the new MCP tool
    installed.

    See ``See the RE-AI output directory
    per-target/p3r/stage5-pogo-debug-check.md`` for the
    canonical Pattern A-DW detection pattern.
    """
    return parsers.get_debug_directory(path)


# ── Android ────────────────────────────────────────────────────────────


@mcp.tool()
def list_dex_classes(path: str) -> list[dict]:
    """List all classes in a Dalvik DEX file.

    Returns FQN, access flags, and method/field counts.
    """
    return parsers.list_dex_classes(path)


@mcp.tool()
def list_dex_methods(path: str, class_fqn: str) -> list[dict]:
    """List all methods of a DEX class identified by FQN (e.g. ``Lcom/foo/Bar;``)."""
    return parsers.list_dex_methods(path, class_fqn)


@mcp.tool()
def list_oat_art(path: str) -> list[dict]:
    """List all methods in an OAT/ART Android runtime file."""
    return parsers.list_oat_art(path)


# ── Disassembly / strings ──────────────────────────────────────────────


@mcp.tool()
def disasm_capstone(
    path: str,
    section_name: str,
    offset: int = 0,
    size: int = 256,
    max_insns: int = 500,
) -> dict:
    """Disassemble *size* bytes of section *section_name* starting at *offset*.

    Returns a JSON list of instructions (address, mnemonic, operands, bytes).
    Truncates to *max_insns* (default 500) — call again with a different
    offset to see more.
    """
    return disasm.disasm_from_path(
        path, section_name, offset=offset, size=size, max_insns=max_insns
    )


@mcp.tool()
def extract_strings(path: str, min_length: int = 5) -> dict:
    """Extract printable ASCII and UTF-16LE strings from *path*.

    Returns ``{"ascii": [...], "utf16le": [...], "totals": {...}, "truncated": bool}``.
    Each string has ``string``, ``offset``, and ``section`` fields.

    .. note::
       This is the v2.4 shape, kept stable for backward compatibility.
       New code should call ``categorize_strings`` (below), which
       returns the same ``ascii`` / ``utf16le`` arrays *plus* a
       keyword-bucketed ``by_category`` block.
    """
    return parsers.extract_strings_for_binary(path, min_length=min_length)


@mcp.tool()
def categorize_strings(
    path: str,
    min_length: int = 5,
    categories: list[str] | None = None,
    include_misc: bool = True,
    max_per_category: int = 200,
    samples_per_category: int = 5,
    skip_sections: list[str] | None = None,
) -> dict:
    """Extract strings from *path* and bucket them into semantic categories.

    The categorization vocabulary is loaded from
    ``data/drm-indicators.yaml::string_categories`` at MCP-server
    load time.  Two categories (``anti_debug``, ``hwid``) inherit
    their keyword lists from the existing catalog sections via a
    ``seed_from`` pointer; the rest have inline keyword lists.
    When a future agent adds a new HWID API to
    ``hwid_apis.high_signal``, the ``hwid`` category picks it up on
    next MCP-server reload with zero Python change.

    The return shape is a strict superset of ``extract_strings``:

    ::

        {
          "path": "...",
          "min_length": 5,
          "totals":   {"ascii_extracted": N, "utf16le_extracted": N,
                       "deduplicated": N, "categorized": N},
          "truncated": {"input": bool, "per_category": bool,
                        "per_encoding": bool},
          "by_category": {
            "anti_debug": {"count": N, "samples": [{"string":..., "section":...}, ...]},
            "hwid":       {"count": N, "samples": [...]},
            "crypto":     {"count": N, "samples": [...]},
            "network":    {"count": N, "samples": [...]},
            "registry":   {"count": N, "samples": [...]},
            "process":    {"count": N, "samples": [...]},
            "file":       {"count": N, "samples": [...]},
            "fingerprint": {"count": N, "samples": [...]},
            "activation":  {"count": N, "samples": [...]},
            "obfuscation": {"count": N, "samples": [...]},
            "misc":        {"count": N, "samples": [...]}
          },
          "ascii_capped": [...],          # backward-compat with extract_strings
          "utf16le_capped": [...],
          "uncategorized_sample": [...]   # 50 misc strings (helps spot missing categories)
        }

    On large binaries (e.g. a 500+ MB Unity IL2CPP ``GameAssembly.dll``
    wrapped by an encrypted-VM bytecode interpreter), pass
    ``skip_sections=[".idata", ".xtls", ".xpdata", ".udata", ".xdata",
    ".didata", ".ecode", ".00cfg"]`` to skip the encrypted-VM
    bytecode regions.  Those sections contain no readable strings;
    the categorization result is the same and the memory footprint
    drops dramatically.

    Categories are descriptive — they describe observable string
    content, not specific commercial products.
    """
    return parsers.categorize_strings(
        path,
        min_length=min_length,
        categories=categories,
        include_misc=include_misc,
        max_per_category=max_per_category,
        samples_per_category=samples_per_category,
        skip_sections=skip_sections,
    )


@mcp.tool()
def normalize_for_diff(path: str) -> dict:
    """Return a structural snapshot suitable for diffing two binaries.

    Strips variable-length fields (hashes, timestamps) and keeps
    the parts that should match between two builds of the same source.
    """
    return parsers.normalize_for_diff(path)


# ── Anti-analysis + native protection (v2.7.0) ───────────────────────


@mcp.tool()
def scan_anti_analysis_primitives(path: str, max_per_category: int = 100) -> dict:
    """Scan a binary for anti-analysis primitives (defender side).

    Walks the string table + the IAT + (best-effort) the
    section table and matches the content against the
    vendored ``data/anti-analysis-catalog.json``. Returns
    category-only labels (``anti_debug``, ``anti_vm``,
    ``anti_emulator``, ``anti_sandbox``, ``process_introspection``,
    ``memory_integrity``, ``code_integrity``). Never names
    a specific commercial product.

    The byte-sequence evidence (RDTSC = 0F 31, INT 2D = CD 2D,
    INT 3 = CC, CPUID = 0F A2) is *not* checked here — that
    requires a disasm pass via ``re-rizin.search_bytes``.
    ``re-anti-analysis`` is the cross-tool orchestrator that
    does both the string-table pass and the disasm pass.

    Args:
        path: file to scan
        max_per_category: per-category cap (default 100)

    Returns::

        {
          "path": "...",
          "matches": [{"primitive": "...", "category": "...",
                       "evidence_kind": "...", "offset": N,
                       "section": "..."}, ...],
          "by_category": {"anti_debug": 4, "anti_vm": 2, ...},
          "truncated": bool
        }
    """
    try:
        from re_lief import protection_catalog
    except ImportError as exc:
        return {
            "path": path,
            "matches": [],
            "by_category": {},
            "error": f"re_lief.protection_catalog module not available: {exc}",
        }
    return protection_catalog.scan_anti_analysis_primitives(
        path, max_per_category=max_per_category,
    )


@mcp.tool()
def classify_native_protection(path: str) -> dict:
    """Classify a native binary's protection class (category-only).

    Combines ``get_sections`` + ``get_imports_exports`` +
    the vendored ``native_packer_signatures`` regex catalog
    + entropy heuristics to label a binary's likely
    protection class. Returns one of:

    - ``"plain-pe"`` — no protection observed.
    - ``"packer-stub-wrapped"`` — UPX / ASPack / MPRESS / Petite / kkrunchy
      style (single non-standard section name).
    - ``"vm-bytecoded-pe"`` — single ``.vmp0`` / ``.vmp1`` style
      section set.
    - ``"encrypted-vm-bytecode-interpreter"`` — the proprietary-engine
      section family (``.arch`` / ``.xcode`` / ``.xtext`` / ``.sbss`` /
      ``.link`` / ``.xtls`` / ``.xpdata``).
    - ``"il2cpp-runtime"`` — large ``.idata`` + tiny ``.text`` +
      ``GameAssembly.dll`` sibling.
    - ``"anti-debug-wrapped"`` — bare anti-debug surface but no
      packer.
    - ``"unpacked-debug-pe"`` — debug build (PDB section + lots of
      stdio / conio / assert symbols).

    Args:
        path: file to classify

    Returns::

        {
          "path": "...",
          "protection_class": "...",
          "evidence": [{"category": "...", "indicator": "...",
                        "section": "..."}, ...]
        }
    """
    try:
        from re_lief import protection_catalog
    except ImportError as exc:
        return {
            "path": path,
            "protection_class": "unknown",
            "evidence": [],
            "error": f"re_lief.protection_catalog module not available: {exc}",
        }
    return protection_catalog.classify_native_protection(path)


# ── Entrypoint ─────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server over stdio (the standard Claude Code transport)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
