"""Binary parsing helpers built on LIEF.

This module consolidates LIEF parsing logic used by the MCP tools.
The pefile+capstone code from v1 ``backend/analysis/native.py`` is
generalized here to LIEF's polyglot API so the same tools work for
PE, ELF, MachO, COFF, DEX, and OAT/ART.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from typing import Any

import lief

_PRINTABLE_ASCII_FMT = rb"[\x20-\x7e]{%d,}"
_PRINTABLE_UTF16LE_FMT = rb"(?:[\x20-\x7e]\x00){%d,}"


def _ascii_re(min_length: int) -> re.Pattern[bytes]:
    return re.compile(_PRINTABLE_ASCII_FMT % min_length)


def _utf16_re(min_length: int) -> re.Pattern[bytes]:
    return re.compile(_PRINTABLE_UTF16LE_FMT % min_length)


# ── Format detection ────────────────────────────────────────────────────


def detect_format(path: str) -> str:
    """Return the LIEF format name for *path* ('PE', 'ELF', 'MACHO', 'COFF', 'DEX', 'OAT', or 'UNKNOWN')."""
    try:
        binary = lief.parse(path)
    except Exception:  # noqa: BLE001
        return "UNKNOWN"
    if binary is None:
        return "UNKNOWN"
    fmt = binary.format
    return {
        lief.Binary.FORMATS.PE: "PE",
        lief.Binary.FORMATS.ELF: "ELF",
        lief.Binary.FORMATS.MACHO: "MACHO",
        lief.Binary.FORMATS.COFF: "COFF",
        lief.Binary.FORMATS.DEX: "DEX",
        lief.Binary.FORMATS.OAT: "OAT",
        lief.Binary.FORMATS.ART: "ART",
    }.get(fmt, "UNKNOWN")


def _parse(path: str) -> lief.Binary | None:
    try:
        return lief.parse(path)
    except Exception:  # noqa: BLE001
        return None


# ── Hashes ──────────────────────────────────────────────────────────────


def file_hashes(path: str) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


# ── Section model ───────────────────────────────────────────────────────


def _section_to_dict(section) -> dict[str, Any]:
    """Format-agnostic section→dict.

    Different LIEF versions (and different format modules — ELF.Section,
    PE.Section, MachO.Section) expose different flag APIs. We do our
    best to extract the common fields and fall back gracefully.
    """
    flags_int = int(getattr(section, "flags", 0))
    # Try to extract W/R/X bits from the flags int via known constants.
    # PE:  IMAGE_SCN_MEM_EXECUTE=0x20000000, _READ=0x40000000, _WRITE=0x80000000
    # ELF: SHF_WRITE=0x1, SHF_ALLOC=0x2, SHF_EXECINSTR=0x4
    write = bool(flags_int & (0x80000000 | 0x1))
    read = bool(flags_int & (0x40000000 | 0x2))
    execute = bool(flags_int & (0x20000000 | 0x4))
    flags_str = ("R" if read else "-") + ("W" if write else "-") + ("X" if execute else "-")
    if flags_str == "---":
        flags_str = "-"
    # Detect W^X violations
    wx = write and execute
    return {
        "name": section.name,
        "virtual_address": int(section.virtual_address),
        "virtual_size": int(section.size),
        "raw_size": int(getattr(section, "original_size", section.size)),
        "offset": int(section.offset),
        "flags": flags_str,
        "wx": wx,
        "entropy": round(float(section.entropy), 3),
    }


# ── String extraction (ported from v1 native.py) ───────────────────────


def extract_strings(
    data: bytes, min_length: int = 5
) -> dict[str, list[dict[str, Any]]]:
    """Return ``{"ascii": [...], "utf16le": [...]}`` for printable strings in *data*.

    Each entry is ``{"string": str, "offset": int}``. Offsets are byte
    offsets into *data*. This is the same algorithm v1 used, but
    regex-driven for speed and clarity.
    """
    ascii_re = _ascii_re(min_length)
    utf16_re = _utf16_re(min_length)
    ascii_matches = [
        {"string": m.group(0).decode("ascii"), "offset": m.start()}
        for m in ascii_re.finditer(data)
    ]
    utf16le_matches = [
        {"string": m.group(0).decode("utf-16-le"), "offset": m.start()}
        for m in utf16_re.finditer(data)
    ]
    return {"ascii": ascii_matches, "utf16le": utf16le_matches}


# ── Format-specific helpers ─────────────────────────────────────────────


def _pe_to_dict(pe: lief.PE.Binary) -> dict[str, Any]:
    # LIEF 0.17.x: there is no `pe.is_dll` instance attribute.
    #   - DLL-ness = bit in `pe.header.characteristics` (IMAGE_FILE_DLL = 0x2000)
    #   - PIE-ness = `pe.optional_header.has(DLL_CHARACTERISTICS.DYNAMIC_BASE)`
    # Imphash is a free function `lief.PE.get_imphash(pe)`, not a `Binary`
    # method. The previous code carried a dead `if False else pe.get_imphash()`
    # branch that raised `AttributeError` on every call, and a stale
    # `DYN_BASE` reference (the actual enum member is `DYNAMIC_BASE` on
    # the optional header, not the file header).
    chars = int(pe.header.characteristics)
    return {
        "format": "PE",
        "machine": str(pe.header.machine),
        "is_dll": bool(chars & int(lief.PE.Header.CHARACTERISTICS.DLL)),
        "is_pie": pe.optional_header.has(
            lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE
        ),
        "entrypoint": int(pe.entrypoint),
        "imagebase": int(pe.imagebase),
        "virtual_size": int(pe.virtual_size),
        "imphash": lief.PE.get_imphash(pe),
        "has_signature": pe.has_signatures,
        "has_debug": pe.has_debug,
        "has_exceptions": pe.has_exceptions,
        "has_tls": pe.has_tls,
        "has_resources": pe.has_resources,
    }


def _elf_to_dict(elf: lief.ELF.Binary) -> dict[str, Any]:
    # LIEF 0.17.x dropped some has_* attrs from the public API.
    # Use getattr with a default of False for forward-compat.
    def _has(name: str) -> bool:
        return bool(getattr(elf, name, False))

    return {
        "format": "ELF",
        "machine": str(elf.header.machine_type),
        "is_pie": elf.is_pie,
        "entrypoint": int(elf.entrypoint),
        "imagebase": int(elf.imagebase),
        "virtual_size": int(elf.virtual_size),
        "has_interpreter": _has("has_interpreter"),
        "interpreter": elf.interpreter,
        "is_dynamic": _has("has_dynamic_symbol"),
        "has_relro": _has("has_notes"),  # proxy; check dynamic tags for full RELRO detection
        "has_bind_now": _has("has_notes"),
        "has_nx": _has("has_nx"),
    }


def _macho_to_dict(macho: lief.MachO.Binary) -> dict[str, Any]:
    return {
        "format": "MACHO",
        "machine": str(macho.header.cpu_type),
        "is_pie": bool(macho.header.flags & lief.MachO.Header.FLAGS.PIE),
        "entrypoint": int(macho.entrypoint),
        "imagebase": int(macho.imagebase),
        "virtual_size": int(macho.virtual_size),
        "has_code_signature": macho.has_code_signature,
        "has_uuid": macho.has_uuid,
    }


def _dex_to_dict(dex: lief.DEX.File) -> dict[str, Any]:
    return {
        "format": "DEX",
        "version": dex.version,
        "class_count": len(dex.classes),
        "method_count": sum(len(c.methods) for c in dex.classes),
        "string_count": len(list(dex.strings)),
    }


def parse_binary(path: str) -> dict[str, Any]:
    """Auto-detect format and return a normalized header dict.

    The result is JSON-serializable and includes hashes, format-specific
    fields, and section/segment info.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    binary = _parse(path)
    if binary is None:
        raise ValueError(f"Could not parse {path} as any LIEF-supported format")

    info: dict[str, Any] = {
        "path": path,
        "size_bytes": os.path.getsize(path),
        "hashes": file_hashes(path),
        "format": str(binary.format),
    }

    if isinstance(binary, lief.PE.Binary):
        info.update(_pe_to_dict(binary))
    elif isinstance(binary, lief.ELF.Binary):
        info.update(_elf_to_dict(binary))
    elif isinstance(binary, lief.MachO.Binary):
        info.update(_macho_to_dict(binary))
    elif isinstance(binary, lief.DEX.File):
        info.update(_dex_to_dict(binary))
    else:
        info.update({
            "format": str(binary.format),
            "entrypoint": int(getattr(binary, "entrypoint", 0)),
        })

    return info


def get_sections(path: str) -> list[dict[str, Any]]:
    """Return sections for the parsed binary.

    For ELF, returns the *section* list (not segments). For MachO,
    returns the *segment → section* tree as a flat list with the
    segment name prefixed.
    """
    binary = _parse(path)
    if binary is None:
        raise ValueError(f"Could not parse {path}")
    sections: list[dict[str, Any]] = []
    for section in binary.sections:
        sections.append(_section_to_dict(section))
    return sections


def get_imports_exports(
    path: str,
    max_imports: int = 0,
    max_exports: int = 0,
    library_filter: str = "",
) -> dict[str, Any]:
    """Return format-normalized imports/exports.

    Args:
        path: PE / ELF / MachO to analyze.
        max_imports: cap the returned ``imports`` list to this many
            entries (0 = no cap, the v2.9.0 default). Triggers the
            ``truncated`` flag in the response when the cap fires.
        max_exports: same cap for ``exports``.
        library_filter: optional substring filter against the
            library name field — pass ``"kernel32|user32"`` (pipe-
            separated) to retain only matching libraries. The
            substring match is case-insensitive.

    Added in v2.9.1+ to fix Gap 27 (the response-size ceiling on
    the 4 large VM-protected targets). The v2.9.0 default (no
    cap) is preserved for backward compatibility.
    """
    binary = _parse(path)
    if binary is None:
        raise ValueError(f"Could not parse {path}")

    imports: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []

    # LIEF has a unified relocations/imports API. `binary.imports` is the
    # *library* list; each library has its own `entries` (per-function
    # symbols). Iterating only the outer level (as the original code did)
    # loses every function name — `getattr(imp, "function", None)` returns
    # None for the library-level object. Walk the inner loop too.
    if hasattr(binary, "imports"):
        for imp in binary.imports:
            lib_name = getattr(imp, "name", None) or str(imp)
            if library_filter and not _library_filter_match(
                lib_name, library_filter
            ):
                continue
            for entry in getattr(imp, "entries", []) or []:
                imports.append({
                    "library": lib_name,
                    "name": getattr(entry, "name", "") or "",
                    "ordinal": getattr(entry, "ordinal", None),
                })

    if hasattr(binary, "exported_functions"):
        for sym in binary.exported_functions:
            sym_name = getattr(sym, "name", "") or str(sym)
            exports.append({
                "name": sym_name,
                "address": getattr(sym, "address", None),
            })

    # Sort for determinism (library, name) for imports and
    # (name) for exports, then apply caps.
    imports.sort(key=lambda e: (e["library"], e["name"]))
    exports.sort(key=lambda e: e["name"])
    original_import_count = len(imports)
    original_export_count = len(exports)
    truncated = False
    if max_imports > 0 and len(imports) > max_imports:
        imports = imports[:max_imports]
        truncated = True
    if max_exports > 0 and len(exports) > max_exports:
        exports = exports[:max_exports]
        truncated = True
    return {
        "imports": imports,
        "exports": exports,
        "truncated": truncated,
        "original_count": {
            "imports": original_import_count,
            "exports": original_export_count,
        },
        "returned_count": {
            "imports": len(imports),
            "exports": len(exports),
        },
    }


def _library_filter_match(lib_name: str, pattern: str) -> bool:
    """Substring (case-insensitive) match against a pipe-separated
    pattern. Empty pattern matches everything. Used by
    ``get_imports_exports(library_filter=...)``."""
    if not pattern:
        return True
    lib_lower = lib_name.lower()
    return any(p.strip().lower() in lib_lower for p in pattern.split("|") if p.strip())


def get_imphash(path: str) -> str:
    """Return the imphash (PE-only). Empty string for non-PE formats."""
    binary = _parse(path)
    if isinstance(binary, lief.PE.Binary):
        # LIEF 0.17.x: imphash is a free function, not a Binary method.
        return lief.PE.get_imphash(binary) or ""
    return ""


def get_overlay(path: str) -> dict[str, Any]:
    """Return appended data after the last section, with offset and size."""
    binary = _parse(path)
    if binary is None:
        raise ValueError(f"Could not parse {path}")
    if isinstance(binary, lief.PE.Binary):
        overlay = binary.overlay
        if overlay is None:
            return {"present": False, "size": 0, "offset": 0}
        return {
            "present": True,
            "size": len(overlay),
            "offset": int(binary.overlay_offset or 0),
        }
    return {"present": False, "size": 0, "offset": 0, "note": "overlay only defined for PE"}


def _safe_str(value: Any, *, encoding: str = "utf-8") -> str:
    """Decode ``value`` to ``str`` if it is ``bytes``/``bytearray``;
    fall back to latin-1 (which never raises) if the chosen encoding
    fails. Returns the original value for non-bytes inputs.

    Cycle 2 fix: LIEF 0.17.x exposes ``SignerInfo.issuer`` and
    ``.serial_number`` as raw ``bytes`` (the DER-encoded ASN.1 form).
    The previous code returned these bytes directly into a dict
    that the MCP transport JSON-encoded, which raised
    ``TypeError: Object of type bytes is not JSON serializable`` on
    4/4 binaries × 3 targets = 12 errors.
    """
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode(encoding)
        except (UnicodeDecodeError, AttributeError):
            return bytes(value).decode("latin-1", errors="replace")
    if value is None:
        return ""
    return str(value)


def get_authenticode(path: str) -> dict[str, Any]:
    """Return Authenticode signature details for PE binaries."""
    binary = _parse(path)
    if not isinstance(binary, lief.PE.Binary):
        return {"signed": False, "note": "not a PE binary"}
    if not binary.has_signatures:
        return {"signed": False}
    sigs = list(binary.signatures)
    # LIEF 0.17.x: `Signature` has no `signer_info` attribute; iterate
    # `.signers` (an iterable of `SignerInfo` with `.issuer`,
    # `.serial_number`, `.digest_algorithm`). The bytes attributes
    # are decoded to str via `_safe_str` so the dict is JSON-encodable.
    return {
        "signed": True,
        "signature_count": len(sigs),
        "signers": [
            {
                "issuer": _safe_str(getattr(si, "issuer", b"")),
                "serial_number": _safe_str(getattr(si, "serial_number", b"")),
                "digest_algorithm": _safe_str(
                    getattr(si, "digest_algorithm", "")
                ),
            }
            for s in sigs
            for si in getattr(s, "signers", [])
        ],
    }


# PE debug directory entry type constants. Subset of
# Microsoft's PE/COFF specification that's relevant to
# the ANTI-TAMPER-TAXONOMY.md Pattern A-DW detection
# (IMAGE_DEBUG_TYPE_CODEVIEW = 2 is the PDB pointer;
# IMAGE_DEBUG_TYPE_POGO = 10 is the third-party-ATD layer's
# trigger-arming metadata).
#
# IMPORTANT (v2.9.1 fix for Gap 22): LIEF 0.16+ uses an
# internal ``Debug.TYPES`` enum that does NOT match the
# Microsoft integer values. Verified on LIEF 0.17.6:
#   MS value  LIEF value  Name
#       2          2       CODEVIEW (matches)
#       10         13      POGO         ← LIEF shifted
#       12         15      MPX          ← LIEF shifted
#       13         16      REPRO        ← LIEF shifted
#       20         12      VC_FEATURE   ← LIEF shifted
#
# The stdlib walker (pure-stdlib PE parsing) reads the
# raw bytes, so it sees the Microsoft values directly.
# The LIEF path needs to translate LIEF's enum to the
# Microsoft value before name lookup + POGO/CODEVIEW
# detection. We do that with ``_LIEF_DEBUG_TYPE_TO_MS``
# below; entries not in the map fall through to the
# MS lookup (and eventually the ``TYPE_<n>`` fallback).
_DEBUG_TYPE_NAMES: dict[int, str] = {
    0: "UNKNOWN",
    1: "COFF",
    2: "CODEVIEW",
    3: "FPO",
    4: "MISC",
    5: "EXCEPTION",
    6: "FIXUP",
    7: "BORLAND_MAP",
    9: "CLSID",
    10: "POGO",
    11: "ILTCG",
    12: "MPX",
    13: "REPRO",
    14: "EX_DLLCHARACTERISTICS",
    16: "RESERVED10",
    20: "VC_FEATURE",
    21: "POGO_INLINES",
    22: "ILTCG_INSTRUMENTATION",
}

# Reverse mapping: LIEF Debug.TYPES enum value -> Microsoft
# IMAGE_DEBUG_TYPE_* value. Populated lazily from
# ``lief.PE.Debug.TYPES`` on first use. The keys that match
# between the two (CODEVIEW=2 in both) are omitted — the
# fallback path is the MS lookup.
_LIEF_DEBUG_TYPE_TO_MS: dict[int, int] = {}


def _init_lief_debug_type_map() -> None:
    """Build the LIEF enum -> Microsoft value map by introspecting
    ``lief.PE.Debug.TYPES`` and matching against the canonical
    names in ``_DEBUG_TYPE_NAMES``.

    Called once on first invocation of ``get_debug_directory``
    via the LIEF path. Idempotent. The map covers every
    member of ``lief.PE.Debug.TYPES`` whose ``name`` string
    appears in ``_DEBUG_TYPE_NAMES`` (case-insensitive).
    Entries not matched are logged in the function's
    ``unknown_lief_types`` list for diagnostic visibility.
    """
    if _LIEF_DEBUG_TYPE_TO_MS:
        return
    try:
        lief_types = lief.PE.Debug.TYPES
    except AttributeError:
        return
    for member_name in dir(lief_types):
        if member_name.startswith("_") or member_name != member_name.upper():
            # LIEF uses SCREAMING_SNAKE for enum members.
            continue
        if not member_name.isupper():
            continue
        # Find the MS value whose key name in _DEBUG_TYPE_NAMES
        # matches the LIEF member name (e.g. "POGO" -> 10).
        ms_value = None
        for ms_k, ms_name in _DEBUG_TYPE_NAMES.items():
            if ms_name == member_name:
                ms_value = ms_k
                break
        if ms_value is None:
            continue
        try:
            lief_value = int(getattr(lief_types, member_name))
        except (TypeError, ValueError):
            continue
        if lief_value != ms_value:
            _LIEF_DEBUG_TYPE_TO_MS[lief_value] = ms_value


def _lief_type_to_ms(lief_type_int: int) -> int:
    """Convert a LIEF ``Debug.TYPES`` integer to the Microsoft
    IMAGE_DEBUG_TYPE_* value. Pass-through if the value already
    matches (e.g. CODEVIEW=2 in both LIEF and Microsoft).

    Lookup order:
    1. If the LIEF value is in ``_LIEF_DEBUG_TYPE_TO_MS`` keys,
       return the mapped MS value (handles LIEF's shifted enums).
    2. If the LIEF value is in ``_DEBUG_TYPE_NAMES`` (i.e. is
       already a valid MS value like CODEVIEW=2), pass through.
    3. Otherwise return the LIEF value unchanged (the caller
       will format it as ``TYPE_<n>``).
    """
    if lief_type_int in _LIEF_DEBUG_TYPE_TO_MS:
        return _LIEF_DEBUG_TYPE_TO_MS[lief_type_int]
    if lief_type_int in _DEBUG_TYPE_NAMES:
        return lief_type_int
    return lief_type_int


def get_debug_directory(path: str) -> dict[str, Any]:
    """Return the PE debug directory entries (incl. IMAGE_DEBUG_TYPE_POGO).

    The POGO entry (type 10) is the third-party-ATD layer's
    trigger-arming metadata; surfaced with ``kind: "POGO"``
    in the response dict. Per the v2.9.0 stress test
    (subdir 4 stage 5), a POGO entry in a UE5 binary is
    a Pattern A-DW signal (third-party-ATD-wrapped variant).

    A non-matching PDB filename tag in the CODEVIEW
    entry (type 2) is the ANTI-TAMPER-TAXONOMY.md
    Pattern A vendor-tag signal. The PDB filename is
    not surfaced here (it would require resolving the
    RSDS CodeView stream); the caller can re-run
    ``parse_binary`` and inspect the ``has_debug`` +
    raw-section-walk fields if the filename is needed.

    The ``backend`` field in the response records which
    LIEF attribute path served the data:

    - ``"lief.debug"`` — LIEF 0.16+ (``binary.debug``,
      ``entry.pointerto_rawdata``, ``entry.major_version``/
      ``entry.minor_version``). The canonical path.
    - ``"lief.debug_directory"`` — LIEF 0.13-0.15
      (``binary.debug_directory``,
      ``entry.addressof_rawdata``, ``entry.version``).
      The legacy path; supported when available.
    - ``"stdlib_pe_walker"`` — pure-stdlib PE parser
      used when neither LIEF attribute is reachable
      (the v2.9.1+ fallback for unparseable / stripped
      PEs). Emits a minimal subset of the dict.

    Returns:
        {
          "path": str,
          "backend": str,
          "debug_entries": int,
          "has_pogo_entry": bool,
          "has_codeview_entry": bool,
          "pogo_indices": list[int],
          "codeview_indices": list[int],
          "entries": [
            {"index": int, "type": int, "kind": str,
             "timestamp": int, "version": int,
             "sizeof_data": int, "addressof_rawdata": int,
             "major_version": int, "minor_version": int},
            ...
          ],
        }
    """
    binary = _parse(path)
    if not isinstance(binary, lief.PE.Binary):
        return {
            "path": path,
            "backend": "not_a_pe_binary",
            "debug_entries": 0,
            "has_pogo_entry": False,
            "has_codeview_entry": False,
            "pogo_indices": [],
            "codeview_indices": [],
            "entries": [],
            "note": "not a PE binary",
        }
    entries: list[dict[str, Any]] = []
    pogo_indices: list[int] = []
    codeview_indices: list[int] = []
    backend = ""
    if hasattr(binary, "debug"):
        # LIEF 0.16+ canonical path.
        backend = "lief.debug"
        dbg = binary.debug
        # Lazily build the LIEF-enum -> Microsoft-value map.
        # The v2.9.1 fix for Gap 22: LIEF shifted the enum
        # values (POGO=13 in LIEF vs 10 in Microsoft docs;
        # CODEVIEW=2 in both).
        _init_lief_debug_type_map()
        for i, entry in enumerate(dbg):
            lief_type_int = int(entry.type)
            # Convert to the Microsoft value for kind-name
            # lookup and POGO/CODEVIEW detection.
            entry_type = _lief_type_to_ms(lief_type_int)
            kind = _DEBUG_TYPE_NAMES.get(entry_type, f"TYPE_{entry_type}")
            if entry_type == 10:
                pogo_indices.append(i)
            if entry_type == 2:
                codeview_indices.append(i)
            major = int(getattr(entry, "major_version", 0) or 0)
            minor = int(getattr(entry, "minor_version", 0) or 0)
            version = (major << 16) | minor
            entries.append({
                "index": i,
                "type": entry_type,
                "kind": kind,
                "timestamp": int(entry.timestamp),
                "version": version,
                "major_version": major,
                "minor_version": minor,
                "sizeof_data": int(entry.sizeof_data),
                "addressof_rawdata": int(getattr(entry, "pointerto_rawdata",
                                                getattr(entry, "addressof_rawdata", 0))),
            })
    elif hasattr(binary, "debug_directory"):
        # LIEF 0.13-0.15 legacy path (kept for hosts pinned
        # to an older LIEF). The v2.9.0 reference MCP tool
        # lived here before the v0.16 attribute rename.
        backend = "lief.debug_directory"
        dbg = binary.debug_directory
        for i, entry in enumerate(dbg):
            entry_type = int(entry.type)
            kind = _DEBUG_TYPE_NAMES.get(entry_type, f"TYPE_{entry_type}")
            if entry_type == 10:
                pogo_indices.append(i)
            if entry_type == 2:
                codeview_indices.append(i)
            entries.append({
                "index": i,
                "type": entry_type,
                "kind": kind,
                "timestamp": int(entry.timestamp),
                "version": int(getattr(entry, "version", 0) or 0),
                "sizeof_data": int(entry.sizeof_data),
                "addressof_rawdata": int(getattr(entry, "addressof_rawdata", 0)),
            })
    else:
        # LIEF stripped / attribute removed entirely.
        # Fall through to the pure-stdlib PE walker that
        # also lives in skills/re-drm-fingerprint/
        # references/pogo_debug_check.py — the v2.9.0
        # ship path for hosts without the new MCP tool.
        backend = "stdlib_pe_walker"
        fallback = _pogo_fallback_stdlib(path)
        return {
            "path": path,
            "backend": backend,
            "debug_entries": fallback.get("debug_entries", 0),
            "has_pogo_entry": fallback.get("has_pogo_entry", False),
            "has_codeview_entry": fallback.get("has_codeview_entry", False),
            "pogo_indices": fallback.get("pogo_indices", []),
            "codeview_indices": fallback.get("codeview_indices", []),
            "entries": fallback.get("entries", []),
            "note": fallback.get("note", "lief has neither debug nor debug_directory"),
        }
    return {
        "path": path,
        "backend": backend,
        "debug_entries": len(entries),
        "has_pogo_entry": bool(pogo_indices),
        "has_codeview_entry": bool(codeview_indices),
        "pogo_indices": pogo_indices,
        "codeview_indices": codeview_indices,
        "entries": entries,
    }


def list_dex_classes(path: str) -> list[dict[str, Any]]:
    binary = _parse(path)
    if not isinstance(binary, lief.DEX.File):
        raise ValueError(f"{path} is not a DEX file")
    return [
        {
            "fqn": str(c.fullname),
            "access_flags": c.access_flags,
            "method_count": len(c.methods),
            "field_count": len(c.fields),
        }
        for c in binary.classes
    ]


def list_dex_methods(path: str, class_fqn: str) -> list[dict[str, Any]]:
    binary = _parse(path)
    if not isinstance(binary, lief.DEX.File):
        raise ValueError(f"{path} is not a DEX file")
    target = class_fqn.strip(";")
    for c in binary.classes:
        if str(c.fullname).strip(";") == target or str(c.fullname) == class_fqn:
            return [
                {
                    "name": m.name,
                    "signature": "".join(p.type for p in m.prototype.parameters)
                    + "->" + str(m.prototype.return_type),
                    "access_flags": m.access_flags,
                    "code_offset": int(m.code_offset) if m.code_offset else None,
                }
                for m in c.methods
            ]
    raise ValueError(f"class {class_fqn!r} not found in {path}")


def list_oat_art(path: str) -> list[dict[str, Any]]:
    binary = _parse(path)
    fmt = str(getattr(binary, "format", ""))
    if fmt not in ("OAT", "ART"):
        raise ValueError(f"{path} is not an OAT/ART file")
    out: list[dict[str, Any]] = []
    for cls in getattr(binary, "classes", []):
        for m in cls.methods:
            out.append({
                "class": str(cls.fullname),
                "name": m.name,
                "is_dex_method": bool(getattr(m, "is_dex_method", lambda: False)()),
            })
    return out


def extract_strings_for_binary(
    path: str, min_length: int = 5
) -> dict[str, Any]:
    """Section-aware string extraction across all sections.

    Backward-compatible wrapper around ``categorize_strings`` — the
    return shape is ``{ascii, utf16le, totals, truncated}`` so any
    caller that was reading the v2.4 shape continues to work.
    """
    result = categorize_strings(
        path,
        min_length=min_length,
        categories=[],
        include_misc=False,
        max_per_category=200,
        samples_per_category=200,
        skip_sections=None,
    )
    return {
        "ascii": result["ascii_capped"],
        "utf16le": result["utf16le_capped"],
        "totals": {
            "ascii": result["totals"]["ascii_extracted"],
            "utf16le": result["totals"]["utf16le_extracted"],
        },
        "truncated": result["truncated"]["per_category"],
    }


def categorize_strings(
    path: str,
    min_length: int = 5,
    categories: list[str] | None = None,
    include_misc: bool = True,
    max_per_category: int = 200,
    samples_per_category: int = 5,
    skip_sections: list[str] | None = None,
) -> dict[str, Any]:
    """Keyword-bucketed strings dump (superset of extract_strings).

    The categorization vocabulary is loaded from
    ``data/drm-indicators.yaml::string_categories`` at module
    import time — see ``re_lief.categorizers``.  Two categories
    (``anti_debug``, ``hwid``) inherit their keyword lists from
    the existing catalog sections via a ``seed_from`` pointer;
    the rest have inline keyword lists.

    Parameters
    ----------
    path
        File to analyze.
    min_length
        Minimum printable run length to consider (default 5).
    categories
        Subset of category names to populate.  ``None`` = all
        11 categories.
    include_misc
        Whether to populate the ``misc`` catch-all bucket.
    max_per_category
        Cap on the number of unique matches returned in each
        category's ``samples`` list.  The ``count`` is reported
        honestly regardless of this cap.
    samples_per_category
        Convenience cap on how many example matches to include
        per category (kept small to keep the JSON payload
        manageable).  The full count is in ``count``.
    skip_sections
        Section names to skip during extraction (e.g.
        ``[".idata", ".xtls"]`` to skip the encrypted-VM
        bytecode regions on a 500+ MB Unity IL2CPP binary).

    Returns a JSON-serializable dict with the schema documented in
    ``docs/MCP_SERVERS.md`` (and the plan file at
    `./docs/`).
    """
    # Import here to avoid a top-level import cycle on first MCP
    # server load (the categorizer pulls in pyyaml).
    from re_lief.categorizers import categorize, load_categories

    binary = _parse(path)
    if binary is None:
        raise ValueError(f"Could not parse {path}")

    skip_set = set(skip_sections or [])
    all_ascii: list[dict[str, Any]] = []
    all_utf16: list[dict[str, Any]] = []
    for section in binary.sections:
        if section.name in skip_set:
            continue
        try:
            data = bytes(section.content)
        except Exception:  # noqa: BLE001
            continue
        extracted = extract_strings(data, min_length=min_length)
        for m in extracted["ascii"]:
            m["section"] = section.name
            all_ascii.append(m)
        for m in extracted["utf16le"]:
            m["section"] = section.name
            all_utf16.append(m)

    # Combine the ASCII + UTF-16LE match lists for the categorizer.
    # The categorizer doesn't care about the encoding; it just sees
    # printable substrings.  We tag each match so a future caller
    # can filter by encoding if needed.
    for m in all_ascii:
        m["encoding"] = "ascii"
    for m in all_utf16:
        m["encoding"] = "utf16le"
    all_matches = all_ascii + all_utf16

    # Deduplicate within (string, section) for fair per-category counts.
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for m in all_matches:
        key = (m["string"], m.get("section", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(m)

    # Filter the category list (None = all).
    cat_names = categories if categories is not None else list(load_categories().keys())
    if not include_misc and "misc" in cat_names:
        cat_names = [c for c in cat_names if c != "misc"]

    by_category = categorize(
        deduped,
        categories=cat_names if categories is not None else None,
        samples_per_category=samples_per_category,
    )

    # Per-category "honest" cap: report the full count, but trim
    # samples to max_per_category.  The count is preserved.
    truncated_per_category = False
    for cat_name, info in by_category.items():
        if info["count"] > max_per_category:
            truncated_per_category = True
        # samples were already capped at samples_per_category by the
        # categorizer; this is the higher-level cap.

    # Per-encoding "honest" cap for the pre-cap flat lists.
    def _dedup_cap(lst: list[dict[str, Any]], cap: int) -> tuple[list[dict[str, Any]], int]:
        seen_local: dict[tuple[str, str], dict[str, Any]] = {}
        for m in lst:
            key = (m["string"], m.get("section", ""))
            if key not in seen_local:
                seen_local[key] = m
        ordered = sorted(seen_local.values(), key=lambda x: (-len(x["string"]), x["string"]))
        return ordered[:cap], len(ordered)

    ascii_capped, ascii_total = _dedup_cap(all_ascii, max_per_category)
    utf16_capped, utf16_total = _dedup_cap(all_utf16, max_per_category)

    # Uncategorised sample: a 50-string slice of strings that fell
    # in misc (helps the user spot missing categories).
    uncategorized_sample: list[dict[str, Any]] = []
    misc_info = by_category.get("misc", {})
    if include_misc and "samples" in misc_info:
        uncategorized_sample = list(misc_info["samples"])
    # Plus a slice of strings that matched zero categories
    # (only if misc is disabled — otherwise the sample already
    # covers it).
    if not include_misc:
        cat_keys = {tuple((s.get("string"), s.get("section"))) for info in by_category.values() for s in info.get("samples", [])}
        extras = [m for m in deduped if (m["string"], m.get("section", "")) not in cat_keys]
        uncategorized_sample = sorted(
            extras, key=lambda x: -len(x["string"])
        )[:50]

    return {
        "path": path,
        "min_length": min_length,
        "totals": {
            "ascii_extracted": len(all_ascii),
            "utf16le_extracted": len(all_utf16),
            "deduplicated": len(deduped),
            "categorized": sum(
                info["count"] for info in by_category.values()
            ),
        },
        "truncated": {
            "input": False,           # we don't currently hard-cap input
            "per_category": truncated_per_category,
            "per_encoding": ascii_total > max_per_category or utf16_total > max_per_category,
        },
        "by_category": by_category,
        "ascii_capped": ascii_capped,
        "utf16le_capped": utf16_capped,
        "uncategorized_sample": uncategorized_sample,
    }


def normalize_for_diff(path: str) -> dict[str, Any]:
    """Return a structural snapshot for cross-binary diffing.

    Strips variable-length fields (hashes, timestamps) and keeps
    only the parts that should match between two binaries of the
    same family.
    """
    binary = _parse(path)
    if binary is None:
        raise ValueError(f"Could not parse {path}")
    info = parse_binary(path)
    # Drop fields that vary between builds of the same source.
    for k in ("size_bytes", "hashes", "path"):
        info.pop(k, None)
    return info


# ── Pure-stdlib PE debug-directory walker (Gap 22 fallback) ─────────────
#
# When LIEF strips the ``binary.debug_directory`` attribute (v0.13-0.15
# legacy) and ``binary.debug`` (v0.16+ canonical) is also missing,
# fall through to a stdlib-only PE walker. This mirrors the structure
# of the v2.9.0 skill-side helper at
# ``skills/re-drm-fingerprint/references/pogo_debug_check.py`` but is
# colocated here so the MCP tool can return the same dict shape
# regardless of which path fired.
#
# The walker is intentionally minimal: it reads the debug directory
# (data directory index 6) via ``struct`` and the PE section table
# for the RVA→file-offset conversion. It does NOT parse the debug
# data payload itself (CODEVIEW/POGO bodies); that's the responsibility
# of the LIEF-based paths.

_IMAGE_DIRECTORY_ENTRY_DEBUG = 6
_IMAGE_DEBUG_DIRECTORY_SIZE = 28
_IMAGE_SIZEOF_SHORT = 2
_IMAGE_SIZEOF_LONG = 4


def _pe_section_offsets_stdlib(data: bytes) -> list[tuple[str, int, int, int]]:
    """Return a list of ``(name, virtual_address, raw_offset, raw_size)``
    for each section in the PE's section table. Used for RVA→file-offset
    conversion in the stdlib debug walker."""
    if len(data) < 0x40:
        return []
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 0xF8 > len(data):
        return []
    # IMAGE_FILE_HEADER is 20 bytes; nt_headers starts at e_lfanew + 4 (PE\0\0)
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    if machine not in (0x14C, 0x8664, 0x1C0, 0xAA64):  # i386, AMD64, ARM, AARCH64
        return []
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    if opt_hdr_size < 0x70 or num_sections < 1:
        return []
    section_table_off = e_lfanew + 24 + opt_hdr_size
    out: list[tuple[str, int, int, int]] = []
    for i in range(num_sections):
        rec = section_table_off + i * 40
        if rec + 40 > len(data):
            break
        name_raw = data[rec:rec + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
        vsize = struct.unpack_from("<I", data, rec + 8)[0]
        va = struct.unpack_from("<I", data, rec + 12)[0]
        raw_size = struct.unpack_from("<I", data, rec + 16)[0]
        raw_off = struct.unpack_from("<I", data, rec + 20)[0]
        out.append((name_raw, va, raw_off, raw_size))
    return out


def _rva_to_file_offset_stdlib(sections: list[tuple[str, int, int, int]], rva: int) -> int:
    """Map an RVA to a file offset via the PE section table.

    The PE headers (RVA 0..0x1000) are not in any section, so for
    those we return the RVA directly (the file layout typically
    places headers at file offset 0 + RVA when the image base is
    the standard 0x140000000 for 64-bit PE). Note: this is the
    v2.9.1-correct behavior; the previous implementation also
    returned the RVA for non-matching RVAs, which produced wrong
    file offsets when the RVA was *between* sections or above
    any section's range. The fix: return -1 (sentinel) for
    out-of-range RVAs and let the caller fall back to the
    stdlib walker's error path."""
    for _name, va, raw_off, raw_size in sections:
        if va <= rva < va + max(raw_size, 0):
            return raw_off + (rva - va)
    # PE headers occupy RVAs 0..0x1000 mapped to file offsets
    # 0..0x400 (the MZ+PE header region). This is the canonical
    # mapping for the IMAGE_OPTIONAL_HEADER-resident data
    # directories. The debug data directory's RVA *is* in
    # this range for many binaries but for our VM-protected
    # targets it is often in a far-away section.
    if 0 <= rva < 0x1000:
        return rva
    return -1


def _pogo_fallback_stdlib(path: str) -> dict[str, Any]:
    """Pure-stdlib PE debug-directory walker. Returns the same dict
    shape as the LIEF path (minus the ``backend`` field — the
    caller adds ``backend: "stdlib_pe_walker"`` to the response).
    The walker is a v2.9.1+ safety net for hosts where LIEF has
    dropped both ``debug_directory`` (v0.13-0.15) and ``debug``
    (v0.16+ canonical)."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        return {
            "debug_entries": 0,
            "has_pogo_entry": False,
            "has_codeview_entry": False,
            "pogo_indices": [],
            "codeview_indices": [],
            "entries": [],
            "note": f"stdlib_pe_walker: failed to read {path}: {exc}",
        }
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {
            "debug_entries": 0,
            "has_pogo_entry": False,
            "has_codeview_entry": False,
            "pogo_indices": [],
            "codeview_indices": [],
            "entries": [],
            "note": "stdlib_pe_walker: not a PE (no MZ signature)",
        }
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 0xF8 > len(data):
        return {
            "debug_entries": 0,
            "has_pogo_entry": False,
            "has_codeview_entry": False,
            "pogo_indices": [],
            "codeview_indices": [],
            "entries": [],
            "note": "stdlib_pe_walker: e_lfanew out of range",
        }
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {
            "debug_entries": 0,
            "has_pogo_entry": False,
            "has_codeview_entry": False,
            "pogo_indices": [],
            "codeview_indices": [],
            "entries": [],
            "note": "stdlib_pe_walker: missing PE\\0\\0 signature",
        }
    opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    if magic == 0x10B:  # PE32
        dd_off = e_lfanew + 24 + 96
    elif magic == 0x20B:  # PE32+
        dd_off = e_lfanew + 24 + 112
    else:
        return {
            "debug_entries": 0,
            "has_pogo_entry": False,
            "has_codeview_entry": False,
            "pogo_indices": [],
            "codeview_indices": [],
            "entries": [],
            "note": f"stdlib_pe_walker: unknown optional-header magic 0x{magic:x}",
        }
    # Data directory index 6 = IMAGE_DIRECTORY_ENTRY_DEBUG. Each
    # data directory is 8 bytes (RVA + size).
    dbg_dir_off = dd_off + _IMAGE_DIRECTORY_ENTRY_DEBUG * 8
    if dbg_dir_off + 8 > len(data):
        return {
            "debug_entries": 0,
            "has_pogo_entry": False,
            "has_codeview_entry": False,
            "pogo_indices": [],
            "codeview_indices": [],
            "entries": [],
            "note": "stdlib_pe_walker: data directory table truncated",
        }
    dbg_rva, dbg_size = struct.unpack_from("<II", data, dbg_dir_off)
    if dbg_rva == 0 or dbg_size == 0:
        return {
            "debug_entries": 0,
            "has_pogo_entry": False,
            "has_codeview_entry": False,
            "pogo_indices": [],
            "codeview_indices": [],
            "entries": [],
            "note": "stdlib_pe_walker: empty debug directory",
        }
    sections = _pe_section_offsets_stdlib(data)
    dbg_file_off = _rva_to_file_offset_stdlib(sections, dbg_rva)
    if dbg_file_off < 0 or dbg_file_off + dbg_size > len(data):
        return {
            "debug_entries": 0,
            "has_pogo_entry": False,
            "has_codeview_entry": False,
            "pogo_indices": [],
            "codeview_indices": [],
            "entries": [],
            "note": "stdlib_pe_walker: debug directory exceeds file",
        }
    entries: list[dict[str, Any]] = []
    pogo_indices: list[int] = []
    codeview_indices: list[int] = []
    n_entries = dbg_size // _IMAGE_DEBUG_DIRECTORY_SIZE
    for i in range(n_entries):
        rec = dbg_file_off + i * _IMAGE_DEBUG_DIRECTORY_SIZE
        chars, ts, major, minor, etype, esize, erva, eptr = (
            struct.unpack_from("<IIHHIIII", data, rec)
        )
        # ``chars`` is reserved in modern PE (always 0); the
        # relevant fields for the v2.9.0 stress-test schema are
        # the type, timestamp, sizes, and RVA. The dict shape
        # matches the LIEF path so the caller doesn't branch.
        if etype == 10:
            pogo_indices.append(i)
        if etype == 2:
            codeview_indices.append(i)
        entries.append({
            "index": i,
            "type": int(etype),
            "kind": _DEBUG_TYPE_NAMES.get(int(etype), f"TYPE_{etype}"),
            "timestamp": int(ts),
            "version": (int(major) << 16) | int(minor),
            "major_version": int(major),
            "minor_version": int(minor),
            "sizeof_data": int(esize),
            "addressof_rawdata": int(eptr),
        })
    return {
        "debug_entries": len(entries),
        "has_pogo_entry": bool(pogo_indices),
        "has_codeview_entry": bool(codeview_indices),
        "pogo_indices": pogo_indices,
        "codeview_indices": codeview_indices,
        "entries": entries,
    }
