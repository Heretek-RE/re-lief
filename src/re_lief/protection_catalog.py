"""Native protection classification + anti-analysis primitive scanner (v2.7.0).

The :func:`scan_anti_analysis_primitives` walker implements
``re-lief.scan_anti_analysis_primitives``; the
:func:`classify_native_protection` classifier implements
``re-lief.classify_native_protection``.

Both use the vendored catalogs under ``data/``:

- ``data/anti-analysis-catalog.json`` for the string-table
  + IAT evidence kinds.
- ``data/drm-indicators.yaml::string_categories.categories
  [name=anti_vm_primitives]`` and
  ``[name=android_anti_analysis]`` for the categorized
  keyword lists.
- ``data/drm-indicators.yaml::string_categories.categories
  [name=native_packer_signatures]`` for the section-name
  regex catalog.

All output is vendor-neutral: the labels are categories,
not products.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

# The PE / ELF section table structures we need are small
# enough to hand-parse for the catalog walker. We don't
# pull in lief here because lief lives in a separate
# venv and the classify walker's call site is in
# re-lief's own server process — the lief import would
# only fire when ``parsers.categorize_strings`` is called.


# ── Catalog loader ────────────────────────────────────────────────────


def _plugin_root() -> Path:
    """The repo root, computed from this file's path."""
    here = Path(__file__).resolve()
    # servers/re-lief/src/re_lief/protection_catalog.py → ../../../../ → repo root
    return here.parents[4]


def _load_anti_analysis_catalog() -> dict:
    p = _plugin_root() / "data" / "anti-analysis-catalog.json"
    if not p.is_file():
        return {"entries": []}
    return json.loads(p.read_text())


def _load_yaml_categories() -> dict:
    """Load the YAML catalog and return just the categories list.

    Re-uses the same preprocessor the re-lief categorizers
    use (the YAML contains regex literals like ``"\\.vm"``
    that are not valid YAML double-quoted escapes; the
    preprocessor converts them to single-quoted strings
    where backslashes are literal).
    """
    import re as _re

    p = _plugin_root() / "data" / "drm-indicators.yaml"
    if not p.is_file():
        return {"categories": []}
    text = p.read_text(encoding="utf-8")
    _DOUBLE_QUOTED_WITH_BACKSLASH = _re.compile(r'"(\\[^"]*)"')

    def _to_single(m):
        body = m.group(1).replace("'", "''")
        return f"'{body}'"

    fixed = _DOUBLE_QUOTED_WITH_BACKSLASH.sub(_to_single, text)
    try:
        import yaml
        d = yaml.safe_load(fixed)
    except ImportError:
        return {"categories": []}
    return d.get("string_categories", {})


# ── Strings walker (a small subset of the re-leak-scan extractor) ────


def _scan_strings(data: bytes, min_length: int = 6) -> list[dict[str, Any]]:
    """Return printable ASCII + UTF-16LE strings from raw bytes."""
    out: list[dict[str, Any]] = []
    # ASCII
    # A9 fix (v2.8.0): Python 3 ``enumerate(bytes)`` yields ints,
    # so ``cur`` must be ``list[int]`` and ``bytes(cur)`` does the
    # conversion. The prior ``b"".join(cur)`` raised
    # ``TypeError: sequence item 0: expected bytes-like, int found``
    # on every PE that reached this codepath (per r03-stress Phase 1
    # on Activation64.dll, crashpad_handler.exe, sentry.dll,
    # OpenImageDenoise.dll).
    cur: list[int] = []
    cur_start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not cur:
                cur_start = i
            cur.append(b)
        else:
            if len(cur) >= min_length:
                out.append({
                    "string": bytes(cur).decode("latin-1", errors="replace"),
                    "offset": cur_start,
                    "encoding": "ascii",
                })
            cur = []
    if len(cur) >= min_length:
        out.append({
            "string": bytes(cur).decode("latin-1", errors="replace"),
            "offset": cur_start,
            "encoding": "ascii",
        })
    # UTF-16LE: pairs of bytes where every other byte is 0
    # and the printable-byte is in the printable range
    i = 0
    while i + 1 < len(data):
        b0 = data[i]
        b1 = data[i + 1]
        if b1 == 0 and 0x20 <= b0 < 0x7F:
            # collect
            start = i
            # A9 fix: same int-vs-bytes issue. Use list[int] + bytes().
            buf: list[int] = []
            while i + 1 < len(data):
                c0 = data[i]
                c1 = data[i + 1]
                if c1 == 0 and 0x20 <= c0 < 0x7F:
                    buf.append(c0)
                    i += 2
                else:
                    break
            if len(buf) >= min_length:
                out.append({
                    "string": bytes(buf).decode("latin-1", errors="replace"),
                    "offset": start,
                    "encoding": "utf16le",
                })
            continue
        i += 1
    return out


# ── The two MCP-facing tools ──────────────────────────────────────────


def scan_anti_analysis_primitives(path: str, max_per_category: int = 100) -> dict:
    """Walk a binary and emit anti-analysis primitive matches.

    Returns the dict shape documented on
    ``re-lief.scan_anti_analysis_primitives``.
    """
    catalog = _load_anti_analysis_catalog()
    entries = catalog.get("entries", [])
    cats = _load_yaml_categories()
    yaml_categories = cats.get("categories", [])
    # Build a name -> keywords map for the YAML buckets that
    # the anti-analysis catalog uses
    extra_categories = {
        c["name"]: c.get("keywords", [])
        for c in yaml_categories
        if c.get("name") in ("anti_vm_primitives", "android_anti_analysis",
                             "process_introspection", "memory_integrity",
                             "code_integrity")
    }
    p = Path(path)
    if not p.is_file():
        return {
            "path": path,
            "matches": [],
            "by_category": {},
            "error": "file not found",
        }
    try:
        data = p.read_bytes()
    except OSError as exc:
        return {
            "path": path,
            "matches": [],
            "by_category": {},
            "error": f"read failed: {exc}",
        }
    # Sample the first 8 MB of the binary to keep the
    # memory footprint down. The .text + .rdata section
    # are almost always in this range for a Windows
    # binary; for ELF the .dynstr is at the start of
    # the file. The catalog walker is a *string-table*
    # pass, not a full disasm pass.
    SAMPLE_BYTES = 8 * 1024 * 1024
    sample = data[:SAMPLE_BYTES]
    strings = _scan_strings(sample)
    matches: list[dict[str, Any]] = []
    by_category: dict[str, int] = {}
    per_category_count: dict[str, int] = {}
    # Walk the catalog entries: api_name / symbol / byte_sequence / import
    for entry in entries:
        cat = entry.get("category")
        ev = entry.get("evidence_kind")
        primitive = entry.get("primitive", "")
        if per_category_count.get(cat, 0) >= max_per_category:
            continue
        if ev in ("api_name", "symbol"):
            pat = re.escape(primitive).replace(r"\ ", " ")
            for s in strings:
                if pat and pat.lower() in s["string"].lower():
                    matches.append({
                        "primitive": primitive,
                        "category": cat,
                        "evidence_kind": ev,
                        "offset": s.get("offset", 0),
                        "section": "string-table",
                        "encoding": s.get("encoding", "ascii"),
                    })
                    by_category[cat] = by_category.get(cat, 0) + 1
                    per_category_count[cat] = per_category_count.get(cat, 0) + 1
                    break
        elif ev == "import":
            # We can't reliably walk the IAT without lief;
            # the string-table presence is the proxy. The
            # import_only confirmation requires lief; this
            # walker is a degraded mode that uses the
            # string-table hit as a fallback.
            for s in strings:
                if primitive in s["string"]:
                    matches.append({
                        "primitive": primitive,
                        "category": cat,
                        "evidence_kind": "import-string-fallback",
                        "offset": s.get("offset", 0),
                        "section": "string-table",
                    })
                    by_category[cat] = by_category.get(cat, 0) + 1
                    per_category_count[cat] = per_category_count.get(cat, 0) + 1
                    break
    # Now walk the YAML-bucket keywords for the categories
    # not in the JSON catalog (anti_vm_primitives,
    # android_anti_analysis).
    for cat_name, keywords in extra_categories.items():
        for kw in keywords:
            if per_category_count.get(cat_name, 0) >= max_per_category:
                break
            for s in strings:
                if kw in s["string"]:
                    matches.append({
                        "primitive": kw,
                        "category": cat_name,
                        "evidence_kind": "yaml-keyword",
                        "offset": s.get("offset", 0),
                        "section": "string-table",
                    })
                    by_category[cat_name] = by_category.get(cat_name, 0) + 1
                    per_category_count[cat_name] = per_category_count.get(cat_name, 0) + 1
                    break
    return {
        "path": path,
        "matches": matches,
        "by_category": dict(sorted(by_category.items())),
        "truncated": any(per_category_count.get(c, 0) >= max_per_category for c in by_category),
    }


def classify_native_protection(path: str) -> dict:
    """Classify a native binary's protection class (category-only).

    Returns the dict shape documented on
    ``re-lief.classify_native_protection``.
    """
    p = Path(path)
    if not p.is_file():
        return {
            "path": path,
            "protection_class": "unknown",
            "evidence": [],
            "error": "file not found",
        }
    try:
        data = p.read_bytes()
    except OSError as exc:
        return {
            "path": path,
            "protection_class": "unknown",
            "evidence": [],
            "error": f"read failed: {exc}",
        }
    evidence: list[dict[str, Any]] = []
    section_names = _pe_section_names(data) if data[:2] == b"MZ" else (
        _elf_section_names(data) if data[:4] == b"\x7fELF" else []
    )
    # Detection rules (in priority order — first match wins)
    # 0. Pattern A-VMT (v2.9.1) — encrypted-VM handler-table dispatch
    #    (proprietary-engine variant). The dual-regime signature in
    #    `.xcode` (low-entropy dispatch table at the head + high-
    #    entropy encrypted metadata after ~0x32000) is the diagnostic
    #    differentiator from Pattern A / A-DW. Requires `.arch` +
    #    `.link` + `.xcode` + `.rodata` to be present (the union of
    #    Pattern C's section set + a large `.rodata`). See
    #    ANTI-TAMPER-TAXONOMY.md Pattern A-VMT for the full
    #    observable-composition table. Placed before rule 1 so the
    #    more-specific signature wins over the generic encrypted-VM
    #    bytecode interpreter.
    avmt_sections = {".arch", ".link", ".xcode", ".rodata"}
    if avmt_sections.issubset(section_names):
        avmt_evidence = _classify_avmt_signature(data, section_names)
        if avmt_evidence is not None:
            evidence.append(avmt_evidence)
            return {
                "path": path,
                "protection_class": "encrypted-vm-handler-table-dispatch",
                "evidence": evidence,
            }
    # 1. encrypted-vm-bytecode-interpreter: .arch / .xcode / .xtext / .sbss / .link / .xtls / .xpdata
    vm_pack_sections = {".arch", ".xcode", ".xtext", ".sbss", ".link", ".xtls", ".xpdata"}
    if section_names & vm_pack_sections:
        evidence.append({
            "category": "encrypted-vm-bytecode-interpreter",
            "indicator": f"section set intersects {vm_pack_sections!r}",
            "matched_sections": sorted(section_names & vm_pack_sections),
        })
        return {
            "path": path,
            "protection_class": "encrypted-vm-bytecode-interpreter",
            "evidence": evidence,
        }
    # 2. vm-bytecoded-pe: .vmp0 / .vmp1
    if section_names & {".vmp0", ".vmp1", ".vmp2"}:
        evidence.append({
            "category": "vm-bytecoded-pe",
            "indicator": ".vmp0/.vmp1 section set",
            "matched_sections": sorted(section_names & {".vmp0", ".vmp1", ".vmp2"}),
        })
        return {
            "path": path,
            "protection_class": "vm-bytecoded-pe",
            "evidence": evidence,
        }
    # 3. packer-stub-wrapped: UPX / ASPack / MPRESS / Petite / kkrunchy
    packer_signatures = {"UPX0", "UPX1", "UPX!", ".aspack", ".MPRESS1", ".petite", ".kkrunchy"}
    if section_names & packer_signatures:
        evidence.append({
            "category": "packer-stub-wrapped",
            "indicator": "packer section name",
            "matched_sections": sorted(section_names & packer_signatures),
        })
        return {
            "path": path,
            "protection_class": "packer-stub-wrapped",
            "evidence": evidence,
        }
    # 4. il2cpp-runtime: large .idata + tiny .text + GameAssembly sibling
    if ".idata" in section_names and ".text" in section_names:
        # rough check: .idata is the canonical IL2CPP native
        # symbol-table dump shape; pair with the path basename
        basename = p.name.lower()
        if "gameassembly" in basename:
            evidence.append({
                "category": "il2cpp-runtime",
                "indicator": "GameAssembly.dll + .idata",
            })
            return {
                "path": path,
                "protection_class": "il2cpp-runtime",
                "evidence": evidence,
            }
    # 5. unpacked-debug-pe: PDB path in the binary
    if b".pdb\x00" in data or b"RSDS" in data[:1024]:
        evidence.append({
            "category": "unpacked-debug-pe",
            "indicator": "PDB path embedded",
        })
        return {
            "path": path,
            "protection_class": "unpacked-debug-pe",
            "evidence": evidence,
        }
    # 6. anti-debug-wrapped: bare anti-debug surface but no packer
    strings = _scan_strings(data, min_length=8)
    ad_strings = ("IsDebuggerPresent", "NtQueryInformationProcess", "CheckRemoteDebuggerPresent")
    if any(any(s in st["string"] for s in ad_strings) for st in strings):
        evidence.append({
            "category": "anti-debug-wrapped",
            "indicator": "anti-debug API in string table",
        })
        return {
            "path": path,
            "protection_class": "anti-debug-wrapped",
            "evidence": evidence,
        }
    return {
        "path": path,
        "protection_class": "plain-pe",
        "evidence": [],
    }


# ── PE / ELF section table walkers (lightweight) ──────────────────────


def _pe_section_names(data: bytes) -> set[str]:
    """Return the set of PE section names.

    Walks the COFF section table directly — no lief
    dependency. The PE format is documented in
    https://learn.microsoft.com/en-us/windows/win32/debug/pe-format.
    """
    out: set[str] = set()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return out
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return out
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return out
    # COFF header is at pe_off + 4: u16 machine, u16 num_sections,
    # u16 timestamp, u16 symtab_ptr, u16 num_symbols, u16 opt_header_size,
    # u16 characteristics
    try:
        num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    except struct.error:
        return out
    sec_off = pe_off + 24 + opt_hdr_size
    if sec_off + 40 * num_sections > len(data):
        return out
    for i in range(num_sections):
        base = sec_off + i * 40
        try:
            name = data[base:base + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        except UnicodeDecodeError:
            continue
        if name:
            out.add("." + name if not name.startswith(".") else name)
    return out


def _elf_section_names(data: bytes) -> set[str]:
    """Return the set of ELF section names."""
    out: set[str] = set()
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return out
    # ELF64 (offset 4 = class), little-endian (offset 4 = EI_DATA)


# ── Pattern A-VMT (v2.9.1) classifier extension ───────────────────────


def _pe_section_offsets(data: bytes) -> dict[str, tuple[int, int]]:
    """Return ``{section_name: (raw_offset, raw_size)}`` for each
    section in the PE's section table. Used by the A-VMT
    classifier to locate the `.xcode` section's file offsets
    for the dual-entropy dispatch-table probe. The walker
    is pure-stdlib (no LIEF dep) and matches the layout
    used in ``parsers._pe_section_offsets_stdlib``.
    """
    out: dict[str, tuple[int, int]] = {}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return out
    import struct as _struct
    e_lfanew = _struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 0xF8 > len(data):
        return out
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return out
    num_sections = _struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_hdr_size = _struct.unpack_from("<H", data, e_lfanew + 20)[0]
    if num_sections < 1 or opt_hdr_size < 0x70:
        return out
    section_table_off = e_lfanew + 24 + opt_hdr_size
    for i in range(num_sections):
        rec = section_table_off + i * 40
        if rec + 40 > len(data):
            break
        name_raw = data[rec:rec + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
        raw_size = _struct.unpack_from("<I", data, rec + 16)[0]
        raw_off = _struct.unpack_from("<I", data, rec + 20)[0]
        out[name_raw] = (raw_off, raw_size)
    return out


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. Returns 0.0 for empty input."""
    import math
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / n
        e -= p * math.log2(p)
    return e


def _classify_avmt_signature(
    data: bytes, section_names: set[str]
) -> dict[str, Any] | None:
    """Pattern A-VMT detection (v2.9.1).

    Returns the per-check evidence dict if the binary carries
    the dual-regime handler-table-dispatch signature; returns
    None if the section set has the A-VMT members but the
    file data does not match the entropy / structure pattern
    (i.e. falls through to the generic encrypted-VM
    classifier in rule 1).

    The signature (any 2 of 3 fires → match):
    - The `.xcode` section's first 32 KB has entropy < 4.0
      (the dispatch-table regime).
    - The `.xcode` section's 32 KB chunk starting at
      offset 0x32000 has entropy > 6.0 (the encrypted-
      metadata regime).
    - The first 16 entries of the dispatch table follow
      the big-endian `[u32 id][u32 reserved=0][u64 target]`
      shape (handler_id <= 0xff).
    """
    sections = _pe_section_offsets(data)
    xcode = sections.get(".xcode")
    if xcode is None:
        return None
    raw_off, raw_size = xcode
    if raw_size < 0x40000:
        # Need at least 256 KB to do the dual-regime probe
        # (32 KB head + 32 KB encrypted chunk at 0x32000).
        return None
    # Probe 1: dispatch-table head entropy
    head_chunk = data[raw_off:raw_off + 0x8000]
    head_entropy = _shannon_entropy(head_chunk) if head_chunk else 0.0
    # Probe 2: encrypted-metadata region entropy
    encrypted_off = raw_off + 0x32000
    encrypted_chunk = data[encrypted_off:encrypted_off + 0x8000]
    encrypted_entropy = (
        _shannon_entropy(encrypted_chunk) if encrypted_chunk else 0.0
    )
    # Probe 3: structural dispatch-table check
    struct_ok = False
    import struct as _struct
    try:
        for i in range(min(16, (raw_size // 16))):
            rec = raw_off + i * 16
            if rec + 16 > len(data):
                break
            h, _pad, _target = _struct.unpack(">IIQ", data[rec:rec + 16])
            if _pad != 0 or h > 0xFF:
                struct_ok = False
                break
        else:
            struct_ok = True
    except _struct.error:
        struct_ok = False
    # Match: dispatch table (low entropy) AND encrypted
    # metadata (high entropy). The structural probe is
    # optional but strongly confirms when both fire.
    low_fires = head_entropy < 4.0
    high_fires = encrypted_entropy > 6.0
    if not (low_fires and high_fires):
        return None
    matched = sorted({".arch", ".link", ".xcode", ".rodata"} & section_names)
    return {
        "category": "encrypted-vm-handler-table-dispatch",
        "indicator": (
            "dual-regime signature in .xcode (dispatch table "
            "<4.0 + encrypted metadata >6.0) + handler-table "
            "structure probe"
        ),
        "matched_sections": matched,
        "dispatch_table_head_entropy": round(head_entropy, 3),
        "encrypted_metadata_entropy": round(encrypted_entropy, 3),
        "dispatch_table_struct_probe": struct_ok,
    }


def _elf_section_names(data: bytes) -> set[str]:
    """Return the set of ELF section names."""
    out: set[str] = set()
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return out
    # ELF64 (offset 4 = class), little-endian (offset 4 = EI_DATA)
    is_64 = data[4] == 2
    is_le = data[5] == 1
    if not is_le:
        return out
    # ELF header offsets: e_shoff (section header table offset)
    # differs between 32/64
    if is_64:
        e_shoff = 0x28
        e_shentsize = 0x3A
        e_shnum = 0x3C
        e_shstrndx = 0x3E
        str_size = 8
    else:
        e_shoff = 0x20
        e_shentsize = 0x2E
        e_shnum = 0x30
        e_shstrndx = 0x32
        str_size = 4
    if e_shoff + str_size * 3 > len(data):
        return out
    try:
        sh_off = struct.unpack_from("<Q" if is_64 else "<I", data, e_shoff)[0]
        sh_entsize = struct.unpack_from("<H", data, e_shentsize)[0]
        sh_num = struct.unpack_from("<H", data, e_shnum)[0]
        sh_strndx = struct.unpack_from("<H", data, e_shstrndx)[0]
    except struct.error:
        return out
    if sh_off + sh_entsize * sh_num > len(data):
        return out
    # Read the string table for the section names
    str_table_off = sh_off + sh_strndx * sh_entsize
    if str_table_off + 24 > len(data):
        return out
    try:
        str_sh_offset = struct.unpack_from("<Q" if is_64 else "<I", data, str_table_off + 24)[0]
        str_sh_size = struct.unpack_from("<Q" if is_64 else "<I", data, str_table_off + 32)[0]
    except struct.error:
        return out
    if str_sh_offset + str_sh_size > len(data):
        return out
    string_table = data[str_sh_offset:str_sh_offset + str_sh_size]
    for i in range(sh_num):
        base = sh_off + i * sh_entsize
        if base + 24 > len(data):
            break
        try:
            sh_name_idx = struct.unpack_from("<I", data, base + 0)[0]
        except struct.error:
            break
        if sh_name_idx >= len(string_table):
            continue
        end = string_table.find(b"\x00", sh_name_idx)
        if end < 0:
            end = len(string_table)
        try:
            name = string_table[sh_name_idx:end].decode("ascii")
        except UnicodeDecodeError:
            continue
        if name:
            out.add("." + name if not name.startswith(".") else name)
    return out
