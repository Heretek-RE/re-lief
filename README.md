# re-lief

MCP server exposing [LIEF](https://lief-project.github.io/) (Library to Instrument Executable Formats) for cross-format binary analysis. Handles **PE, ELF, MachO, COFF, DEX, ART, OAT** in a single, normalized API.

## Why

LIEF is the Python successor to `pefile` — same data for PE, plus ELF, MachO, DEX, ART, and OAT. It also handles DWARF/PDB debug info, ObjC metadata, the Dyld Shared Cache, and (optionally) has a built-in disassembler/assembler.

This server is the **foundation** of the RE-AI plugin: it works without any system tools installed (no rizin, no gdb, no anything), is pure Python, and runs in-process.

## Tools

| Tool | What it does |
|---|---|
| `check_lief` | Health check — return LIEF version, supported formats |
| `parse_binary` | Auto-detect format and return normalized header + high-level structure |
| `get_sections` | Section list with permissions (R/W/X), virtual vs raw size, entropy |
| `get_imports_exports` | Symbol-level import/export tables (per format) |
| `get_authenticode` | PE signature details (Win) |
| `get_overlay` | Appended data after the last section |
| `list_dex_classes` | Android DEX class list |
| `list_dex_methods` | Methods of a DEX class |
| `list_oat_art` | Android OAT/ART method list |
| `disasm_capstone` | Capstone disassembly (works for any LIEF-parsed binary) |
| `extract_strings` | ASCII + UTF-16LE string extraction with section awareness |
| `categorize_strings` | ASCII + UTF-16LE string extraction, section-aware, bucketed into keyword categories from `data/drm-indicators.yaml::string_categories`. Superset of `extract_strings`. |
| `get_imphash` | PE import hash (MD5 of normalized import table) |
| `normalize_for_diff` | Produce a structural snapshot suitable for diffing two binaries |

## Install

This server is part of the RE-AI plugin. The plugin's `install.sh` / `install.bat` installs it as part of the standard flow.

To install standalone:

```bash
pip install -e ./servers/re-lief
```

## Run

```bash
re-lief                          # stdio transport (default for MCP)
python -m re_lief                # equivalent
```

## Format support

LIEF auto-detects the format and exposes a polyglot API. Most tools return results shaped by format:

- **PE** (`.exe`, `.dll`, `.sys`): full sections, imports/exports, imphash, Authenticode, resources, exceptions, TLS, debug info (PDB path)
- **ELF** (Linux binaries, .so, kernel modules): sections, segments (program headers), dynamic symbols, RELRO, BIND_NOW, NX, PIE, RPATH/RUNPATH, SONAME, dynamic libs
- **MachO** (macOS/iOS binaries, .dylib, frameworks): load commands, segments, LC_BUILD_VERSION, code signature, dyld info, ObjC metadata
- **DEX** (Android Dalvik): class list with FQN, method list per class, string pool
- **OAT/ART** (Android runtime): method list with class/method indices, vdex references
- **COFF** (Windows object files, EFI): sections, symbols, relocations

## Deprecation of pefile

If you're familiar with the v1 `re-ai` repo, this server **supersedes** the old pefile-based code. The string-extraction algorithm (ASCII + UTF-16LE) and imphash logic were ported from `backend/analysis/native.py`; the rest of the API is LIEF-native and works for all formats.

## Categorization vocabulary

`categorize_strings` reads its 11 keyword categories from
`data/drm-indicators.yaml::string_categories` at MCP-server load
time. The `anti_debug` and `hwid` categories **inherit** their
keyword lists from
`drm-indicators.yaml::anti_debug_indicators.checks[].name` and
`hwid_apis.high_signal[].api` via a `seed_from:` YAML pointer —
when a future agent adds a new HWID API to `hwid_apis.high_signal`,
the categorizer picks it up automatically on next reload. The
other 9 categories have their keyword lists inline in the YAML
under `string_categories.categories[].keywords`.

This makes the categorizer *idempotent* with the catalog: the
YAML is the single source of truth for both the indicator set
that `re-drm-fingerprint` reads and the keyword set that the
categorizer reads. Both the static analysis and the string
analysis will give consistent answers.

On large binaries (>100 MB, e.g. a Unity IL2CPP `GameAssembly.dll`
wrapped by an encrypted-VM bytecode interpreter), pass
`skip_sections=[".idata", ".xtls", ".xpdata", ".udata", ".xdata",
".didata", ".ecode", ".00cfg"]` to skip the encrypted-VM
bytecode regions. Note: on the bundled IL2CPP target sample,
the import-table strings live *inside* those sections,
so skipping them blinds the categorizer to the imports. Use
`skip_sections` for memory-bound runs; use the full section walk
for completeness.
