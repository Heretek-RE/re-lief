"""Capstone-backed disassembly helpers.

LIEF can hold disassembled bytes; this module provides a thin wrapper
around the optional LIEF disassembler (LIEF has a built-in disassembler
when ``lief.disassembler`` is available) and falls back to raw
``capstone`` for any architecture LIEF doesn't disassemble.
"""

from __future__ import annotations

import capstone
import lief

# Map LIEF architectures to capstone (arch, mode) tuples.
# Used as a fallback when LIEF's built-in disassembler is unavailable.
_ARCH_MAP: dict[tuple[int, int], tuple[int, int]] = {
    # (lief arch, bits) → (cs_arch, cs_mode)
    # Best-effort — capstone defaults handle most modern ISAs.
}


def _lief_arch_to_capstone(arch: int) -> tuple[int, int]:
    """Best-effort mapping from LIEF's arch enum to capstone's.

    LIEF doesn't expose a public arch enum that always maps cleanly,
    so we use the generic "auto" disassembly from capstone for
    unknown architectures. For x86/x64/ARM/AArch64 we have explicit
    mappings.
    """
    # These are best-effort — when in doubt, let capstone auto-detect
    # by trying CS_ARCH_ALL. We try a few common cases first.
    name = str(arch).upper()
    if "X86_64" in name or "AMD64" in name:
        return (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if "I386" in name or "X86" in name:
        return (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    if "AARCH64" in name or "ARM64" in name:
        return (capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
    if "ARM" in name:
        return (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    if "MIPS" in name:
        return (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN)
    if "PPC" in name or "POWERPC" in name:
        return (capstone.CS_ARCH_PPC, capstone.CS_MODE_BIG_ENDIAN)
    if "RISCV" in name:
        return (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64)
    # Fallback: x86-64 — better than nothing.
    return (capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def disasm_bytes(
    code: bytes,
    base_address: int,
    arch_hint: int | None = None,
    max_insns: int = 500,
) -> list[dict[str, object]]:
    """Disassemble *code* bytes with capstone, returning a list of instruction dicts.

    Each entry has ``address``, ``mnemonic``, ``operands``, ``bytes``, ``size``.
    """
    if arch_hint is not None:
        cs_arch, cs_mode = _lief_arch_to_capstone(arch_hint)
    else:
        cs_arch, cs_mode = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = False  # mirror v1 backend
    out: list[dict[str, object]] = []
    for insn in md.disasm(code, base_address):
        out.append({
            "address": int(insn.address),
            "mnemonic": insn.mnemonic,
            "operands": insn.op_str,
            "bytes": insn.bytes.hex(),
            "size": insn.size,
        })
        if len(out) >= max_insns:
            out.append({"truncated": True})
            break
    return out


def disasm_from_path(
    path: str,
    section_name: str,
    offset: int = 0,
    size: int = 256,
    max_insns: int = 500,
) -> dict[str, object]:
    """Load *path*, find *section_name*, disassemble from *offset* for *size* bytes."""
    binary = lief.parse(path)
    if binary is None:
        raise ValueError(f"Could not parse {path}")
    target = section_name.encode("ascii") if isinstance(section_name, str) else section_name
    for section in binary.sections:
        if section.name.encode("ascii").rstrip(b"\x00") == target.rstrip(b"\x00"):
            data = bytes(section.content)
            available = len(data) - offset
            if available <= 0:
                raise ValueError(
                    f"offset {offset} is beyond section {section_name!r} (size={len(data)})"
                )
            actual_size = min(size, available)
            code = data[offset : offset + actual_size]
            base = int(section.virtual_address) + offset
            return {
                "section_name": section.name,
                "architecture": str(binary.format),
                "offset": offset,
                "bytes_count": len(code),
                "instructions": disasm_bytes(
                    code, base, arch_hint=int(binary.header.machine if hasattr(binary, "header") else 0), max_insns=max_insns
                ),
            }
    raise ValueError(f"section {section_name!r} not found in {path}")
