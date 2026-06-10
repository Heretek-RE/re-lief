# re-lief

MCP server exposing LIEF (Library to Instrument Executable Formats) for cross-format binary analysis: PE, ELF, MachO, COFF, DEX, ART.

Version: 0.1.0 | License: MIT

## Structure

```
re-lief/
  pyproject.toml                    # build config (setuptools, mcp[cli] + deps)
  src/re_lief/
    __init__.py
    __main__.py                     # entry: from server import main; main()
    server.py                       # FastMCP app with @mcp.tool() functions
  README.md
  LICENSE
  SECURITY.md


```

## Build

```bash
pip install -e .                    # install with deps
re-lief                         # start MCP server on stdio
```



## Tools

This server exposes these MCP tools: `check_lief,parse_binary,get_sections,get_imports_exports,get_imphash,get_overlay,get_authenticode,get_debug_directory,list_dex_classes,list_dex_methods,list_oat_art,disasm_capstone,extract_strings,categorize_strings,normalize_for_diff,scan_anti_analysis_primitives,classify_native_protection`

## Usage (standalone)

Register this server in your `.mcp.json`:

```json
{
  "mcpServers": {
    "re-lief": {
      "command": "uv",
      "args": ["--directory", "/path/to/re-lief", "run", "re-lief"]
    }
  }
}
```

Or use via the [RE-AI agent-space](https://github.com/Heretek-RE/RE-AI): `./install.sh` clones all servers at pinned versions.
