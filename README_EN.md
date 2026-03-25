English | [中文](README.md)

# Reverse Engineering Skills for Claude Code

A Claude Code plugin marketplace providing reverse engineering skills.

**Designed to work with [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP)** - Export IDA decompilation results, then analyze with Claude Code.

## Workflow

1. **Export from IDA** using [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP) plugin (`Ctrl-Shift-E`)
2. **Open exported directory** with Claude Code
3. **Use skills** to analyze symbols and structures

### Exported Directory Structure (by IDA-NO-MCP)

```
export_dir/
├── decompile/              # Decompiled C code
│   ├── 0x401000.c          # One file per function, named by hex address
│   ├── 0x401234.c
│   └── ...
├── decompile_failed.txt    # Failed decompilation list
├── decompile_skipped.txt   # Skipped functions list
├── strings.txt             # String table (address, length, type, content)
├── imports.txt             # Import table (address:function_name)
├── exports.txt             # Export table (address:function_name)
└── memory/                 # Memory hexdump (1MB chunks)
```

### Function File Format (decompile/*.c)

```c
/*
 * func-name: sub_401000
 * func-address: 0x401000
 * callers: 0x402000, 0x403000    // Who calls this function
 * callees: 0x404000, 0x405000    // What this function calls
 */

int __fastcall sub_401000(int a1, int a2)
{
    // Decompiled code...
}
```

## Skills Included

| Skill | Description |
|-------|-------------|
| `/reverse-engineering:rev-symbol` | Analyze function symbols from exports/imports or decompiled code |
| `/reverse-engineering:rev-struct` | Reconstruct data structures from decompiled functions |

## Installation

### Claude
1. Add the Marketplace

```bash
# From GitHub
/plugin marketplace add pandaos/reverse-skills

# From local path (for development)
/plugin marketplace add /path/to/reverse-skills
```

2. Install the Plugin

### Cursor

1. Download source code on github code page.

2. unzip the source code and locate the `reverse-engineering` folder. Put it into `C:\User\<username>\.cursor` (`<username>` is the local user's account name). Then delete the  `.claude-plugin` folder inside of it.

the final folder structure is:

```
.
├── reverse-engineering
│   └── skills
│       ├── rev-struct
│       │   └── SKILL.md
│       └── rev-symbol
│           └── SKILL.md
```

4. restart the cursor.


```bash
/plugin install reverse-engineering@reverse-engineering-skills
```

## Usage

### Analyze a Symbol

```
/reverse-engineering:rev-symbol sub_401000
```

### Reconstruct a Structure

```
/reverse-engineering:rev-struct sub_401000
```

## Directory Structure

```
reverse-skills/
├── .claude-plugin/
│   └── marketplace.json          # Marketplace catalog
├── plugins/
│   └── reverse-engineering/
│       ├── .claude-plugin/
│       │   └── plugin.json       # Plugin manifest
│       └── skills/
│           ├── rev-symbol/
│           │   └── SKILL.md      # Symbol analysis skill
│           └── rev-struct/
│               └── SKILL.md      # Structure reconstruction skill
└── README.md
```

## Development

### Validate the Marketplace

```bash
claude plugin validate .
```

Or within Claude Code:

```
/plugin validate .
```

### Test Locally

```bash
/plugin marketplace add ./reverse-skills
/plugin install reverse-engineering@reverse-engineering-skills
```

## Adding More Skills

1. Create a new directory under `plugins/reverse-engineering/skills/`
2. Add a `SKILL.md` file with the skill definition
3. Update version in `plugin.json` if needed

## License

MIT
