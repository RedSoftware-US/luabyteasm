# luabyteasm v0.1.0

**A minimal Lua 5.2 bytecode assembler**

---

## Overview

luabyteasm converts a human-readable text representation of Lua 5.2 bytecode into a valid binary `.luac` file. It is useful for:

* Generating Lua bytecode programmatically.
* Experimenting with custom assembly-like chunks.
* Testing or fuzzing Lua interpreters with controlled bytecode.

luabyteasm does not parse Lua source code. Instead, it assembles text instructions, constants, headers, and metadata directly into the binary format expected by the Lua 5.2 virtual machine.

---

## Key Principles

* **Direct control**: Exposes Lua’s internal bytecode format, instruction encoding, and constant layout.
* **Deterministic output**: Assembly produces exact `.luac` binaries conforming to the Lua 5.2 specification.
* **Minimal abstraction**: The input format resembles an assembler: `.fn`, `.const`, `.instruction`, `.upvalue`, etc.

---

## Assembly Format

The assembly syntax is line-oriented. Sections begin with directives:

* `.fn [@source]` — start a function prototype. Optional `@file.lua` sets the `source`.
* `.endfn` — end the current function prototype.
* `.header` — function header fields.
* `.instruction` — a sequence of Lua VM instructions.
* `.const` — constants (nil, booleans, numbers, or strings).
* `.upvalue` — upvalue definitions.
* `.locals` and `.lineinfo` — optional debug metadata.

---

### Example: Hello World

```lua
local hello_world_chunk = [[
    .fn @hello.lua
    .header
    numparams=0, is_vararg=1, maxstack=3
    .instruction
    GETTABUP  R0 U0 K0
    LOADK     R1 K1
    CALL      R0 2 1
    RETURN    R0 1
    .const
    K0 = "print"
    K1 = "Hello, World!"
    .upvalue
    U0 = L0 R0
    .endfn
]]

local bytecode = lbasm.assemble(hello_world_chunk)
```

Produces a valid Lua 5.2 `.luac` file that prints “Hello, World!”.

---

## Instruction Encoding

luabyteasm supports all Lua 5.2 opcodes, grouped by mode:

* **iABC** — three arguments (e.g. `MOVE A B C`).
* **iABx** — two arguments, with `Bx` (18 bits).
* **iAsBx** — two arguments, with signed `sBx` (loop offsets).
* **iAx** — extended constants (not yet implemented).

Arguments are parsed as:

* `R<num>` — register.
* `K<num>` — constant.
* `U<num>` — upvalue.
* Literal numbers or booleans where appropriate.

---

## Constants

Constants are defined in the `.const` section:

```
K0 = "string"
K1 = 42
K2 = true
K3 = nil
```

Types supported:

* `nil`
* `boolean`
* `number`
* `string` (quoted)

---

## Upvalues

Upvalues are declared in the `.upvalue` section:

```
U0 = L0 R0
```

* `U<num>` — upvalue index.
* `L<num>` — instack flag (0/1).
* `R<num>` — register index.

---

## Header Fields

Within `.header`, you may set:

* `linedefined` (int)
* `lastlinedefined` (int)
* `numparams` (int)
* `is_vararg` / `vararg` (bool as 0/1)
* `maxstack` (int)
* `source` (string)

---

## Runtime Behavior

* `assemble(chunk: string)` returns the assembled binary bytecode (`string`).
* Bytecode can be written to disk (`hello.luac`) or loaded dynamically with `loadstring`.
* Debug mode (`DEBUG = true`) prints instruction encoding, constants, and hex dumps.

---

## Status & Roadmap

**Current status:**

* Supports all Lua 5.2 instructions.
* Supports constants, headers, upvalues, nested functions.
* Generates valid `.luac` headers and function prototypes.

**Planned improvements:**

* `.locals` and `.lineinfo` syntax for full debug symbol support.
* Support for extended `iAx` instructions (LOADKX).
* Better error reporting and diagnostics.
* Optional disassembler to round-trip bytecode to text.

---

## Compatibility & Platform

* Targets **Lua 5.2** bytecode format.
* Tested on stock Lua 5.2 interpreter.
* Output may not be compatible with LuaJIT or Lua 5.1/5.3 due to differing instruction sets.

---

## License

luabyteasm is released under the Apache 2.0 License.

---

**Contact:**

* GitHub: `https://github.com/RedSoftware-US/NexCore`
* Discord: `red.software`
* Email: `redsoftware-us@proton.me`

---

## FAQ (brief)

**Q: Does luabyteasm compile Lua source?**
A: No. It only assembles text-based bytecode definitions. Use `luac` to compile Lua source.

**Q: Which Lua versions are supported?**
A: Only Lua 5.2 bytecode format is currently supported.

**Q: Can I disassemble `.luac` back to text?**
A: Not yet. I may include a matching disassembler in the future.
