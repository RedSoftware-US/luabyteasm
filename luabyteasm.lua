--[[
luabyteasm.lua

Copyright 2025 SpartanSoftware

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]

local band, bor, bxor, bnot, lshift, rshift =
    bit32.band, bit32.bor, bit32.bxor, bit32.bnot, bit32.lshift, bit32.rshift

local OP_MODES = {
    iABC = 1, iABx = 2, iAsBx = 3, iAx = 4
}

local OPCODES = {

    MOVE = {0, OP_MODES.iABC, "r", "r", nil},
    LOADK = {1, OP_MODES.iABx, "r", "k", nil},
    LOADKX = {2, OP_MODES.iABC, "r", nil, nil},
    LOADBOOL = {3, OP_MODES.iABC, "r", "b", "b"},
    LOADNIL = {4, OP_MODES.iABC, "r", "r", nil},
    GETUPVAL = {5, OP_MODES.iABC, "r", "u", nil},
    GETTABUP = {6, OP_MODES.iABC, "r", "u", "rk"},
    GETTABLE = {7, OP_MODES.iABC, "r", "r", "rk"},
    SETTABUP = {8, OP_MODES.iABC, "u", "rk", "rk"},
    SETUPVAL = {9, OP_MODES.iABC, "r", "u", nil},
    SETTABLE = {10, OP_MODES.iABC, "r", "rk", "rk"},
    NEWTABLE = {11, OP_MODES.iABC, "r", "i", "i"},
    SELF = {12, OP_MODES.iABC, "r", "r", "rk"},
    ADD = {13, OP_MODES.iABC, "r", "rk", "rk"},
    SUB = {14, OP_MODES.iABC, "r", "rk", "rk"},
    MUL = {15, OP_MODES.iABC, "r", "rk", "rk"},
    DIV = {16, OP_MODES.iABC, "r", "rk", "rk"},
    MOD = {17, OP_MODES.iABC, "r", "rk", "rk"},
    POW = {18, OP_MODES.iABC, "r", "rk", "rk"},
    UNM = {19, OP_MODES.iABC, "r", "r", nil},
    NOT = {20, OP_MODES.iABC, "r", "r", nil},
    LEN = {21, OP_MODES.iABC, "r", "r", nil},
    CONCAT = {22, OP_MODES.iABC, "r", "r", "r"},
    JMP = {23, OP_MODES.iAsBx, nil, "s", nil},
    EQ = {24, OP_MODES.iABC, "b", "rk", "rk"},
    LT = {25, OP_MODES.iABC, "b", "rk", "rk"},
    LE = {26, OP_MODES.iABC, "b", "rk", "rk"},
    TEST = {27, OP_MODES.iABC, "r", "b", nil},
    TESTSET = {28, OP_MODES.iABC, "r", "r", "b"},
    CALL = {29, OP_MODES.iABC, "r", "i", "i"},
    TAILCALL = {30, OP_MODES.iABC, "r", "i", "i"},
    RETURN = {31, OP_MODES.iABC, "r", "i", nil},
    FORLOOP = {32, OP_MODES.iAsBx, "r", "s", nil},
    FORPREP = {33, OP_MODES.iAsBx, "r", "s", nil},
    TFORCALL = {34, OP_MODES.iABC, "r", "i", nil},
    TFORLOOP = {35, OP_MODES.iAsBx, "r", "s", nil},
    SETLIST = {36, OP_MODES.iABC, "r", "i", "i"},
    CLOSURE = {37, OP_MODES.iABx, "r", "p", nil},
    VARARG = {38, OP_MODES.iABC, "r", "i", nil},
    EXTRAARG = {39, OP_MODES.iAx, "i", nil, nil}
}

local OPCODE_NAMES = {}
for name, data in pairs(OPCODES) do
    OPCODE_NAMES[data[1]] = name
end

local LUAC_HEADER = string.char(
    0x1B, 0x4C, 0x75, 0x61,
    0x52,
    0x00,
    0x01,
    0x04,
    0x08,
    0x04,
    0x08,
    0x00
)

local LUAC_DATA = string.char(0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A)

local SIZE_OP = 6
local SIZE_A = 8
local SIZE_B = 9
local SIZE_C = 9
local SIZE_Bx = SIZE_B + SIZE_C
local SIZE_Ax = SIZE_A + SIZE_B + SIZE_C
local MAXARG_sBx = math.floor((2^(SIZE_Bx-1))-1)
local BITRK = lshift(1, (SIZE_B - 1))

local function create_abc(op, a, b, c)

    return bor(lshift(op, 0), lshift(a, 6), lshift(c or 0, 14), lshift(b or 0, 23))
end

local function create_abx(op, a, bc)
    return bor(lshift(op, 0), lshift(a, 6), lshift(bc, 14))
end

local function create_asbx(op, a, sbx)
    return create_abx(op, a, sbx + MAXARG_sBx)
end

local function create_ax(op, ax)
    return bor(lshift(op, 0), lshift(ax, 6))
end

local function parse_register(str)
    if not str then return nil end
    if type(str) ~= "string" then
        error("Expected string for register, got: " .. type(str))
    end
    local num = tonumber(str:match("^R(%d+)$"))
    if not num or num < 0 or num > 255 then
        error("Invalid register format: " .. tostring(str) .. ". Expected format like R0, R1, etc.")
    end
    return num
end

local function parse_upvalue(str)
    if not str then return nil end
    if type(str) ~= "string" then
        error("Expected string for upvalue, got: " .. type(str))
    end
    local num = tonumber(str:match("^U(%d+)$"))
    if not num or num < 0 or num > 255 then
        error("Invalid upvalue format: " .. tostring(str) .. ". Expected format like U0, U1, etc.")
    end
    return num
end

local function parse_constant(str)
    if not str then return nil end
    if type(str) ~= "string" then
        error("Expected string for constant, got: " .. type(str))
    end
    local num = tonumber(str:match("^K(%d+)$"))
    if not num then
        return nil
    end
    if num < 0 or num >= BITRK then
        error("Constant index out of range: " .. num)
    end
    return num + BITRK
end

local function parse_number(str, signed)
    if not str then return nil end
    local num = tonumber(str)
    if not num then
        error("Invalid number: " .. tostring(str))
    end
    if signed then
        if num < -MAXARG_sBx or num > MAXARG_sBx then
            error("Signed value out of range: " .. num)
        end
    else
        if num < 0 or num > (2^SIZE_Bx)-1 then
            error("Unsigned value out of range: " .. num)
        end
    end
    return num
end

local function parse_boolean(str)
    if not str then return nil end
    if str == "true" then return 1 end
    if str == "false" then return 0 end
    error("Invalid boolean: " .. tostring(str))
end

local function parse_proto(str)
    if not str then return nil end
    local num = tonumber(str:match("^P(%d+)$"))
    if not num or num < 0 or num >= BITRK then
        error("Invalid proto index: " .. tostring(str))
    end
    return num
end

local function parse_constant_raw(str)
    if not str then return nil end
    if type(str) ~= "string" then
        error("Expected string for constant, got: " .. type(str))
    end
    local num = tonumber(str:match("^K(%d+)$"))
    if not num then
        return nil
    end
    if num < 0 or num >= BITRK then
        error("Constant index out of range: " .. num)
    end
    return num
end

local function parse_argument(arg, expected_type)
    if not arg then return nil end

    if expected_type == "r" then
        return parse_register(arg)
    elseif expected_type == "u" then
        return parse_upvalue(arg)
    elseif expected_type == "k" then
        return parse_constant_raw(arg)
    elseif expected_type == "rk" then

        local k = parse_constant_raw(arg)
        if k then return k + BITRK end
        return parse_register(arg)
    elseif expected_type == "b" then
        return parse_boolean(arg)
    elseif expected_type == "i" then
        return parse_number(arg)
    elseif expected_type == "s" then
        return parse_number(arg, true)
    elseif expected_type == "p" then
        return parse_proto(arg)
    else
        error("Unknown argument type: " .. tostring(expected_type))
    end
end

local function encode_instruction(opname, args)
    local opdata = OPCODES[opname]
    if not opdata then
        error("Unknown opcode: " .. tostring(opname))
    end

    local opcode, mode = opdata[1], opdata[2]
    local a, b, c

    if mode == OP_MODES.iABC then
        a = opdata[3] and parse_argument(args[1], opdata[3])
        b = opdata[4] and parse_argument(args[2], opdata[4])
        c = opdata[5] and parse_argument(args[3], opdata[5])

        return create_abc(opcode, a or 0, b or 0, c or 0)

    elseif mode == OP_MODES.iABx then
        a = opdata[3] and parse_argument(args[1], opdata[3])
        b = opdata[4] and parse_argument(args[2], opdata[4])

        return create_abx(opcode, a or 0, b or 0)

    elseif mode == OP_MODES.iAsBx then
        a = opdata[3] and parse_argument(args[1], opdata[3])
        b = opdata[4] and parse_argument(args[2], opdata[4])

        return create_asbx(opcode, a or 0, b or 0)

    elseif mode == OP_MODES.iAx then
        a = opdata[3] and parse_argument(args[1], opdata[3])

        return create_ax(opcode, a or 0)
    end

    error("Unknown instruction mode for opcode: " .. opname)
end

local function hexdump(s, maxbytes)
    maxbytes = maxbytes or #s
    local out = {}
    for i = 1, math.min(#s, maxbytes) do
        out[#out+1] = string.format("%02X", s:byte(i))
        if i % 16 == 0 then out[#out+1] = "\n" end
    end
    return table.concat(out, " ")
end

local function new_writer_debug()
    local w = { data = {}, size = 0 }
    local function push_byte(b)
        w.data[#w.data + 1] = string.char(b)
        w.size = w.size + 1
    end
    function w:write_byte(b) push_byte(b) end
    function w:write_int(n, size)
        size = size or 4
        for i = 0, size - 1 do
            push_byte(band(rshift(n, i * 8), 0xFF))
        end
    end
    function w:write_string(s)

        if s == nil then
            self:write_int(0, 8)
            return
        end

        local len = #s

        self:write_int(len + 1, 8)

        for i = 1, len do
            push_byte(s:byte(i))
        end

        push_byte(0)
    end

    function w:write_double(n)
        if string and string.pack then
            local bytes = string.pack("<d", n)
            for i = 1, #bytes do
                self.data[#self.data + 1] = bytes:sub(i, i)
            end
            self.size = self.size + #bytes
            return
        end
        error("string.pack required for IEEE754 double; run Lua with string.pack support")
    end
    function w:get_output() return table.concat(self.data), self.size end
    return w
end

local function write_proto_to_debug(writer, proto)
    print(">>> Serializing proto. source=", proto.source or "@hello.lua")
    local code = proto.code or {}
    local consts = proto.constants or {}
    local protos = proto.protos or {}

    local max_code = #code
    local max_const = 0
    for k in pairs(consts) do if type(k) == "number" and k > max_const then max_const = k end end
    local max_proto = 0
    for k in pairs(protos) do if type(k) == "number" and k > max_proto then max_proto = k end end

    print(string.format(" proto (before write): code=%d const=%d protos=%d upvals=%d",
        max_code, max_const, max_proto, (proto.upvalues and #proto.upvalues) or 0))

    local max_up = 0
    for k in pairs(proto.upvalues or {}) do
        if type(k) == "number" and k > max_up then max_up = k end
    end

    local before = writer.size
    writer:write_string(proto.source or "@hello.lua")
    print(" wrote source string; bytes_written=", writer.size - before)

    before = writer.size
    writer:write_int(proto.linedefined or 0)
    writer:write_int(proto.lastlinedefined or 0)
    writer:write_byte(max_up)
    writer:write_byte(proto.num_params or 0)
    writer:write_byte(proto.is_vararg or 2)
    writer:write_byte(proto.max_stack or 2)
    print(string.format(" wrote header ints/bytes; bytes_written=%d (linedefined=%d,last=%d,nups=%d,numparams=%d,is_vararg=%d,maxstack=%d)",
        writer.size - before, proto.linedefined or 0, proto.lastlinedefined or 0, max_up, proto.num_params or 0, proto.is_vararg or 2, proto.max_stack or 2))

    before = writer.size
    writer:write_int(#code)
    for i, instr in ipairs(code) do
        writer:write_int(instr)
    end
    print(" wrote code: count=", #code, " bytes_written=", writer.size - before)

    before = writer.size
    local max_const = 0
    for k in pairs(consts) do
        if type(k) == "number" and k > max_const then max_const = k end
    end
    writer:write_int(max_const)
    print(" wrote const count (max index)=", max_const)
    for i = 1, max_const do
        local const = consts[i]
        if const == nil then
            writer:write_byte(0)
        elseif type(const) == "string" then
            writer:write_byte(4)
            writer:write_string(const)
        elseif type(const) == "number" then
            writer:write_byte(3)
            writer:write_double(const)
        elseif type(const) == "boolean" then
            writer:write_byte(1)
            writer:write_byte(const and 1 or 0)
        else
            error("Unsupported constant type: " .. type(const))
        end
    end
    print(" wrote constants; bytes_written=", writer.size - before)

    before = writer.size
    local max_proto = 0
    for k in pairs(protos) do if type(k) == "number" and k > max_proto then max_proto = k end end
    writer:write_int(max_proto)
    print(" wrote sub-proto count (max index)=", max_proto)
    for i = 1, max_proto do
        local p = protos[i]
        if not p then error("Encountered nil sub-proto at index " .. i .. "; sub-protos must be contiguous") end
        write_proto_to_debug(writer, p)
    end
    print(" wrote protos; bytes_written=", writer.size - before)

    before = writer.size
    writer:write_int(max_up)
    for i = 1, max_up do
        local uv = proto.upvalues[i] or { instack = 0, index = 0 }
        writer:write_byte(uv.instack or 0)
        writer:write_byte(uv.index or 0)
    end
    print(" wrote upvalues; count=", max_up, " bytes_written=", writer.size - before)

    before = writer.size
    local lineinfo = proto.lineinfo or {}
    writer:write_int(#lineinfo)
    print(" wrote lineinfo count=", #lineinfo, " bytes_written=", writer.size - before)

    before = writer.size
    local locals = proto.locals or {}
    writer:write_int(#locals)
    print(" wrote locals count=", #locals, " bytes_written=", writer.size - before)

    before = writer.size
    local up_names = proto.upvalue_names or {}
    writer:write_int(#up_names)
    for i = 1, #up_names do
        writer:write_string(up_names[i] or "")
    end
    print(" wrote upvalue names count=", #up_names, " bytes_written=", writer.size - before)
end

local function generate_bytecode_debug(proto)
    local body_writer = new_writer_debug()
    write_proto_to_debug(body_writer, proto)
    local proto_body, body_size = body_writer:get_output()

    print("proto body total bytes:", body_size)
    print("proto body hexdump (first 256 bytes):\n", hexdump(proto_body, 256))

    local header = LUAC_HEADER .. LUAC_DATA
    print("header bytes length:", #header)
    local chunk = header .. proto_body
    print("full chunk bytes length:", #chunk)
    print("full chunk hexdump (first 256 bytes):\n", hexdump(chunk, 256))
    return chunk
end

local function test_bytecode_debug(bytecode)
    local func, err = loadstring(bytecode)
    if func then
        print("loadstring succeeded; executing...")
        func()
    else
        print("loadstring failed:", err)
    end
end

local function assemble_lua(chunk)
    local proto = {
        code = {},
        constants = {},
        upvalues = {},
        max_stack = 0
    }

    local current_section = nil
    local max_register = 0

    for line in chunk:gmatch("[^\r\n]+") do
        line = line:match("^%s*(.-)%s*$")
        if line == "" or line:sub(1, 1) == ";" then

        elseif line:sub(1, 1) == "." then

            current_section = line:sub(2):match("^(%S+)")
            if current_section == "endfn" then
                break
            end
        else
            if current_section == "const" then
                local key, value = line:match("^(%S+)%s*=%s*(.+)")
                if key and value then
                    local idx = tonumber(key:match("K(%d+)"))
                    if not idx then
                        error("Invalid constant declaration: " .. line)
                    end

                    if value:sub(1, 1) == '"' and value:sub(-1) == '"' then
                        value = value:sub(2, -2)

                    elseif tonumber(value) then
                        value = tonumber(value)

                    elseif value == "true" then
                        value = true
                    elseif value == "false" then
                        value = false

                    elseif value == "nil" then
                        value = nil
                    end

                    proto.constants[idx + 1] = value
                end
            elseif current_section == "upvalue" then
                local key, instack, idx = line:match("^(U%d+)%s*=%s*L(%d+)%s+R(%d+)")
                if key and instack and idx then
                    local uv_idx = tonumber(key:match("U(%d+)"))
                    proto.upvalues[uv_idx + 1] = {
                        instack = tonumber(instack),
                        index = tonumber(idx)
                    }
                end
            elseif current_section == "instruction" then
                local parts = {}
                for part in line:gmatch("%S+") do
                    parts[#parts + 1] = part
                end

                if #parts > 0 then
                    local opname = table.remove(parts, 1)
                    local instruction = encode_instruction(opname, parts)
                    proto.code[#proto.code + 1] = instruction

                    for _, part in ipairs(parts) do
                        if part:match("^R%d+$") then
                            local reg = parse_register(part)
                            if reg and reg > max_register then
                                max_register = reg
                            end
                        end
                    end
                end
            end
        end
    end

    proto.max_stack = max_register + 1

    return generate_bytecode_debug(proto)
end

local hello_world_chunk = [[
.fn(R0)
.instruction
GETTABUP  R0 U0 K0       ; R0 = _ENV["print"]
LOADK     R1 K1          ; R1 = "Hello, World!"
CALL      R0 2 1         ; print(R1)
RETURN    R0 1           ; return
.const
K0 = "print"
K1 = "Hello, World!"
.upvalue
U0 = L0 R0               ; U0 = _ENV (upvalue 0)
.endfn
]]

local bytecode = assemble_lua(hello_world_chunk)

local file = io.open("hello.luac", "wb")
if file then
    file:write(bytecode)
    file:close()
    print("Hello World bytecode written to hello.luac")
else
    print("Error: Could not open file for writing")
end

local f = io.open("hello.luac","rb"); local s = f:read(48); f:close()
for i=1,#s do io.write(string.format("%02X ", s:byte(i))) end; io.write("\n")

local function test_bytecode()
    local func, err = loadstring(bytecode)
    if func then
        print("Executing compiled bytecode:")
        func()
    else
        print("Error loading bytecode:", err)
    end
end

test_bytecode()

return {
    assemble = assemble_lua,
    OPCODES = OPCODES,
    OPCODE_NAMES = OPCODE_NAMES
}
