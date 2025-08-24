local struct = require("struct")

local DEBUG = true
local function dprint(...) if DEBUG then print("[DEBUG]", ...) end end

local band, bor, bxor, bnot, lshift, rshift =
  bit32.band, bit32.bor, bit32.bxor, bit32.bnot, bit32.lshift, bit32.rshift

local OP_MODES = { iABC=0, iABx=1, iAsBx=2, iAx=3 }

local OPCODES = {
    MOVE={0,OP_MODES.iABC}, LOADK={1,OP_MODES.iABx}, LOADKX={2,OP_MODES.iABC},
    LOADBOOL={3,OP_MODES.iABC}, LOADNIL={4,OP_MODES.iABC}, GETUPVAL={5,OP_MODES.iABC},
    GETTABUP={6,OP_MODES.iABC}, GETTABLE={7,OP_MODES.iABC}, SETTABUP={8,OP_MODES.iABC},
    SETUPVAL={9,OP_MODES.iABC}, SETTABLE={10,OP_MODES.iABC}, NEWTABLE={11,OP_MODES.iABC},
    SELF={12,OP_MODES.iABC}, ADD={13,OP_MODES.iABC}, SUB={14,OP_MODES.iABC},
    MUL={15,OP_MODES.iABC}, DIV={16,OP_MODES.iABC}, MOD={17,OP_MODES.iABC},
    POW={18,OP_MODES.iABC}, UNM={19,OP_MODES.iABC}, NOT={20,OP_MODES.iABC},
    LEN={21,OP_MODES.iABC}, CONCAT={22,OP_MODES.iABC}, JMP={23,OP_MODES.iAsBx},
    EQ={24,OP_MODES.iABC}, LT={25,OP_MODES.iABC}, LE={26,OP_MODES.iABC},
    TEST={27,OP_MODES.iABC}, TESTSET={28,OP_MODES.iABC}, CALL={29,OP_MODES.iABC},
    TAILCALL={30,OP_MODES.iABC}, RETURN={31,OP_MODES.iABC}, FORLOOP={32,OP_MODES.iAsBx},
    FORPREP={33,OP_MODES.iAsBx}, TFORCALL={34,OP_MODES.iABC}, TFORLOOP={35,OP_MODES.iAsBx},
    SETLIST={36,OP_MODES.iABC}, CLOSURE={37,OP_MODES.iABx}, VARARG={38,OP_MODES.iABC}
}

local OPCODE_NAMES = {}
for name,data in pairs(OPCODES) do OPCODE_NAMES[data[1]]=name end

-- Lua 5.2 instruction format: 32-bit instructions
-- bits 0-5: opcode (6 bits)
-- bits 6-13: A (8 bits)
-- bits 14-22: C (9 bits)
-- bits 23-31: B (9 bits)
-- For Bx mode: bits 14-31 (18 bits)
-- For sBx mode: signed Bx with bias

local SIZE_OP, SIZE_A, SIZE_B, SIZE_C = 6, 8, 9, 9
local SIZE_Bx = SIZE_B + SIZE_C -- 18
local MAXARG_Bx = lshift(1, SIZE_Bx) - 1
local MAXARG_sBx = rshift(MAXARG_Bx, 1)
local MAXARG_A = lshift(1, SIZE_A) - 1
local MAXARG_B = lshift(1, SIZE_B) - 1
local MAXARG_C = lshift(1, SIZE_C) - 1

local BITRK = lshift(1, SIZE_B - 1)

local function create_abc(op, a, b, c)
    return bor(
        band(op, 0x3F),
        lshift(band(a or 0, 0xFF), 6),
        lshift(band(c or 0, 0x1FF), 14),
        lshift(band(b or 0, 0x1FF), 23)
    )
end

local function create_abx(op, a, bx)
    return bor(
        band(op, 0x3F),
        lshift(band(a or 0, 0xFF), 6),
        lshift(band(bx or 0, 0x3FFFF), 14)
    )
end

local function create_asbx(op, a, sbx)
    local bx = (sbx or 0) + MAXARG_sBx
    return create_abx(op, a, bx)
end


local function parse_register(str)
    local num = tonumber(str:match("^R(%d+)$"))
    if not num or num < 0 or num > MAXARG_A then
        error("Invalid register " .. tostring(str))
    end
    return num
end

local function parse_upvalue(str)
    local num = tonumber(str:match("^U(%d+)$"))
    if not num or num < 0 or num > MAXARG_A then
        error("Invalid upvalue " .. tostring(str))
    end
    return num
end

local function parse_constant(str)
    local num = tonumber(str:match("^K(%d+)$"))
    if not num then return nil end
    if num < 0 or num >= BITRK then
        error("Constant index out of range: " .. num)
    end
    return num + BITRK
end

local function parse_constant_raw(str)
    local num = tonumber(str:match("^K(%d+)$"))
    if not num then return nil end
    return num
end

local function parse_rk(arg)
    return parse_constant(arg) or parse_register(arg)
end

local function parse_argument(arg, pos, opname)
    if not arg then return 0 end

    if opname == "MOVE" then
        return parse_register(arg)
    elseif opname == "LOADK" or opname == "LOADKX" then
        if pos == 1 then return parse_register(arg)
        elseif pos == 2 then return parse_constant_raw(arg) end
    elseif opname == "LOADBOOL" then
        if pos == 1 then return parse_register(arg)
        elseif pos == 2 or pos == 3 then return (arg == "true" and 1) or 0 end
    elseif opname == "LOADNIL" then
        return parse_register(arg)
    elseif opname == "GETUPVAL" or opname == "SETUPVAL" then
        if pos == 1 then return parse_register(arg)
        elseif pos == 2 then return parse_upvalue(arg) end
    elseif opname == "GETTABUP" or opname == "SETTABUP" then
        if pos == 1 then return parse_register(arg)
        elseif pos == 2 then return parse_upvalue(arg)
        elseif pos == 3 then return parse_rk(arg) end
    elseif opname == "CALL" or opname == "TAILCALL" or opname == "RETURN" then
        if pos == 1 then return parse_register(arg)
        else return tonumber(arg) or 0 end
    elseif opname == "SETLIST" then
        if pos == 1 then return parse_register(arg)
        else return tonumber(arg) or 0 end
    elseif opname == "NEWTABLE" then
        if pos == 1 then return parse_register(arg)
        else return tonumber(arg) or 0 end
    elseif opname == "VARARG" then
        if pos == 1 then return parse_register(arg)
        elseif pos == 2 then return tonumber(arg) or 0 end
    elseif opname == "TFORCALL" then
        if pos == 1 then return parse_register(arg)
        elseif pos == 2 then return tonumber(arg) or 0 end
    elseif opname == "JMP" or opname == "FORLOOP" or opname == "FORPREP" or opname == "TFORLOOP" then
        if pos == 1 then return parse_register(arg)
        elseif pos == 2 then return tonumber(arg) or 0 end
    elseif opname:match("^GET") or opname:match("^SET") or opname == "SELF" then
        if pos == 1 then return parse_register(arg)
        else return parse_rk(arg) end
    elseif opname:match("^[A-Z]+$") then
        local rk_val = parse_rk(arg)
        if rk_val then return rk_val end
        return tonumber(arg) or 0
    end

    return tonumber(arg) or 0
end

local function encode_instruction(opname, args)
    local opdata = OPCODES[opname]
    if not opdata then error("Unknown opcode: " .. tostring(opname)) end

    local opcode, mode = opdata[1], opdata[2]

    if mode == OP_MODES.iABC then
        local a = parse_argument(args[1], 1, opname)
        local b = parse_argument(args[2], 2, opname)
        local c = parse_argument(args[3], 3, opname)
        return create_abc(opcode, a, b, c)
    elseif mode == OP_MODES.iABx then
        local a = parse_argument(args[1], 1, opname)
        local bx = parse_argument(args[2], 2, opname)
        return create_abx(opcode, a, bx)
    elseif mode == OP_MODES.iAsBx then
        local a = parse_argument(args[1], 1, opname)
        local sbx = tonumber(args[2]) or 0
        return create_asbx(opcode, a, sbx)
    else
        error("Unknown instruction mode for opcode: " .. opname)
    end
end

local function new_writer(opts)
    opts = opts or {}
    local int_size = opts.int_size or 4
    local size_t_size = opts.size_t_size or 8
    local instr_size = opts.instr_size or 4
    local number_size = opts.number_size or 8
    local little_endian = opts.little_endian ~= false

    local w = {data = {}, size = 0}

    local function push_byte(b)
        w.data[#w.data + 1] = string.char(band(b, 0xFF))
        w.size = w.size + 1
    end

    function w:write_raw_bytes(s)
        w.data[#w.data + 1] = s
        w.size = w.size + #s
    end

    local function write_uint_le(n, bytes)
        for i = 0, bytes - 1 do
            push_byte(band(rshift(n, i * 8), 0xFF))
        end
    end

    local function write_uint_be(n, bytes)
        for i = bytes - 1, 0, -1 do
            push_byte(band(rshift(n, i * 8), 0xFF))
        end
    end

    function w:write_int(n, size)
        size = size or int_size
        if little_endian then
            write_uint_le(n, size)
        else
            write_uint_be(n, size)
        end
    end

    function w:write_size_t(n)
        if little_endian then
            write_uint_le(n, size_t_size)
        else
            write_uint_be(n, size_t_size)
        end
    end

    function w:write_instruction(n)
        if little_endian then
            write_uint_le(n, instr_size)
        else
            write_uint_be(n, instr_size)
        end
    end

    function w:write_byte(b) push_byte(b) end

    function w:write_string(s)
        dprint("Writing string:", s and (#s .. " chars") or "empty")
        if s == nil or s == "" then
            self:write_size_t(0)
            return
        end
        local len = #s
        self:write_size_t(len + 1)
        self:write_raw_bytes(s)
        push_byte(0)
    end

    function w:write_number(n)
        local bytes
        if little_endian then
            bytes = struct.pack("<d", n)
        else
            bytes = struct.pack(">d", n)
        end
        self:write_raw_bytes(bytes)
    end

    function w:get_output()
        return table.concat(self.data), self.size
    end

    return w
end

local function make_luac_header(opts)
    opts = opts or {}
    local is_little = opts.little_endian ~= false
    local sizeof_int = opts.sizeof_int or 4
    local sizeof_size_t = opts.sizeof_size_t or 8
    local sizeof_instruction = opts.sizeof_instruction or 4
    local sizeof_lua_number = opts.sizeof_lua_number or 8
    local lua_number_is_integral = opts.lua_number_is_integral and 1 or 0

    local out = {}
    out[#out + 1] = string.char(0x1B, string.byte("L"), string.byte("u"), string.byte("a"))
    out[#out + 1] = string.char(0x52, 0)
    out[#out + 1] = string.char(is_little and 1 or 0)           -- endianness
    out[#out + 1] = string.char(sizeof_int)                     -- sizeof(int)
    out[#out + 1] = string.char(sizeof_size_t)                  -- sizeof(size_t)
    out[#out + 1] = string.char(sizeof_instruction)             -- sizeof(Instruction)
    out[#out + 1] = string.char(sizeof_lua_number)              -- sizeof(lua_Number)
    out[#out + 1] = string.char(lua_number_is_integral)         -- lua_Number is integral
    out[#out + 1] = string.char(0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A)

    return table.concat(out)
end

local LUA_TNIL = 0
local LUA_TBOOLEAN = 1
local LUA_TNUMBER = 3
local LUA_TSTRING = 4

local function write_proto(writer, proto)
    dprint("Writing proto")

    writer:write_int(proto.linedefined or 0)
    writer:write_int(proto.lastlinedefined or 0)
    writer:write_byte(proto.num_params or 0)
    writer:write_byte(proto.is_vararg or 0)
    writer:write_byte(proto.max_stack or 2)

    local code = proto.code or {}
    dprint("Writing", #code, "instructions")
    writer:write_int(#code)
    for i = 1, #code do
        dprint("Instruction", i, ":", code[i])
        writer:write_instruction(code[i])
    end

    local consts = proto.constants or {}
    dprint("Writing", #consts, "constants")
    writer:write_int(#consts)
    for i = 1, #consts do
        local v = consts[i]
        dprint("Constant", i, ":", v, type(v))
        if v == nil then
            writer:write_byte(LUA_TNIL)
        else
            local t = type(v)
            if t == "boolean" then
                writer:write_byte(LUA_TBOOLEAN)
                writer:write_byte(v and 1 or 0)
            elseif t == "number" then
                writer:write_byte(LUA_TNUMBER)
                writer:write_number(v)
            elseif t == "string" then
                writer:write_byte(LUA_TSTRING)
                writer:write_string(v)
            else
                error("Unsupported constant type: " .. t)
            end
        end
    end

    local protos = proto.protos or {}
    dprint("Writing", #protos, "child protos")
    writer:write_int(#protos)
    for i = 1, #protos do
        dprint("Writing child proto", i)
        write_proto(writer, protos[i])
    end

    local ups = proto.upvalues or {}
    dprint("Writing", #ups, "upvalues")
    writer:write_int(#ups)
    for i = 1, #ups do
        local uv = ups[i] or {instack = 0, index = 0}
        dprint("Upvalue", i, ":", uv.instack, uv.index)
        writer:write_byte(uv.instack or 0)
        writer:write_byte(uv.index or 0)
    end

    local source_str = proto.source or ""
    dprint("Writing source:", source_str)
    writer:write_string(source_str)

    local lineinfo = proto.lineinfo or {}
    local code_len = #(proto.code or {})
    dprint("Writing line info for", code_len, "instructions")
    writer:write_int(code_len)
    for i = 1, code_len do
        writer:write_int(lineinfo[i] or 1)
    end

    local locals = proto.locals or {}
    dprint("Writing", #locals, "locals")
    writer:write_int(#locals)
    for i = 1, #locals do
        local loc = locals[i]
        writer:write_string(loc.name or "")
        writer:write_int(loc.startpc or 0)
        writer:write_int(loc.endpc or 0)
    end

    local up_names = proto.upvalue_names or {}
    dprint("Writing upvalue names for", #ups, "upvalues")
    writer:write_int(#ups)
    for i = 1, #ups do
        dprint("Upvalue name", i, ":", up_names[i] or "")
        writer:write_string(up_names[i] or "")
    end

    dprint("Finished writing proto")
end

local function assemble_lua(chunk)
    dprint("Starting assembly")
    local stack, root_proto, max_register = {}, nil, 0

    local function new_proto()
        return {
            source = nil,
            linedefined = 0,
            lastlinedefined = 0,
            num_params = 0,
            is_vararg = 0,
            max_stack = 2,
            code = {},
            constants = {},
            protos = {},
            upvalues = {},
            lineinfo = {},
            locals = {},
            upvalue_names = {},
            _labels = {},
            _pending = {},
        }
    end

    local current_section = nil

    local free_regs = {}
    local scopes = {}
    local for_stack = {}

    local reserved_counts = {}

    local function push_scope()
        scopes[#scopes + 1] = { names = {}, allocated = {} }
        dprint("PUSH SCOPE, depth=", #scopes)
    end
    local function pop_scope()
        local s = table.remove(scopes)
        if not s then return end
        dprint("POP SCOPE, freeing:", next(s.allocated) and table.concat((function() local a={} for k in pairs(s.allocated) do a[#a+1]=k end return a end)(), ", ") or "<none>")
        for name, reg in pairs(s.allocated) do
            s.names[name] = nil
            if not reserved_counts[reg] or reserved_counts[reg] == 0 then
                free_regs[#free_regs + 1] = reg
                dprint("Recycled register R" .. reg .. " from name $" .. name)
            else
                dprint("Skipping recycle of reserved R" .. reg .. " from name $" .. name)
            end
        end
    end

    local function lookup_reg_by_name(name)
        for i = #scopes, 1, -1 do
            local s = scopes[i]
            if s.names[name] then return s.names[name] end
        end
        return nil
    end

    local function find_scope_with_reg(regnum)
        for i = #scopes, 1, -1 do
            local s = scopes[i]
            for _name, r in pairs(s.allocated) do
                if r == regnum then return s end
            end
        end
        return scopes[#scopes]
    end

    local function pop_free_nonreserved()
        for i = #free_regs, 1, -1 do
            local r = free_regs[i]
            if not reserved_counts[r] or reserved_counts[r] == 0 then
                table.remove(free_regs, i)
                return r
            end
        end
        return nil
    end

    local function alloc_reg_for_name(name)
        local existing = lookup_reg_by_name(name)
        if existing then return existing end
        if #scopes == 0 then push_scope() end
        local top = scopes[#scopes]

        local reg = pop_free_nonreserved()
        if reg then
            dprint("Reusing register R" .. reg .. " for $" .. name)
        else
            reg = max_register + 1
            max_register = reg
            dprint("Allocating new register R" .. reg .. " for $" .. name)
        end

        top.names[name] = reg
        top.allocated[name] = reg
        return reg
    end

    local function reg_token_to_R(token)
        if not token then return token end
        local nm = token:match("^%$([%w_]+)$")
        if nm then
            local existing = lookup_reg_by_name(nm)
            if existing then return "R" .. tostring(existing) end

            if nm == "val" and #for_stack > 0 then
                local for_entry = for_stack[#for_stack]
                local base = for_entry.base
                local reg = base + 3
                if reg > max_register then max_register = reg end
                local scope_for_base = find_scope_with_reg(base) or scopes[#scopes]
                scope_for_base.names[nm] = reg
                scope_for_base.allocated[nm] = reg
                dprint("Binding $val to loop control R" .. reg .. " (base R" .. base .. ")")
                return "R" .. tostring(reg)
            end

            local rnum = alloc_reg_for_name(nm)
            return "R" .. tostring(rnum)
        end
        if token:match("^R%d+$") then return token end
        return token
    end

    local function transform_parts(parts)
        local out = {}
        for i, p in ipairs(parts) do
            out[i] = reg_token_to_R(p)
        end
        return out
    end

    for line in chunk:gmatch("[^\r\n]+") do
        line = line:match("^%s*(.-)%s*$")
        line = line:gsub("%s*;.*$", "")

        if line == "" then
        elseif line:sub(1, 1) == "." then
            local directive = line:match("^%.([%a_][%w_]*)")
            local rest = line:sub(#directive + 2) or ""

            if directive == "fn" then
                dprint("Starting new function")
                local p = new_proto()
                local atsrc = rest:match("@(%S+)")
                if atsrc then
                    p.source = "@" .. atsrc
                    dprint("Set source to:", p.source)
                end
                stack[#stack + 1] = p
                if not root_proto then root_proto = p end
                current_section = nil
                free_regs = {}
                scopes = {}
                max_register = 0
                for_stack = {}
                reserved_counts = {}
                push_scope()

            elseif directive == "endfn" then
                dprint("Ending function")
                local finished = table.remove(stack)
                if not finished then error(".endfn with no matching .fn") end

                for _, p in ipairs(finished._pending) do
                    local cur = p.idx
                    local target = finished._labels[p.label]
                    assert(target, "unknown label: "..tostring(p.label))
                    local sBx = target - (cur + 1)
                    local a_token = p.a
                    if type(a_token) == "string" and a_token:match("^%$") then
                        a_token = reg_token_to_R(a_token)
                    end
                    local args = { a_token, tostring(sBx) }
                    finished.code[cur] = encode_instruction(p.opname, args)
                end
                finished._labels, finished._pending = nil, nil

                local parent = stack[#stack]
                if parent then
                    parent.protos[#parent.protos + 1] = finished
                end
                current_section = nil
                if #stack == 0 then break end

            elseif directive == "scope" then
                dprint(".scope encountered")
                push_scope()

            elseif directive == "endscope" then
                dprint(".endscope encountered")
                pop_scope()

            else
                dprint("Section:", directive)
                current_section = directive
            end

        else
            local proto = stack[#stack]
            if not proto then error("instruction outside of .fn block: " .. line) end

            if current_section == "instruction" then
                local label = line:match("^([%w_]+):%s*$")
                if label then
                    proto._labels[label] = #(proto.code) + 1
                else
                    local parts = {}
                    for part in line:gmatch("%S+") do parts[#parts + 1] = part end
                    if #parts > 0 then
                        local opname = table.remove(parts, 1)
                        dprint("Encoding instruction:", opname, table.concat(parts, " "))

                        local transformed = transform_parts(parts)

                        if opname == "FORPREP" then
                            local base_token = transformed[1]
                            local base_reg = tonumber(base_token and base_token:match("^R(%d+)$"))
                            if base_reg then
                                local reserved = base_reg + 3
                                reserved_counts[reserved] = (reserved_counts[reserved] or 0) + 1
                                if reserved > max_register then max_register = reserved end
                                for_stack[#for_stack + 1] = { base = base_reg, reserved = reserved }
                                dprint("PUSH FOR BASE R" .. base_reg .. " (reserved R" .. reserved .. ")")
                            end
                        end

                        if (opname == "FORPREP" or opname == "FORLOOP" or opname == "JMP" or opname == "TFORLOOP")
                           and not tonumber(parts[2] or "") then
                            proto._pending[#proto._pending+1] = {
                                idx = #(proto.code)+1,
                                opname = opname,
                                a = transformed[1],
                                label = parts[2],
                            }
                            proto.code[#proto.code+1] = 0
                        else
                            local inst = encode_instruction(opname, transformed)
                            dprint("Encoded as:", inst)
                            proto.code[#proto.code + 1] = inst
                        end

                        if opname == "FORLOOP" then
                            local fe = table.remove(for_stack)
                            if fe then
                                local reserved = fe.reserved
                                reserved_counts[reserved] = (reserved_counts[reserved] or 1) - 1
                                if reserved_counts[reserved] <= 0 then
                                    reserved_counts[reserved] = nil
                                    dprint("UNRESERVED R" .. reserved)
                                else
                                    dprint("Deferred unreserve of R" .. reserved .. " (count=" .. reserved_counts[reserved] .. ")")
                                end
                                dprint("POP FOR BASE R" .. tostring(fe.base))
                            else
                                dprint("Warning: FORLOOP without matching FORPREP on for_stack")
                            end
                        end

                        for _, tpart in ipairs(transformed) do
                            local reg = tpart:match("^R(%d+)$")
                            if reg then
                                local rnum = tonumber(reg)
                                if rnum and rnum > max_register then
                                    max_register = rnum
                                end
                            end
                        end
                    end
                end

            elseif current_section == "const" then
                local key, value = line:match("^(%S+)%s*=%s*(.+)")
                if key and value then
                    local idx = tonumber(key:match("K(%d+)"))
                    if idx then
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
                        dprint("Adding constant", idx, "->", value)
                        proto.constants[idx + 1] = value
                    end
                end

            elseif current_section == "upvalue" then
                local key, instack, idx = line:match("^(U%d+)%s*=%s*L(%d+)%s+R(%d+)")
                if key and instack and idx then
                    local uv_idx = tonumber(key:match("U(%d+)"))
                    if uv_idx then
                        dprint("Adding upvalue", uv_idx, "->", instack, idx)
                        proto.upvalues[uv_idx + 1] = {
                            instack = tonumber(instack),
                            index = tonumber(idx)
                        }
                        proto.upvalue_names[uv_idx + 1] = "_ENV"
                    end
                end

            elseif current_section == "header" then
                for k, v in line:gmatch("(%w+)%s*=%s*([^,%s]+)") do
                    dprint("Header:", k, "=", v)
                    if k == "linedefined" then
                        proto.linedefined = tonumber(v) or 0
                    elseif k == "lastlinedefined" then
                        proto.lastlinedefined = tonumber(v) or 0
                    elseif k == "numparams" then
                        proto.num_params = tonumber(v) or 0
                    elseif k == "is_vararg" or k == "vararg" then
                        proto.is_vararg = (tonumber(v) ~= 0) and 1 or 0
                    elseif k == "maxstack" then
                        proto.max_stack = tonumber(v) or proto.max_stack
                    elseif k == "source" then
                        proto.source = v
                    end
                end
            end
        end
    end

    if not root_proto then error("no .fn found in chunk") end

    dprint("Assembly complete, max register:", max_register)
    dprint("Root proto constants:", #root_proto.constants)
    dprint("Root proto upvalues:", #root_proto.upvalues)
    dprint("Root proto code:", #root_proto.code)

    root_proto.max_stack = math.max(root_proto.max_stack or 2, max_register + 1)

    local function fix_defaults(p)
        p.max_stack = math.max(p.max_stack or 2, 2)
        p.num_params = p.num_params or 0
        p.is_vararg = (p.is_vararg and 1) or 0
        for _, sub in ipairs(p.protos or {}) do
            fix_defaults(sub)
        end
    end
    fix_defaults(root_proto)

    dprint("Creating writer and writing bytecode")
    local w = new_writer()
    w:write_raw_bytes(make_luac_header())
    dprint("Header written, writing proto")
    write_proto(w, root_proto)
    dprint("Proto written, getting output")

    return w:get_output()
end

local function hexdump(data, limit)
    limit = limit or 256
    local hex = {}
    local ascii = {}
    for i = 1, math.min(#data, limit) do
        local byte = data:byte(i)
        hex[#hex + 1] = string.format("%02X", byte)
        ascii[#ascii + 1] = (byte >= 32 and byte <= 126) and string.char(byte) or "."
        if i % 16 == 0 then
            dprint(string.format("%04X: %s %s", i-16, table.concat(hex, " "), table.concat(ascii, "")))
            hex, ascii = {}, {}
        end
    end
    if #hex > 0 then
        dprint(string.format("%04X: %-47s %s", #data - (#data % 16), table.concat(hex, " "), table.concat(ascii, "")))
    end
end

local chunk = [[
.fn @loop.lua
.header
numparams=0, is_vararg=1, maxstack=6
.instruction
.scope
    LOADK     $idx K0
    LOADK     $limit K1
    LOADK     $step K2

    FORPREP   $idx Lloop

Lbody:
.scope
    GETTABUP  $f U0 K3
    MOVE      $arg $val
    CALL      $f 2 1
.endscope

Lloop:
    FORLOOP   $idx Lbody

    RETURN    $idx 1
.endscope
.const
    K0 = 1
    K1 = 3
    K2 = 1
    K3 = "print"
.upvalue
    U0 = L0 R0
.endfn

]]

dprint("Starting bytecode generation")
local bytecode = assemble_lua(chunk)
dprint("Bytecode generated, length:", #bytecode)

dprint("Complete bytecode hex dump:")
hexdump(bytecode, #bytecode)

local file = io.open("hello.luac", "wb")
if file then
    file:write(bytecode)
    file:close()
    dprint("Bytecode written to hello.luac")
else
    dprint("Failed to open hello.luac for writing")
end

dprint("Attempting to load bytecode with loadstring")
local ok, err = loadstring(bytecode)
if err then
    dprint("Error in bytecode:", err)
    print("Error in bytecode: " .. err)
else
    dprint("Bytecode loaded successfully!")
    print("Bytecode loaded successfully!")
    if ok then
        dprint("Function type:", type(ok))
        ok()
    end
end

return {assemble = assemble_lua}
