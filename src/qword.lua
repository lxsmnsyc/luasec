local bit = require "bit"
local ffi = require "ffi"

local AND, OR, NOT, XOR = bit.band, bit.bor, bit.bnot, bit.bxor 
local LSHIFT, RSHIFT = bit.lshift, bit.rshift

local ROL, ROR = bit.rol, bit.ror

local tohex = bit.tohex

ffi.cdef[[
    typedef struct{
        uint32_t left, right;
    } QWORD_T;
]]

local function RSHIFT64(al, ar, n)
    if(n < 32) then
        return RSHIFT(al, n), OR(RSHIFT(ar, n), LSHIFT(al, 32 - n))
    end 
    return 0x0, RSHIFT(al, n - 32)
end 


local function LSHIFT64(al, ar, n)
    if(n < 32) then
        return OR(LSHIFT(al, n), RSHIFT(ar, 32 - n)), LSHIFT(ar, n)
    end 
    return LSHIFT(ar, n - 32), 0x0
end 

local function ROR64(al, ar, n)
    local rsl, rsr = RSHIFT64(al, ar, n)
    local lsl, lsr = LSHIFT64(al, ar, 64 - n)
    return OR(lsl, rsl), OR(lsr, rsr)
end 

local function ROL64(al, ar, n)
    local rsl, rsr = LSHIFT64(al, ar, n)
    local lsl, lsr = RSHIFT64(al, ar, 64 - n)
    return OR(lsl, rsl), OR(lsr, rsr)
end 


local qword

local mt = {
    __mul = function (a, b)
        return qword(AND(a.left, b.left), AND(a.right, b.right))
    end, 
    __div = function (a, b)
        return qword(OR(a.left, b.left), OR(a.right, b.right))
    end,
    __unm = function (a)
        return qword(NOT(a.left), NOT(a.right))
    end,
    __pow = function (a, b)
        return qword(XOR(a.left, b.left), XOR(a.right, b.right))
    end,
    __add = function (a, b)
        local al, ar = a.left, a.right
        local bl, br = b.left, b.right
        local sr = ar + br
        local r = sr - 0xFFFFFFFF
        local sl = al + bl
        if(r > 0) then
            sl = sl + 1
            sr = r - 1
        end 
        return qword(sl, sr)
    end,
    __sub = function (a, b)
        local al, ar = a.left, a.right
        local bl, br = b.left, b.right

        local sl = al - bl
        local sr = ar - br
        if(ar < br) then
            sl = sl - 1
            sr = sr + 0x100000000
        end 
        return qword(sl, sr)
    end,
    __eq = function (a, b)
        return a.left == b.left and a.right == b.right
    end, 
    __lt = function (a, b)
        return (a.left < b.left) or ((a.left == b.left) and (a.right < b.right))
    end, 
    __le = function (a, b)
        return (a.left < b.left) or ((a.left == b.left) and (a.right <= b.right))
    end,
    __tostring = function (a)
        return tohex(a.left)..tohex(a.right)
    end, 
    __concat = function (a, b)
        return tostring(a)..tostring(b)
    end,
    __index = {
        rshift = function (a, n)
            local l, r = RSHIFT64(a.left, a.right, n)
            return qword(l, r)
        end,
        lshift = function (a, n)
            local l, r = LSHIFT64(a.left, a.right, n)
            return qword(l, r)
        end,
        ror = function (a, n)
            local l, r = ROR64(a.left, a.right, n)
            return qword(l, r)
        end,
        rol = function (a, n)
            local l, r = ROL64(a.left, a.right, n)
            return qword(l, r)
        end
    }
}

qword = ffi.metatype("QWORD_T", mt)
return qword 