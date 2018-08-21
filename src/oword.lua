
local ffi = require "ffi"
local bit = require "bit"

local AND, OR, NOT, XOR = bit.band, bit.bor, bit.bnot, bit.bxor 
local LSHIFT, RSHIFT = bit.lshift, bit.rshift

local ROL, ROR = bit.rol, bit.ror

local tohex = bit.tohex

local qword = require "luasec.src.qword"

ffi.cdef[[
    typedef struct{
        QWORD_T left, right;
    } OWORD_T;
]]

local function RSHIFT128(al, ar, n)
    if(n < 64) then
        return al:rshift(n), ar:rshift(n) / al:lshift(64 - n)
    end 
    return qword(0, 0), al:rshift(n - 64)
end 


local function LSHIFT128(al, ar, n)
    if(n < 64) then
        return al:lshift(n) / ar:rshift(64 - n), ar:lshift(n)
    end 
    return ar:lshift(n - 64), qword(0, 0)
end 

local function ROR128(al, ar, n)
    local rsl, rsr = RSHIFT128(al, ar, n)
    local lsl, lsr = LSHIFT128(al, ar, 128 - n)
    return lsl / rsl, lsr / rsr
end 

local function ROL128(al, ar, n)
    local rsl, rsr = LSHIFT128(al, ar, n)
    local lsl, lsr = RSHIFT128(al, ar, 128 - n)
    return lsl / rsl, lsr / rsr
end 

local oword

local mt = {
    __mul = function (a, b)
        return oword(a.left * b.left, a.right * b.right)
    end, 
    __div = function (a, b)
        return oword(a.left / b.left, a.right / b.right)
    end,
    __unm = function (a)
        return oword(-a.left, -a.right)
    end,
    __pow = function (a, b)
        return oword(a.left ^ b.left, a.right ^ b.right)
    end,
    __add = function (a, b)
        local al, ar = a.left, a.right
        local bl, br = b.left, b.right
        local sr = ar + br
        local sl = al + bl
        if(br > qword(0xFFFFFFFF, 0xFFFFFFFF) - ar) then
            sl = sl + qword(0, 1)
            sr = (sr - qword(0xFFFFFFFF, 0xFFFFFFFF)) - qword(0, 1)
        end 
        return oword(sl, sr)
    end,
    __sub = function (a, b)
        local al, ar = a.left, a.right
        local bl, br = b.left, b.right

        local sl = al - bl
        local sr = ar - br
        if(ar < br) then
            sl = sl - qword(0, 1)
            sr = sr + qword(0xFFFFFFFF, 0xFFFFFFFF) + qword(0, 1)
        end 
        return oword(sl, sr)
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
        return tostring(a.left)..tostring(a.right)
    end,  
    __concat = function (a, b)
        return tostring(a)..tostring(b)
    end,
    __index = {
        rshift = function (a, n)
            local l, r = RSHIFT128(a.left, a.right, n)
            return oword(l, r)
        end,
        lshift = function (a, n)
            local l, r = LSHIFT128(a.left, a.right, n)
            return oword(l, r)
        end,
        ror = function (a, n)
            local l, r = ROR128(a.left, a.right, n)
            return oword(l, r)
        end,
        rol = function (a, n)
            local l, r = ROL128(a.left, a.right, n)
            return oword(l, r)
        end,
        split = function (w)
            local a, b = w.left, w.right -- 64-bit
            return a.left, a.right, b.left, b.right -- 32-bit
        end
    }
}

oword = ffi.metatype("OWORD_T", mt)
return oword 