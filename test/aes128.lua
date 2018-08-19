local aes = require "luasec.src.aes128"
local bit = require "bit"
local hex = bit.tohex

local function dump(data)
    local s = ""
    for i = 0, 15 do 
        if data[i] < 16 then s = s.."0" end
        s = s..string.format("%x", data[i])
    end
    return s 
end
local crypt = aes.new(0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
print("Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c")
local function roundKey(start)
    local tbl = {}
    for i = 0, 15 do 
        tbl[i] = crypt.ciphers[start + i]
    end 
    return dump(tbl)
end
for i = 0, #crypt.ciphers, 16 do
    print("Key "..((i == 0) and "0" or "")..string.format("%x", i)..": "..roundKey(i))
end
print("------------------------------------------------------------------")
local a, b, c, d = 0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734
print("------------------------------------------------------------------")
print("Before: ", hex(a), hex(b), hex(c), hex(d))
print("------------------------------------------------------------------")
a, b, c, d = crypt:encrypt(a, b, c, d)
print("------------------------------------------------------------------")
print("After: \t", hex(a), hex(b), hex(c), hex(d))
print("------------------------------------------------------------------")
a, b, c, d = crypt:decrypt(a, b, c, d)
print("------------------------------------------------------------------")
print("Decrypted: ", hex(a), hex(b), hex(c), hex(d))
print("------------------------------------------------------------------")