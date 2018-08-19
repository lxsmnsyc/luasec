local aes = require "luasec.src.aes192"
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
local crypt = aes.new(0x01020304, 0x05061020, 0x30405060, 0x01020304, 0x05061020, 0x30405060)
print("Key: 01 02 03 04 05 06 10 20 30 40 50 60 01 02 03 04 05 06 10 20 30 40 50 60")
local function roundKey(start)
    local tbl = {}
    for i = 0, 15 do 
        tbl[i] = crypt.ciphers[start + i]
    end 
    return dump(tbl)
end
local i = 0
while i < #crypt.ciphers do
    print("Key "..((i == 0) and "0" or "")..string.format("%x", i)..": "..roundKey(i))
    i = i + 24
end
print("------------------------------------------------------------------")
local a, b, c, d = 0x01020304, 0x0204070B, 0x03070E1A, 0x040B1A40
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