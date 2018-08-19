local qword = require "luasec.src.qword"
local oword = require "luasec.src.oword"
local c128 = require "luasec.src.camellia256"

local a, b, c, d = 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
local e, f, g, h = 0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF
local i, j, k, l = 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210

local cipher1 = oword(qword(a, b), qword(c, d))
local cipher2 = oword(qword(e, f), qword(g, h))
local crypt = c128.new(a, b, c, d, e, f, g, h)

print("Key: "..tostring(cipher1)..tostring(cipher2))

print("------------------------------------------------------------------")
local base = tostring(cipher1)
print("Before: \t"..base)
i, j, k, l = crypt:encrypt(i, j, k, l)
local enc = oword(qword(i, j), qword(k, l))
print("After: \t\t"..tostring(enc))
i, j, k, l = crypt:decrypt(i, j, k, l)
local dec = oword(qword(i, j), qword(k, l))
local result = tostring(dec)
print("Decrypted: \t"..result)
print("------------------------------------------------------------------")
print("Test Result: "..((result == base) and "Passed" or "Failed"))