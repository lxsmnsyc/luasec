local qword = require "luasec.src.qword"
local oword = require "luasec.src.oword"
local c128 = require "luasec.src.camellia192"

local a, b, c, d, e, f = 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210, 0x00112233, 0x44556677
local g, h, i, j = 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210

local cipher1 = oword(qword(a, b), qword(c, d))
local cipher2 = qword(e, f)
local crypt = c128.new(a, b, c, d, e, f)

print("Key: "..tostring(cipher1)..tostring(cipher2))

print("------------------------------------------------------------------")
local base = tostring(cipher1)
print("Before: \t"..base)
g, h, i, j = crypt:encrypt(g, h, i, j)
local enc = oword(qword(g, h), qword(i, j))
print("After: \t\t"..tostring(enc))
g, h, i, j = crypt:decrypt(g, h, i, j)
local dec = oword(qword(g, h), qword(i, j))
local result = tostring(dec)
print("Decrypted: \t"..result)
print("------------------------------------------------------------------")
print("Test Result: "..((result == base) and "Passed" or "Failed"))