local qword = require "luasec.src.qword"
local oword = require "luasec.src.oword"
local c128 = require "luasec.src.camellia128"

local a, b, c, d = 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
local e, f, g, h = 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210

local cipher = oword(qword(a, b), qword(c, d))
local crypt = c128.new(a, b, c, d)

print("Key: "..tostring(cipher))

print("------------------------------------------------------------------")
local base = tostring(cipher)
print("Before: \t"..base)
e, f, g, h = crypt:encrypt(e, f, g, h)
local enc = oword(qword(e, f), qword(g, h))
print("After: \t\t"..tostring(enc))
e, f, g, h = crypt:decrypt(e, f, g, h)
local dec = oword(qword(e, f), qword(g, h))
local result = tostring(dec)
print("Decrypted: \t"..result)
print("------------------------------------------------------------------")
print("Test Result: "..((result == base) and "Passed" or "Failed"))