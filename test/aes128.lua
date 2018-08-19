local aes = require "luasec.src.aes128"

function dump(d)
    local s = "\t"
    for i = 1, 16 do
        if(d[i] < 16) then s = s.."0" end
        s = s..string.format("%x", d[i])
    end 

    return s
end 

local cipher = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
}

local crypt = aes.new(cipher)
print("Key: "..dump(cipher))
print("------------------------------------------------------------------")
print("Keys:")
local function roundKey(start)
    local tbl = {}
    for i = 0, 15 do 
        tbl[i + 1] = crypt.ciphers[start + i]
    end 
    return dump(tbl)
end
for i = 0, #crypt.ciphers, 16 do
    print("Key "..((i == 0) and "0" or "")..string.format("%x", i)..": "..roundKey(i))
end

local data = {
    0x32, 0x43, 0xf6, 0xa8,
    0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2,
    0xe0, 0x37, 0x07, 0x34
}
print("------------------------------------------------------------------")
local base = dump(data)
print("Before: "..base)
print("------------------------------------------------------------------")
crypt:encrypt(data)
print("------------------------------------------------------------------")
print("After: \t"..dump(data))
print("------------------------------------------------------------------")
crypt:decrypt(data)
print("------------------------------------------------------------------")
local result = dump(data)
print("Decrypted: "..result)
print("------------------------------------------------------------------")
print("Test Result: "..((result == base) and "Passed" or "Failed"))

local data = {
    0x1, 0x8, 0x9, 0x0,
    0x2, 0x7, 0xA, 0xF,
    0x3, 0x6, 0xB, 0xE,
    0x4, 0x5, 0xC, 0xD
}
print("------------------------------------------------------------------")
local base = dump(data)
print("Before: "..base)
print("------------------------------------------------------------------")
crypt:encrypt(data)
print("------------------------------------------------------------------")
print("After: \t"..dump(data))
print("------------------------------------------------------------------")
crypt:decrypt(data)
print("------------------------------------------------------------------")
local result = dump(data)
print("Decrypted: "..result)
print("------------------------------------------------------------------")
print("Test Result: "..((result == base) and "Passed" or "Failed"))