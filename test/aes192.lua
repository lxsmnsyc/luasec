local aes = require "luasec.src.aes192"

function dumpCipher(c)
    local s = ""
    for i = 1, 24 do
        if(c[i] < 16) then s = s.."0" end
        s = s..string.format("%x", c[i])
        --s = s..string.char(d[i])
    end 
    return s
end

function dump(d)
    local s = ""
    for i = 1, 16 do
        if(d[i] < 16) then s = s.."0" end
        s = s..string.format("%x", d[i])
        --s = s..string.char(d[i])
    end 
    return s
end 

local cipher = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60
}

local crypt = aes.new(cipher)
print("Key: "..dumpCipher(cipher))

local data = {
    0x01, 0x02, 0x03, 0x04,
    0x02, 0x04, 0x07, 0x0B,
    0x03, 0x07, 0x0E, 0x1A,
    0x04, 0x0B, 0x1A, 0x40
}
print("------------------------------------------------------------------")
local base = dump(data)
print("Before: "..base)
print("------------------------------------------------------------------")
crypt:encrypt(data)
print("------------------------------------------------------------------")
print("After: "..dump(data))
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
print("After: "..dump(data))
print("------------------------------------------------------------------")
crypt:decrypt(data)
print("------------------------------------------------------------------")
local result = dump(data)
print("Decrypted: "..result)
print("------------------------------------------------------------------")
print("Test Result: "..((result == base) and "Passed" or "Failed"))