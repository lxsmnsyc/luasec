local bit = require "bit"

local AND, OR, NOT, XOR = bit.band, bit.bor, bit.bnot, bit.bxor 
local LSHIFT, RSHIFT = bit.lshift, bit.rshift

local ROL, ROR = bit.rol, bit.ror

local tohex = bit.tohex

local int64 = require "luasec.src.qword"
--[[
    Since Lua doesn't support 64-bit integers on earlier versions
    we need to split the constants into two 32-bit integers
]]

local KL = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0xca273ece, 
    0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 
    0x113f9804, 0x1b710b35, 0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 
    0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c
}

local KR = {
    0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538,
    0xb605d019, 0xaf194f9b, 0xda6d8118, 0xa3030242, 0x45706fbe,
    0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235,
    0xcf692694, 0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65,
    0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5, 0xee66dfab,
    0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725,
    0xe003826f, 0x0a0e6e70, 0x46d22ffc, 0x5c26c926, 0x5ac42aed,
    0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
    0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218,
    0x5565a910, 0x5771202a, 0x32bbd1b8, 0xb8d2d0c8, 0x5141ab53,
    0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373,
    0xd6b2b8a3, 0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec,
    0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b, 0xea26619c,
    0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6,
    0xbef90dae, 0x131c471b, 0x23047d84, 0x40c72493, 0x15c9bebc,
    0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817
}

local K = {}
local mergedK = false
local function mergeK()
    if(mergedK) then return end
    for i = 1, 80 do
        K[i] = int64(KL[i], KR[i])
    end
end

local function str2byte(str)
    local bytes = {}
    for i = 1, #str do
        bytes[i] = str:sub(i, i):byte()
    end
    return bytes
end

local function mergeBytes(a, b, c, d)
    a = LSHIFT(a, 24)
    b = LSHIFT(b, 16)
    c = LSHIFT(c, 8)
    return OR(OR(a, b), OR(c, d))
end 

local function mergeBytes64(a, b, c, d, e, f, g, h)
    a = mergeBytes(a, b, c, d)
    b = mergeBytes(e, f, g, h)
    return int64(a, b)
end

local function splitWord(w)
    local a = RSHIFT(AND(w, 0xff000000), 24)
    local b = RSHIFT(AND(w, 0xff0000), 16)
    local c = RSHIFT(AND(w, 0xff00), 8)
    local d = AND(w, 0xff)
    return a, b, c, d
end

local function padding(bytes)
    local L = #bytes 
    -- pad 1 bit and 7 zero bits
    bytes[#bytes + 1] = 0x80 -- 1000 0000
    
    -- calculate for k
    repeat 
        -- append 8 '0' bits
        bytes[#bytes + 1] = 0x00 -- 0000 0000
    until ((#bytes + 16) % 128 == 0)
    
    -- append first 64-bit for the 128-bit big endian
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000

    -- convert bit length to big-endian hex
    local a0, a1, a2, a3 = splitWord(L*8)

    -- set the left-part of the 64-bit to zero
    bytes[#bytes + 1] = 0x00
    bytes[#bytes + 1] = 0x00
    bytes[#bytes + 1] = 0x00
    bytes[#bytes + 1] = 0x00
    bytes[#bytes + 1] = a0
    bytes[#bytes + 1] = a1
    bytes[#bytes + 1] = a2
    bytes[#bytes + 1] = a3
end 

local function getChunk(bytes, start)
    local chunk = {}
    local chunkI = 1
    for i = 0, 127, 8 do
        chunk[chunkI]= mergeBytes64(
            bytes[start + i],
            bytes[start + i + 1],
            bytes[start + i + 2],
            bytes[start + i + 3],
            bytes[start + i + 4],
            bytes[start + i + 5],
            bytes[start + i + 6],
            bytes[start + i + 7]
         )
        chunkI = chunkI + 1
    end 
    return chunk
end 

local function getEMSA(chunk)
    local emsa = {}
    for i = 1, 80 do
        emsa[i] = (i <= 16) and chunk[i] or 0
    end
    return emsa
end

local function choice(x, y, z)
    return (x * y) ^ (-x * z)
end

local function majority(x, y, z)
    -- return XOR(AND(x, y), AND(x, z), AND(y, z))
    return (x * y) ^ (x * z) ^ (y * z)
end

local function sigma0(x)
    -- S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
    return x:ror(28) ^ x:ror(34) ^ x:ror(39)
end

local function sigma1(x)
    -- S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
    return x:ror(14) ^ x:ror(18) ^ x:ror(41)
end

local function lsigma0(x)
    -- s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
    return x:ror(1) ^ x:ror(8) ^ x:rshift(7)
end

local function lsigma1(x)
    -- s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
    return x:ror(19) ^ x:ror(61) ^ x:rshift(6)
end

local function decompose(w)
    for i = 17, 80 do
        -- w[i] = lsigma1(w[i - 2]) + w[i - 7] + lsigma0(w[i - 15]) + w[i - 16]
        w[i] = lsigma1(w[i - 2]) + w[i - 7] + lsigma0(w[i - 15]) + w[i - 16]
    end 
end

local function compute(w, a, b, c, d, e, f, g, h)
    for i = 1, 80 do
        local t1 = h + sigma1(e) + choice(e, f, g) + K[i] + w[i]
        local t2 = sigma0(a) + majority(a, b, c)

        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    end
    return a, b, c, d, e, f, g, h
end

return function (message)
    -- convert message to bytes
    local bytes = str2byte(message)

    -- padding process
    padding(bytes)

    mergeK()

    local h0 = int64(0x6a09e667, 0xf3bcc908)
    local h1 = int64(0xbb67ae85, 0x84caa73b)
    local h2 = int64(0x3c6ef372, 0xfe94f82b)
    local h3 = int64(0xa54ff53a, 0x5f1d36f1)
    local h4 = int64(0x510e527f, 0xade682d1)
    local h5 = int64(0x9b05688c, 0x2b3e6c1f)
    local h6 = int64(0x1f83d9ab, 0xfb41bd6b)
    local h7 = int64(0x5be0cd19, 0x137e2179)

    for i = 1, #bytes, 128 do -- 1024-bit chunks or 128-bytes 
        local w = getEMSA(getChunk(bytes, i))

        decompose(w)

        local a, b, c, d, e, f, g, h = compute(w, h0, h1, h2, h3, h4, h5, h6, h7)

        h0 = (h0 + a)
        h1 = (h1 + b)
        h2 = (h2 + c)
        h3 = (h3 + d)
        h4 = (h4 + e)
        h5 = (h5 + f)
        h6 = (h6 + g)
        h7 = (h7 + h)
    end 
    return tostring(h0)..tostring(h1)..tostring(h2)..tostring(h3)..
    tostring(h4)..tostring(h5)..tostring(h6)..tostring(h7)
end