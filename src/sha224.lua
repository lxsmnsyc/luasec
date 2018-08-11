local bit = require "bit"

local AND, OR, NOT, XOR = bit.band, bit.bor, bit.bnot, bit.bxor 
local LSHIFT, RSHIFT = bit.lshift, bit.rshift

local ROL, ROR = bit.rol, bit.ror

local tohex, tobit = bit.tohex, bit.tobit

local K = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

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
    until ((#bytes + 8) % 64 == 0)
    
    -- append first 32-bit for the 64-bit big endian
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000
    bytes[#bytes + 1] = 0x00 -- 0000 0000

    -- convert bit length to big-endian hex
    local a0, a1, a2, a3 = splitWord(L*8)

    bytes[#bytes + 1] = a0
    bytes[#bytes + 1] = a1
    bytes[#bytes + 1] = a2
    bytes[#bytes + 1] = a3
end 

local function getChunk(bytes, start)
    local chunk = {}
    local chunkI = 1
    for i = 0, 63, 4 do
        chunk[chunkI] = mergeBytes(
            bytes[start + i],
            bytes[start + i + 1],
            bytes[start + i + 2],
            bytes[start + i + 3]
        )
        chunkI = chunkI + 1
    end 
    return chunk
end 

local function getEMSA( chunk)
    local emsa = {}
    for i = 1, 64 do
        emsa[i] = (i <= 16) and chunk[i] or 0
    end
    return emsa
end

local function choice(x, y, z)
    return XOR(AND(x, y), AND(NOT(x), z))
end

local function majority(x, y, z)
    return XOR(AND(x, y), AND(x, z), AND(y, z))
end

local function sigma0(x)
    return XOR(ROR(x, 2), ROR(x, 13), ROR(x, 22))
end

local function sigma1(x)
    return XOR(ROR(x, 6), ROR(x, 11), ROR(x, 25))
end

local function lsigma0(x)
    return XOR(ROR(x, 7), ROR(x, 18), RSHIFT(x, 3))
end

local function lsigma1(x)
    return XOR(ROR(x, 17), ROR(x, 19), RSHIFT(x, 10))
end

local function decompose(w)
    for i = 17, 64 do
        w[i] = lsigma1(w[i - 2]) + w[i - 7] + lsigma0(w[i - 15]) + w[i - 16]
    end 
end

local function compute(w, a, b, c, d, e, f, g, h)
    for i = 1, 64 do
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

    local h0, h1, h2, h3 = 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939
    local h4, h5, h6, h7 = 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4

    for i = 1, #bytes, 64 do
        local w = getEMSA(getChunk(bytes, i))

        decompose(w)

        local a, b, c, d, e, f, g, h = compute(w, h0, h1, h2, h3, h4, h5, h6, h7)

        h0 = tobit(h0 + a)
        h1 = tobit(h1 + b)
        h2 = tobit(h2 + c)
        h3 = tobit(h3 + d)
        h4 = tobit(h4 + e)
        h5 = tobit(h5 + f)
        h6 = tobit(h6 + g)
        h7 = tobit(h7 + h)
    end 

    return tohex(h0)..tohex(h1)..tohex(h2)..tohex(h3)..tohex(h4)..tohex(h5)..tohex(h6)
end