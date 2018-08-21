--[[
    Camellia 128

    https:--tools.ietf.org/html/rfc3713

]]

local bit = require "bit"
local ffi = require "ffi"

local AND, OR, NOT, XOR = bit.band, bit.bor, bit.bnot, bit.bxor 
local LSHIFT, RSHIFT = bit.lshift, bit.rshift

local ROL, ROR = bit.rol, bit.ror

local tohex = bit.tohex

local qword = require "luasec.src.qword"
local oword = require "luasec.src.oword"

local MASK8 = qword(0x00000000, 0x0000000ff)
local MASK32 = qword(0x00000000, 0xffffffff)

--[[
    The 64-bit constants Sigma1, Sigma2, ..., Sigma6 are used as "keys"
   in the F-function.  These constant values are, in hexadecimal
   notation, as follows.
   
   Sigma1 = 0xA09E667F3BCC908B;
   Sigma2 = 0xB67AE8584CAA73B2;
   Sigma3 = 0xC6EF372FE94F82BE;
   Sigma4 = 0x54FF53A5F1D36F1C;
   Sigma5 = 0x10E527FADE682D1D;
   Sigma6 = 0xB05688C2B3E6C1FD;
]]

local SIGMA1 = qword(0xA09E667F, 0x3BCC908B)
local SIGMA2 = qword(0xB67AE858, 0x4CAA73B2)
local SIGMA3 = qword(0xC6EF372F, 0xE94F82BE)
local SIGMA4 = qword(0x54FF53A5, 0xF1D36F1C)
local SIGMA5 = qword(0x10E527FA, 0xDE682D1D)
local SIGMA6 = qword(0xB05688C2, 0xB3E6C1FD)
--[[
    SBOX1, SBOX2, SBOX3, and SBOX4 are lookup tables with 8-bit input/
   output data.  SBOX2, SBOX3, and SBOX4 are defined using SBOX1 as
   follows:

       SBOX2[x] = SBOX1[x] <<< 1;
       SBOX3[x] = SBOX1[x] <<< 7;
       SBOX4[x] = SBOX1[x <<< 1];
       
    SBOX1 is defined by the following table.  For example, SBOX1[0x3d]
    equals 86.

    SBOX1:
        0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
    00: 112 130  44 236 179  39 192 229 228 133  87  53 234  12 174  65
    10:  35 239 107 147  69  25 165  33 237  14  79  78  29 101 146 189
    20: 134 184 175 143 124 235  31 206  62  48 220  95  94 197  11  26
    30: 166 225  57 202 213  71  93  61 217   1  90 214  81  86 108  77
    40: 139  13 154 102 251 204 176  45 116  18  43  32 240 177 132 153
    50: 223  76 203 194  52 126 118   5 109 183 169  49 209  23   4 215
    60:  20  88  58  97 222  27  17  28  50  15 156  22  83  24 242  34
    70: 254  68 207 178 195 181 122 145  36   8 232 168  96 252 105  80
    80: 170 208 160 125 161 137  98 151  84  91  30 149 224 255 100 210
    90:  16 196   0  72 163 247 117 219 138   3 230 218   9  63 221 148
    a0: 135  92 131   2 205  74 144  51 115 103 246 243 157 127 191 226
    b0:  82 155 216  38 200  55 198  59 129 150 111  75  19 190  99  46
    c0: 233 121 167 140 159 110 188 142  41 245 249 182  47 253 180  89
    d0: 120 152   6 106 231  70 113 186 212  37 171  66 136 162 141 250
    e0: 114   7 185  85 248 238 172  10  54  73  42 104  60  56 241 164
    f0:  64  40 211 123 187 201  67 193  21 227 173 244 119 199 128 158
]]

local SBOX1 = {
[0]=0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
    0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
    0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
    0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
    0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
    0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
    0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
    0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
    0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
    0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
    0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
    0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
    0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
    0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
    0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
    0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e
}

local SBOX2 = {
[0]=0xe0, 0x05, 0x58, 0xd9, 0x67, 0x4e, 0x81, 0xcb, 0xc9, 0x0b, 0xae, 0x6a, 0xd5, 0x18, 0x5d, 0x82,
    0x46, 0xdf, 0xd6, 0x27, 0x8a, 0x32, 0x4b, 0x42, 0xdb, 0x1c, 0x9e, 0x9c, 0x3a, 0xca, 0x25, 0x7b,
    0x0d, 0x71, 0x5f, 0x1f, 0xf8, 0xd7, 0x3e, 0x9d, 0x7c, 0x60, 0xb9, 0xbe, 0xbc, 0x8b, 0x16, 0x34,
    0x4d, 0xc3, 0x72, 0x95, 0xab, 0x8e, 0xba, 0x7a, 0xb3, 0x02, 0xb4, 0xad, 0xa2, 0xac, 0xd8, 0x9a,
    0x17, 0x1a, 0x35, 0xcc, 0xf7, 0x99, 0x61, 0x5a, 0xe8, 0x24, 0x56, 0x40, 0xe1, 0x63, 0x09, 0x33,
    0xbf, 0x98, 0x97, 0x85, 0x68, 0xfc, 0xec, 0x0a, 0xda, 0x6f, 0x53, 0x62, 0xa3, 0x2e, 0x08, 0xaf,
    0x28, 0xb0, 0x74, 0xc2, 0xbd, 0x36, 0x22, 0x38, 0x64, 0x1e, 0x39, 0x2c, 0xa6, 0x30, 0xe5, 0x44,
    0xfd, 0x88, 0x9f, 0x65, 0x87, 0x6b, 0xf4, 0x23, 0x48, 0x10, 0xd1, 0x51, 0xc0, 0xf9, 0xd2, 0xa0,
    0x55, 0xa1, 0x41, 0xfa, 0x43, 0x13, 0xc4, 0x2f, 0xa8, 0xb6, 0x3c, 0x2b, 0xc1, 0xff, 0xc8, 0xa5,
    0x20, 0x89, 0x00, 0x90, 0x47, 0xef, 0xea, 0xb7, 0x15, 0x06, 0xcd, 0xb5, 0x12, 0x7e, 0xbb, 0x29,
    0x0f, 0xb8, 0x07, 0x04, 0x9b, 0x94, 0x21, 0x66, 0xe6, 0xce, 0xed, 0xe7, 0x3b, 0xfe, 0x7f, 0xc5,
    0xa4, 0x37, 0xb1, 0x4c, 0x91, 0x6e, 0x8d, 0x76, 0x03, 0x2d, 0xde, 0x96, 0x26, 0x7d, 0xc6, 0x5c,
    0xd3, 0xf2, 0x4f, 0x19, 0x3f, 0xdc, 0x79, 0x1d, 0x52, 0xeb, 0xf3, 0x6d, 0x5e, 0xfb, 0x69, 0xb2,
    0xf0, 0x31, 0x0c, 0xd4, 0xcf, 0x8c, 0xe2, 0x75, 0xa9, 0x4a, 0x57, 0x84, 0x11, 0x45, 0x1b, 0xf5,
    0xe4, 0x0e, 0x73, 0xaa, 0xf1, 0xdd, 0x59, 0x14, 0x6c, 0x92, 0x54, 0xd0, 0x78, 0x70, 0xe3, 0x49,
    0x80, 0x50, 0xa7, 0xf6, 0x77, 0x93, 0x86, 0x83, 0x2a, 0xc7, 0x5b, 0xe9, 0xee, 0x8f, 0x01, 0x3d
}

local SBOX3 = {
[0]=0x38, 0x41, 0x16, 0x76, 0xd9, 0x93, 0x60, 0xf2, 0x72, 0xc2, 0xab, 0x9a, 0x75, 0x06, 0x57, 0xa0,
    0x91, 0xf7, 0xb5, 0xc9, 0xa2, 0x8c, 0xd2, 0x90, 0xf6, 0x07, 0xa7, 0x27, 0x8e, 0xb2, 0x49, 0xde,
    0x43, 0x5c, 0xd7, 0xc7, 0x3e, 0xf5, 0x8f, 0x67, 0x1f, 0x18, 0x6e, 0xaf, 0x2f, 0xe2, 0x85, 0x0d,
    0x53, 0xf0, 0x9c, 0x65, 0xea, 0xa3, 0xae, 0x9e, 0xec, 0x80, 0x2d, 0x6b, 0xa8, 0x2b, 0x36, 0xa6,
    0xc5, 0x86, 0x4d, 0x33, 0xfd, 0x66, 0x58, 0x96, 0x3a, 0x09, 0x95, 0x10, 0x78, 0xd8, 0x42, 0xcc,
    0xef, 0x26, 0xe5, 0x61, 0x1a, 0x3f, 0x3b, 0x82, 0xb6, 0xdb, 0xd4, 0x98, 0xe8, 0x8b, 0x02, 0xeb,
    0x0a, 0x2c, 0x1d, 0xb0, 0x6f, 0x8d, 0x88, 0x0e, 0x19, 0x87, 0x4e, 0x0b, 0xa9, 0x0c, 0x79, 0x11,
    0x7f, 0x22, 0xe7, 0x59, 0xe1, 0xda, 0x3d, 0xc8, 0x12, 0x04, 0x74, 0x54, 0x30, 0x7e, 0xb4, 0x28,
    0x55, 0x68, 0x50, 0xbe, 0xd0, 0xc4, 0x31, 0xcb, 0x2a, 0xad, 0x0f, 0xca, 0x70, 0xff, 0x32, 0x69,
    0x08, 0x62, 0x00, 0x24, 0xd1, 0xfb, 0xba, 0xed, 0x45, 0x81, 0x73, 0x6d, 0x84, 0x9f, 0xee, 0x4a,
    0xc3, 0x2e, 0xc1, 0x01, 0xe6, 0x25, 0x48, 0x99, 0xb9, 0xb3, 0x7b, 0xf9, 0xce, 0xbf, 0xdf, 0x71,
    0x29, 0xcd, 0x6c, 0x13, 0x64, 0x9b, 0x63, 0x9d, 0xc0, 0x4b, 0xb7, 0xa5, 0x89, 0x5f, 0xb1, 0x17,
    0xf4, 0xbc, 0xd3, 0x46, 0xcf, 0x37, 0x5e, 0x47, 0x94, 0xfa, 0xfc, 0x5b, 0x97, 0xfe, 0x5a, 0xac,
    0x3c, 0x4c, 0x03, 0x35, 0xf3, 0x23, 0xb8, 0x5d, 0x6a, 0x92, 0xd5, 0x21, 0x44, 0x51, 0xc6, 0x7d,
    0x39, 0x83, 0xdc, 0xaa, 0x7c, 0x77, 0x56, 0x05, 0x1b, 0xa4, 0x15, 0x34, 0x1e, 0x1c, 0xf8, 0x52,
    0x20, 0x14, 0xe9, 0xbd, 0xdd, 0xe4, 0xa1, 0xe0, 0x8a, 0xf1, 0xd6, 0x7a, 0xbb, 0xe3, 0x40, 0x4f
}

local SBOX4 = {
[0]=0x70, 0x2c, 0xb3, 0xc0, 0xe4, 0x57, 0xea, 0xae, 0x23, 0x6b, 0x45, 0xa5, 0xed, 0x4f, 0x1d, 0x92,
    0x86, 0xaf, 0x7c, 0x1f, 0x3e, 0xdc, 0x5e, 0x0b, 0xa6, 0x39, 0xd5, 0x5d, 0xd9, 0x5a, 0x51, 0x6c,
    0x8b, 0x9a, 0xfb, 0xb0, 0x74, 0x2b, 0xf0, 0x84, 0xdf, 0xcb, 0x34, 0x76, 0x6d, 0xa9, 0xd1, 0x04,
    0x14, 0x3a, 0xde, 0x11, 0x32, 0x9c, 0x53, 0xf2, 0xfe, 0xcf, 0xc3, 0x7a, 0x24, 0xe8, 0x60, 0x69,
    0xaa, 0xa0, 0xa1, 0x62, 0x54, 0x1e, 0xe0, 0x64, 0x10, 0x00, 0xa3, 0x75, 0x8a, 0xe6, 0x09, 0xdd,
    0x87, 0x83, 0xcd, 0x90, 0x73, 0xf6, 0x9d, 0xbf, 0x52, 0xd8, 0xc8, 0xc6, 0x81, 0x6f, 0x13, 0x63,
    0xe9, 0xa7, 0x9f, 0xbc, 0x29, 0xf9, 0x2f, 0xb4, 0x78, 0x06, 0xe7, 0x71, 0xd4, 0xab, 0x88, 0x8d,
    0x72, 0xb9, 0xf8, 0xac, 0x36, 0x2a, 0x3c, 0xf1, 0x40, 0xd3, 0xbb, 0x43, 0x15, 0xad, 0x77, 0x80,
    0x82, 0xec, 0x27, 0xe5, 0x85, 0x35, 0x0c, 0x41, 0xef, 0x93, 0x19, 0x21, 0x0e, 0x4e, 0x65, 0xbd,
    0xb8, 0x8f, 0xeb, 0xce, 0x30, 0x5f, 0xc5, 0x1a, 0xe1, 0xca, 0x47, 0x3d, 0x01, 0xd6, 0x56, 0x4d,
    0x0d, 0x66, 0xcc, 0x2d, 0x12, 0x20, 0xb1, 0x99, 0x4c, 0xc2, 0x7e, 0x05, 0xb7, 0x31, 0x17, 0xd7,
    0x58, 0x61, 0x1b, 0x1c, 0x0f, 0x16, 0x18, 0x22, 0x44, 0xb2, 0xb5, 0x91, 0x08, 0xa8, 0xfc, 0x50,
    0xd0, 0x7d, 0x89, 0x97, 0x5b, 0x95, 0xff, 0xd2, 0xc4, 0x48, 0xf7, 0xdb, 0x03, 0xda, 0x3f, 0x94,
    0x5c, 0x02, 0x4a, 0x33, 0x67, 0xf3, 0x7f, 0xe2, 0x9b, 0x26, 0x37, 0x3b, 0x96, 0x4b, 0xbe, 0x2e,
    0x79, 0x8c, 0x6e, 0x8e, 0xf5, 0xb6, 0xfd, 0x59, 0x98, 0x6a, 0x46, 0xba, 0x25, 0x42, 0xa2, 0xfa,
    0x07, 0x55, 0xee, 0x0a, 0x49, 0x68, 0x38, 0xa4, 0x28, 0x7b, 0xc9, 0xc1, 0xe3, 0xf4, 0xc7, 0x9e
}

--[[
   F-function takes two parameters.  One is 64-bit input data F_IN.  The
   other is 64-bit subkey KE.  F-function returns 64-bit data F_OUT.
]]
local function F(a, b)
    --[[
       var x as 64-bit unsigned integer;
       var t1, t2, t3, t4, t5, t6, t7, t8 as 8-bit unsigned integer;
       var y1, y2, y3, y4, y5, y6, y7, y8 as 8-bit unsigned integer;
    ]]
    local x = a ^ b        
    --[[
       t1 = (x >> 56)
       t2 = (x >> 48) & MASK8;
       t3 = (x >> 40) & MASK8;
       t4 = (x >> 32) & MASK8;
       t5 = (x >> 24) & MASK8;
       t6 = (x >> 16) & MASK8;
       t7 = (x >>  8) & MASK8;
       t8 =  x        & MASK8;
    ]]        
    local t1 = x:rshift(56)         
    local t2 = x:rshift(48) * MASK8
    local t3 = x:rshift(40) * MASK8
    local t4 = x:rshift(32) * MASK8
    local t5 = x:rshift(24) * MASK8 
    local t6 = x:rshift(16) * MASK8
    local t7 = x:rshift(8) * MASK8
    local t8 = x * MASK8
    --[[
       t1 = SBOX1[t1];
       t2 = SBOX2[t2];
       t3 = SBOX3[t3];
       t4 = SBOX4[t4];
       t5 = SBOX2[t5];
       t6 = SBOX3[t6];
       t7 = SBOX4[t7];
       t8 = SBOX1[t8];
    ]]
    t1 = SBOX1[t1.right]
    t2 = SBOX2[t2.right]
    t3 = SBOX3[t3.right]
    t4 = SBOX4[t4.right]
    t5 = SBOX2[t5.right]
    t6 = SBOX3[t6.right]
    t7 = SBOX4[t7.right]
    t8 = SBOX1[t8.right]

    --[[
       y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
       y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
       y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
       y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
       y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
       y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
       y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
       y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
    ]]
    local y1 = AND(XOR(t1, t3, t4, t6, t7, t8), 0xff)
    local y2 = AND(XOR(t1, t2, t4, t5, t7, t8), 0xff)
    local y3 = AND(XOR(t1, t2, t3, t5, t6, t8), 0xff)
    local y4 = AND(XOR(t2, t3, t4, t5, t6, t7), 0xff)
    local y5 = AND(XOR(t1, t2, t6, t7, t8), 0xff)
    local y6 = AND(XOR(t2, t3, t5, t7, t8), 0xff)
    local y7 = AND(XOR(t3, t4, t5, t6, t8), 0xff)
    local y8 = AND(XOR(t1, t4, t5, t6, t7), 0xff)
    
    y1 = LSHIFT(y1, 24)
    y2 = LSHIFT(y2, 16)
    y3 = LSHIFT(y3, 8)
    y5 = LSHIFT(y5, 24)
    y6 = LSHIFT(y6, 16)
    y7 = LSHIFT(y7, 8)
    --[[
       F_OUT = (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32)
       | (y5 << 24) | (y6 << 16) | (y7 <<  8) | y8;
       return FO_OUT;
    ]]
    return qword(OR(y1, y2, y3, y4), OR(y5, y6, y7, y8))
end

--[[
    FL-function takes two parameters.  One is 64-bit input data FL_IN.
   The other is 64-bit subkey KE.  FL-function returns 64-bit data
   FL_OUT.
]]
local function FL(a, b)
    --[[
        
       var x1, x2 as 32-bit unsigned integer;
       var k1, k2 as 32-bit unsigned integer;
       x1 = FL_IN >> 32;
       x2 = FL_IN & MASK32;
       k1 = KE >> 32;
       k2 = KE & MASK32;
       x2 = x2 ^ ((x1 & k1) <<< 1);
       x1 = x1 ^ (x2 | k2);
       FL_OUT = (x1 << 32) | x2;
    ]]
    local x1 = a.left
    local x2 = a.right
    local k1 = b.left
    local k2 = b.right
    x2 = XOR(x2, ROL(AND(x1, k1), 1))
    x1 = XOR(x1, OR(x2, k2))
    return qword(x1, x2)
end 

local function FLINV(a, b)
    --[[
       var y1, y2 as 32-bit unsigned integer;
       var k1, k2 as 32-bit unsigned integer;
       y1 = FLINV_IN >> 32;
       y2 = FLINV_IN & MASK32;
       k1 = KE >> 32;
       k2 = KE & MASK32;
       y1 = y1 ^ (y2 | k2);
       y2 = y2 ^ ((y1 & k1) <<< 1);
       FLINV_OUT = (y1 << 32) | y2;
    ]]
    local y1 = a.left
    local y2 = a.right
    local k1 = b.left
    local k2 = b.right
    y1 = XOR(y1, OR(y2, k2))
    y2 = XOR(y2, ROL(AND(y1, k1), 1))
    return qword(y1, y2)
end

--[[
    In the key schedule part of Camellia, the 128-bit variables of KL and
   KR are defined as follows.  For 128-bit keys, the 128-bit key K is
   used as KL and KR is 0.  For 192-bit keys, the leftmost 128-bits of
   key K are used as KL and the concatenation of the rightmost 64-bits
   of K and the complement of the rightmost 64-bits of K are used as KR.
   For 256-bit keys, the leftmost 128-bits of key K are used as KL and
   the rightmost 128-bits of K are used as KR.

   128-bit key K:
       KL = K;    KR = 0;

   192-bit key K:
       KL = K >> 64;
       KR = ((K & MASK64) << 64) | (~(K & MASK64));

   256-bit key K:
       KL = K >> 128;
       KR = K & MASK128;

   The 128-bit variables KA and KB are generated from KL and KR as
   follows.  Note that KB is used only if the length of the secret key
   is 192 or 256 bits.  D1 and D2 are 64-bit temporary variables.  F-
   function is described in Section 2.4.
]]
local function schedule(k1, k2)
    local KL, KR = k1, oword(k2, -k2)

    local D1 = (KL.left ^ KR.left)      -- D1 = (KL ^ KR) >> 64;
    local D2 = (KL.right ^ KR.right)    -- D2 = (KL ^ KR) & MASK64;
    D2 = D2 ^ F(D1, SIGMA1)             -- D2 = D2 ^ F(D1, Sigma1);
    D1 = D1 ^ F(D2, SIGMA2)             -- D1 = D1 ^ F(D2, Sigma2);
    D1 = D1 ^ KL.left                   -- D1 = D1 ^ (KL >> 64);
    D2 = D2 ^ KL.right                  -- D2 = D2 ^ (KL & MASK64);
    D2 = D2 ^ F(D1, SIGMA3)             -- D2 = D2 ^ F(D1, Sigma3);
    D1 = D1 ^ F(D2, SIGMA4)             -- D1 = D1 ^ F(D2, Sigma4);
    local KA = oword(D1, D2)            -- KA = (D1 << 64) | D2;
    D1 = (KA.left ^ KR.left)            -- D1 = (KA ^ KR) >> 64;
    D2 = (KA.right ^ KR.right)          -- D2 = (KA ^ KR) & MASK64;
    D2 = D2 ^ F(D1, SIGMA5)             -- D2 = D2 ^ F(D1, Sigma5);
    D1 = D1 ^ F(D2, SIGMA6)             -- D1 = D1 ^ F(D2, Sigma6);
    local KB = oword(D1, D2)            -- KB = (D1 << 64) | D2; 
    local kw1 = KL.left                 -- kw1 = (KL <<<   0) >> 64;
    local kw2 = KL.right                -- kw2 = (KL <<<   0) & MASK64;
    local k1  = KB.left                 -- k1  = (KB <<<   0) >> 64;
    local k2  = KB.right                -- k2  = (KB <<<   0) & MASK64;
    local k3  = KR:rol(15).left         -- k3  = (KR <<<  15) >> 64;
    local k4  = KR:rol(15).right        -- k4  = (KR <<<  15) & MASK64;
    local k5  = KA:rol(15).left         -- k5  = (KA <<<  15) >> 64;
    local k6  = KA:rol(15).right        -- k6  = (KA <<<  15) & MASK64;
    local ke1 = KR:rol(30).left         -- ke1 = (KR <<<  30) >> 64;
    local ke2 = KR:rol(30).right        -- ke2 = (KR <<<  30) & MASK64;
    local k7  = KB:rol(30).left         -- k7  = (KB <<<  30) >> 64;
    local k8  = KB:rol(30).right        -- k8  = (KB <<<  30) & MASK64;
    local k9  = KL:rol(45).left         -- k9  = (KL <<<  45) >> 64;
    local k10 = KL:rol(45).right        -- k10 = (KL <<<  45) & MASK64;
    local k11 = KA:rol(45).left         -- k11 = (KA <<<  45) >> 64;
    local k12 = KA:rol(45).right        -- k12 = (KA <<<  45) & MASK64;
    local ke3 = KL:rol(60).left         -- ke3 = (KL <<<  60) >> 64;
    local ke4 = KL:rol(60).right        -- ke4 = (KL <<<  60) & MASK64;
    local k13 = KR:rol(60).left         -- k13 = (KR <<<  60) >> 64;
    local k14 = KR:rol(60).right        -- k14 = (KR <<<  60) & MASK64;
    local k15 = KB:rol(60).left         -- k15 = (KB <<<  60) >> 64;
    local k16 = KB:rol(60).right        -- k16 = (KB <<<  60) & MASK64;
    local k17 = KL:rol(77).left         -- k17 = (KL <<<  77) >> 64;
    local k18 = KL:rol(77).right        -- k18 = (KL <<<  77) & MASK64;
    local ke5 = KA:rol(77).left         -- ke5 = (KA <<<  77) >> 64;
    local ke6 = KA:rol(77).right        -- ke6 = (KA <<<  77) & MASK64;
    local k19 = KR:rol(94).left         -- k19 = (KR <<<  94) >> 64;
    local k20 = KR:rol(94).right        -- k20 = (KR <<<  94) & MASK64;
    local k21 = KA:rol(94).left         -- k21 = (KA <<<  94) >> 64;
    local k22 = KA:rol(94).right        -- k22 = (KA <<<  94) & MASK64;
    local k23 = KL:rol(111).left        -- k23 = (KL <<< 111) >> 64;
    local k24 = KL:rol(111).right       -- k24 = (KL <<< 111) & MASK64;
    local kw3 = KB:rol(111).left        -- kw3 = (KB <<< 111) >> 64;
    local kw4 = KB:rol(111).right       -- kw4 = (KB <<< 111) & MASK64;

    local w = {
        kw1.left, kw1.right, kw2.left, kw2.right,
        kw3.left, kw3.right, kw4.left, kw4.right
    }
    local e = {
        ke1.left, ke1.right, ke2.left, ke2.right,
        ke3.left, ke3.right, ke4.left, ke4.right,
        ke5.left, ke5.right, ke6.left, ke6.right
    }
    local k = {
        k1.left, k1.right, k2.left, k2.right, 
        k3.left, k3.right, k4.left, k4.right, 
        k5.left, k5.right, k6.left, k6.right, 
        k7.left, k7.right, k8.left, k8.right, 
        k9.left, k9.right, k10.left, k10.right, 
        k11.left, k11.right, k12.left, k12.right,
        k13.left, k13.right, k14.left, k14.right, 
        k15.left, k15.right, k16.left, k16.right,
        k17.left, k17.right, k18.left, k18.right,
        k19.left, k19.right, k20.left, k20.right,
        k21.left, k21.right, k22.left, k22.right,
        k23.left, k23.right, k24.left, k24.right
    }
    return {
        w = w,
        e = e,
        k = k
    }
end
--[[
    
   128-bit plaintext M is divided into the left 64-bit D1 and the right
   64-bit D2.

   D1 = M >> 64;
   D2 = M & MASK64;

   Encryption is performed using an 18-round Feistel structure with FL-
   and FLINV-functions inserted every 6 rounds. F-function, FL-function,
   and FLINV-function are described in Section 2.4.

]]

local function loadQWords(tbl)
    local t = {}
    local c = 1
    for i = 1, #tbl, 2 do
        t[c] = qword(tbl[i], tbl[i + 1])
        c = c + 1
    end
    return t
end 

local function encrypt(self, data)
    local ke, kw = loadQWords(self.e), loadQWords(self.w)
    local k = loadQWords(self.k)
    local D1 = data.left
    local D2 = data.right

    D1 = D1 ^ kw[1]
    D2 = D2 ^ kw[2]
    D2 = D2 ^ F(D1, k[1]);     -- Round 1
    D1 = D1 ^ F(D2, k[2]);     -- Round 2
    D2 = D2 ^ F(D1, k[3]);     -- Round 3
    D1 = D1 ^ F(D2, k[4]);     -- Round 4
    D2 = D2 ^ F(D1, k[5]);     -- Round 5
    D1 = D1 ^ F(D2, k[6]);     -- Round 6
    D1 = FL   (D1, ke[1]);     -- FL
    D2 = FLINV(D2, ke[2]);     -- FLINV
    D2 = D2 ^ F(D1, k[7]);     -- Round 7
    D1 = D1 ^ F(D2, k[8]);     -- Round 8
    D2 = D2 ^ F(D1, k[9]);     -- Round 9
    D1 = D1 ^ F(D2, k[10]);    -- Round 10
    D2 = D2 ^ F(D1, k[11]);    -- Round 11
    D1 = D1 ^ F(D2, k[12]);    -- Round 12
    D1 = FL   (D1, ke[3]);     -- FL
    D2 = FLINV(D2, ke[4]);     -- FLINV
    D2 = D2 ^ F(D1, k[13]);    -- Round 13
    D1 = D1 ^ F(D2, k[14]);    -- Round 14
    D2 = D2 ^ F(D1, k[15]);    -- Round 15
    D1 = D1 ^ F(D2, k[16]);    -- Round 16
    D2 = D2 ^ F(D1, k[17]);    -- Round 17
    D1 = D1 ^ F(D2, k[18]);    -- Round 18
    D1 = FL   (D1, ke[5]);     -- FL
    D2 = FLINV(D2, ke[6]);     -- FLINV
    D2 = D2 ^ F(D1, k[19]);    -- Round 19
    D1 = D1 ^ F(D2, k[20]);    -- Round 20
    D2 = D2 ^ F(D1, k[21]);    -- Round 21
    D1 = D1 ^ F(D2, k[22]);    -- Round 22
    D2 = D2 ^ F(D1, k[23]);    -- Round 23
    D1 = D1 ^ F(D2, k[24]);    -- Round 24
    D2 = D2 ^ kw[3];           -- Postwhitening
    D1 = D1 ^ kw[4];

    -- C = (D2 << 64) | D1;
    return oword(D2, D1)
end 


local function decrypt(self, data)
    local ke, kw = loadQWords(self.e), loadQWords(self.w)
    local k = loadQWords(self.k)
    local D1 = data.left
    local D2 = data.right
    D2 = D2 ^ kw[4]
    D1 = D1 ^ kw[3]
    D2 = D2 ^ F(D1, k[24]);     -- Round 1
    D1 = D1 ^ F(D2, k[23]);     -- Round 2
    D2 = D2 ^ F(D1, k[22]);     -- Round 3
    D1 = D1 ^ F(D2, k[21]);     -- Round 4
    D2 = D2 ^ F(D1, k[20]);     -- Round 5
    D1 = D1 ^ F(D2, k[19]);     -- Round 6
    D1 = FL   (D1, ke[6]);     -- FL
    D2 = FLINV(D2, ke[5]);     -- FLINV
    D2 = D2 ^ F(D1, k[18]);     -- Round 1
    D1 = D1 ^ F(D2, k[17]);     -- Round 2
    D2 = D2 ^ F(D1, k[16]);     -- Round 3
    D1 = D1 ^ F(D2, k[15]);     -- Round 4
    D2 = D2 ^ F(D1, k[14]);     -- Round 5
    D1 = D1 ^ F(D2, k[13]);     -- Round 6
    D1 = FL   (D1, ke[4]);     -- FL
    D2 = FLINV(D2, ke[3]);     -- FLINV
    D2 = D2 ^ F(D1, k[12]);     -- Round 7
    D1 = D1 ^ F(D2, k[11]);     -- Round 8
    D2 = D2 ^ F(D1, k[10]);     -- Round 9
    D1 = D1 ^ F(D2, k[9]);    -- Round 10
    D2 = D2 ^ F(D1, k[8]);    -- Round 11
    D1 = D1 ^ F(D2, k[7]);    -- Round 12
    D1 = FL   (D1, ke[2]);     -- FL
    D2 = FLINV(D2, ke[1]);     -- FLINV
    D2 = D2 ^ F(D1, k[6]);    -- Round 13
    D1 = D1 ^ F(D2, k[5]);    -- Round 14
    D2 = D2 ^ F(D1, k[4]);    -- Round 15
    D1 = D1 ^ F(D2, k[3]);    -- Round 16
    D2 = D2 ^ F(D1, k[2]);    -- Round 17
    D1 = D1 ^ F(D2, k[1]);    -- Round 18
    D1 = D1 ^ kw[2];           -- Postwhitening
    D2 = D2 ^ kw[1];

    -- C = (D2 << 64) | D1;
    return oword(D2, D1)
end 

local m = {}
m.__index = m 
m.new = function (a, b, c, d, e, f)
    local new = schedule(oword(qword(a, b), qword(c, d)), qword(e, f))
    setmetatable(new, m)
    return new 
end

m.encrypt = function (k, a, b, c, d)
    return encrypt(k, oword(qword(a, b), qword(c, d))):split()
end

m.decrypt = function (k, a, b, c, d)
    return decrypt(k, oword(qword(a, b), qword(c, d))):split()
end

return m
