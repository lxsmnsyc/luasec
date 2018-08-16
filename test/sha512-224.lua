local digest = require "luasec.src.sha512-224"

local test = {
    (""),
    ("a"),
    ("abc"),
    ("message digest"),
    ("abcdefghijklmnopqrstuvwxyz"),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
    ("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
}

local result = {
    "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
    "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327",
    "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    "ad1a4db188fe57064f4f24609d2a83cd0afb9b398eb2fcaeaae2c564",
    "ff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8",
    "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3",
    "ae988faaa47e401a45f704d1272d99702458fea2ddc6582827556dd2"
}

for i = 1, 7 do
    local t, e = test[i], result[i]
    local r = digest(t)
    print("Comparing")
    print("Message: \t"..t)
    print("Result: \t"..r)
    print("Expected:\t"..e)
    print("Test Result:"..((r == e) and "Passed" or "Failed"))
    print("")
end