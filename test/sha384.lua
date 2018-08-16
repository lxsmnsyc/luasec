local digest = require "luasec.src.sha384"

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
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
    "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
    "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
    "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026"
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