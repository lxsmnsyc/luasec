local digest = require "luasec.src.sha512-256"

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
    "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8",
    "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    "0cf471fd17ed69d990daf3433c89b16d63dec1bb9cb42a6094604ee5d7b4e9fb",
    "fc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26",
    "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8",
    "2c9fdbc0c90bdd87612ee8455474f9044850241dc105b1e8b94b8ddf5fac9148"
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