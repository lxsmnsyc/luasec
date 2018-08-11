local digest = require "luasec.src.sha256"

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
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
    "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
    "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
    "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
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