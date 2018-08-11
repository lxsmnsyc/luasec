local digest = require "luasec.src.sha224"

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
    "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
    "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
    "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9",
    "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e"
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