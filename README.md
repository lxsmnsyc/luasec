# luasec
Crypto-related algorithms (encryption, hash, etc.)

Includes (currently):
- SHA-224 (only capable of < 0xFFFFFFFF - 512 bits of message)
- SHA-256 (only capable of < 0xFFFFFFFF - 512 bits of message)
- AES-128
- AES-192
- AES-256

I am currently writing an int64 emulator library so that every library can handle 64-bits of information
(lua can only handle 2^53 bits)

To run tests, simply run "require "luasec.test.<lib-name>" " on LuaJIT