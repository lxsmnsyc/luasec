# luasec
Crypto-related algorithms (encryption, hash, etc.)

Includes (currently):
- SHA-224
- SHA-256
- SHA-512
- SHA-384
- SHA-512/224
- SHA-512/256
- AES-128
- AES-192
- AES-256

I am currently writing an int64 emulator library so that every library can handle 64-bits of information
(lua can only handle 2^53 bits)

To run tests, simply run "require "luasec.test.<lib-name>" " on LuaJIT