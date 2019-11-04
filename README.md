## MemguardAES

MemguardAES is AES implementation for GoLang that uses Memguard library to protect cipher key
while encrypting/decrypting. Correct usage is:

```
mciph, err := memguardaes.Cipher(key)
if err!=nil { ... }
defer mciph.Destroy()
```

This version works with MeguardAES from 2019.11.
License: same as in GoLang - BSD-style license.
