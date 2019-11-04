## MemguardAES

MemguardAES is AES implementation for GoLang that uses Memguard library to destroy key data
after encryption/decryption. Correct usage is:

```
mciph, err := memguardaes.Cipher(key)
if err!=nil { ... }
defer mciph.Destroy()
```

This version works with MeguardAES from 2019.11.
License: same as in GoLang - BSD-style license.
