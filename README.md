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

### About: memlock

Sometime Linux memlock limit is too small to run tests of this library. If you have problems with
passing tests, then set up greater limits in `/etc/security/limits.conf` by adding/changing
following lines:

```
*               hard     memlock         XXX
*               soft     memlock         XXX
```
where XXX is number of kilobytes of memlock limit. Recommended value is equal or greater than 128
(can be greater).
