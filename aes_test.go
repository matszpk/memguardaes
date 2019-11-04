// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package memguardaes
 
import (
    "bytes"
    "crypto/aes"
    "crypto/rand"
    "github.com/awnumar/memguard"
    "testing"
)

func randRead(t *testing.T, size int) []byte {
    r := make([]byte, size)
    sz, err := rand.Read(r)
    if err!=nil {
        t.Fatal("Can't read random:", err)
    }
    if sz!=len(r) {
        t.Fatal("Can't read whole random")
    }
    return r
}

func TestMemguardAES(t *testing.T) {
    msg := randRead(t, aes.BlockSize)
    
    for i:=0; i < 3; i++ {
        for _, ks := range []int{ 128, 192, 256 } {
            key := randRead(t, ks>>3)
            
            keyBuf := memguard.NewBufferFromBytes(key)
            defer keyBuf.Destroy()
            
            encrypted := make([]byte, aes.BlockSize)
            mencrypted := make([]byte, aes.BlockSize)
            ciph, err := aes.NewCipher(key)
            if err!=nil {
                t.Fatal("Can't get standard AES cipher:", err)
            }
            mciph, err := NewCipher(key)
            if err!=nil {
                t.Fatal("Can't get Memguard AES cipher:", err)
            }
            defer mciph.Destroy()
            keyBuf.Destroy()
            ciph.Encrypt(encrypted, msg)
            mciph.Encrypt(mencrypted, msg)
            
            if !bytes.Equal(encrypted, mencrypted) {
                t.Errorf("Encrypted data mismatch: %v!=%v", encrypted, mencrypted)
            }
            
            decrypted := make([]byte, aes.BlockSize)
            mdecrypted := make([]byte, aes.BlockSize)
            ciph.Decrypt(decrypted, encrypted)
            mciph.Decrypt(mdecrypted, mencrypted)
            if !bytes.Equal(msg, decrypted) {
                t.Errorf("Decrypted and original data mismatch: %v!=%v", msg, decrypted)
            }
            if !bytes.Equal(decrypted, mdecrypted) {
                t.Errorf("Decrypted data mismatch: %v!=%v", decrypted, mdecrypted)
            }
        }
    }
}
