// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package memguardaes

import (
	"crypto/cipher"
	"strconv"
	"github.com/awnumar/memguard"
)

// The AES block size in bytes.
const BlockSize = 16

type BlockMG interface {
	cipher.Block
	
	Destroy()
}

// A cipher is an instance of AES encryption using a particular key.
type aesCipherMG struct {
	enc []uint32
	dec []uint32
	encBuf *memguard.LockedBuffer
	decBuf *memguard.LockedBuffer
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
func NewCipher(key []byte) (BlockMG, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16, 24, 32:
		break
	}
	return newCipherMG(key)
}

func (s *aesCipherMG) Destroy() {
	s.encBuf.Destroy()
	s.decBuf.Destroy()
}

// newCipherGeneric creates and returns a new cipher.Block
// implemented in pure Go.
func newCipherMG(key []byte) (BlockMG, error) {
	n := len(key) + 28
	encBuf := memguard.NewBuffer(4*n)
	decBuf := memguard.NewBuffer(4*n)
	c := aesCipherMG{encBuf.Uint32(), decBuf.Uint32(), encBuf, decBuf}
	expandKeyGo(key, c.enc, c.dec)
	encBuf.Freeze()
	decBuf.Freeze()
	return &c, nil
}

func (c *aesCipherMG) BlockSize() int { return BlockSize }

func (c *aesCipherMG) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	encryptBlockGo(c.enc, dst, src)
}

func (c *aesCipherMG) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	decryptBlockGo(c.dec, dst, src)
}
