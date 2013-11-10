/*
Package aes wraps openssl's implementation of aes. It is a drop in replacement
for crypto/aes, as well as implementing the CTR mode AES as well.
*/
package aes

// #cgo LDFLAGS: -lcrypto -lssl
// #include <openssl/aes.h>
import "C"

import (
	"crypto/cipher"
	"strconv"
	"unsafe"
)

const BlockSize = 16

type aesCipher struct {
	key    []byte
	encKey C.AES_KEY
	decKey C.AES_KEY
}

type aesCipherCTR struct {
	key    []byte
	iv     []byte
	aesKey C.AES_KEY
	num    C.uint
	ecount []byte
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the AES key, and must be 16, 24 or 32 bytes long
// or an error is thrown.
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	case 16, 24, 32:
		break
	default:
		return nil, KeySizeError(k)
	}

	block := &aesCipher{key: key}

	C.AES_set_encrypt_key(
		(*C.uchar)(unsafe.Pointer(&key[0])),
		C.int(len(key)*8),
		&block.encKey,
	)
	C.AES_set_decrypt_key(
		(*C.uchar)(unsafe.Pointer(&key[0])),
		C.int(len(key)*8),
		&block.decKey,
	)

	return block, nil
}

func (a *aesCipher) BlockSize() int { return BlockSize }

func (a *aesCipher) Encrypt(dst, src []byte) {
	C.AES_ecb_encrypt(
		(*C.uchar)(unsafe.Pointer(&src[0])),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
		&a.encKey,
		C.AES_ENCRYPT,
	)
}

func (a *aesCipher) Decrypt(dst, src []byte) {
	C.AES_ecb_encrypt(
		(*C.uchar)(unsafe.Pointer(&src[0])),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
		&a.decKey,
		C.AES_DECRYPT,
	)
}

// NewCipherCTR returns an AES128 CTR cipher stream.
func NewCipherCTR(key, iv []byte) (cipher.Stream, error) {
	k := len(key)
	switch k {
	case 16, 24, 32:
		break
	default:
		return nil, KeySizeError(k)
	}

	stream := &aesCipherCTR{
		key:    key,
		iv:     iv,
		num:    0,
		ecount: make([]byte, 16),
	}
	C.AES_set_encrypt_key(
		(*C.uchar)(unsafe.Pointer(&key[0])),
		C.int(len(key)*8),
		&stream.aesKey,
	)

	return stream, nil
}

func (a *aesCipherCTR) XORKeyStream(dst, src []byte) {
	C.AES_ctr128_encrypt(
		(*C.uchar)(unsafe.Pointer(&src[0])),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
		C.size_t(len(src)),
		&a.aesKey,
		(*C.uchar)(unsafe.Pointer(&a.iv[0])),
		(*C.uchar)(unsafe.Pointer(&a.ecount[0])),
		&a.num,
	)
}
