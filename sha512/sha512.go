// Package sha512 wraps openssl's sha512 library. It is a drop in replacement
// for crypto/sha512.
package sha512

import (
	"hash"
	"unsafe"
)

// #cgo LDFLAGS: -lcrypto
// #include <openssl/sha.h>
import "C"

// The size of a SHA512 hash in bytes.
const Size = 64

// The blocksize of SHA512 in bytes.
const BlockSize = 128

// digest represents the partial evaluation of a checksum.
type digest struct {
	ctx *C.SHA512_CTX
}

func (d *digest) Reset() {
	C.SHA512_Init(d.ctx)
}

// New returns a new hash.Hash computing the SHA512 hash.
func New() hash.Hash {
	d := &digest{new(C.SHA512_CTX)}
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (n int, err error) {
	C.SHA512_Update(
		d.ctx,
		unsafe.Pointer(&p[0]),
		C.size_t(len(p)),
	)
	return len(p), nil
}

func (d *digest) Sum(in []byte) []byte {
	var b [Size]byte

	i := len(in)

	if cap(in)-len(in) >= Size {
		in = in[:len(in)+Size]
	} else {
		in = append(in, b[:]...)
	}

	C.SHA512_Final(
		(*C.uchar)(unsafe.Pointer(&in[i])),
		d.ctx,
	)

	return in
}
