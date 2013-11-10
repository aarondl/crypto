// Package sha256 wraps openssl's sha256 library. It is a drop in replacement
// for crypto/sha256.
package sha256

import (
	"hash"
	"unsafe"
)

// #cgo LDFLAGS: -lcrypto
// #include <openssl/sha.h>
import "C"

// The size of a SHA256 hash in bytes.
const Size = 32

// The blocksize of SHA256 in bytes.
const BlockSize = 64

// digest represents the partial evaluation of a checksum.
type digest struct {
	ctx *C.SHA256_CTX
}

func (d *digest) Reset() {
	C.SHA256_Init(d.ctx)
}

// New returns a new hash.Hash computing the SHA256 hash.
func New() hash.Hash {
	d := &digest{new(C.SHA256_CTX)}
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (n int, err error) {
	C.SHA256_Update(
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

	C.SHA256_Final(
		(*C.uchar)(unsafe.Pointer(&in[i])),
		d.ctx,
	)

	return in
}
