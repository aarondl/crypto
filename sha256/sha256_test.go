package sha256

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	. "testing"
)

func Test_ShaCorrectness(t *T) {
	data := make([]byte, 64)
	rand.Read(data)

	hash := sha256.New()
	hash.Write(data)
	out1 := hash.Sum(nil)

	hash = New()
	hash.Write(data)
	out2 := hash.Sum(nil)

	if !bytes.Equal(out1, out2) {
		t.Error("out1 and out2 should not differ!")
	}
}

func Benchmark_SHA256_Stl(b *B) {
	b.StopTimer()
	data := make([]byte, 64)
	rand.Read(data)

	hash := sha256.New()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 50; j++ {
			hash.Write(data)
		}
		hash.Sum(nil)
	}
}

func Benchmark_SHA256_Lib(b *B) {
	b.StopTimer()
	data := make([]byte, 64)
	rand.Read(data)

	hash := New()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 50; j++ {
			hash.Write(data)
		}
		hash.Sum(nil)
		hash.Reset()
	}
}
