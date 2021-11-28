package crypto

import (
	"crypto/sha1"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateSHA1OK(t *testing.T) {
	n := []byte("dummy text")
	res := CalculateSHA1(n)
	assert.Equal(t, "f5d04899d2bbea2bacbf2227dc05bf70cffd78fe", res)
}

func BenchmarkSHA1(b *testing.B) {
  n := []byte("dummy text")
  for i := 0; i < b.N; i++ {
	  CalculateSHA1(n)
  }
}

func BenchmarkDefaultSHA1(b *testing.B) {
  n := []byte("dummy text")
  for i := 0; i < b.N; i++ {
	  sha1.Sum(n)
	  _ = fmt.Sprintf("%x", sha1.Sum(n))
  }
}
