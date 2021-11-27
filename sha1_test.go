package ma

import (
	"crypto/sha1"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateSHA1OK(t *testing.T) {
	n := []byte("dummy text")
	expected := fmt.Sprintf("%x", sha1.Sum(n))
	res := CalculateSHA1(n)
	assert.Equal(t, expected, res)
}
