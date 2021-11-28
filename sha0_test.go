package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateSHA0OK(t *testing.T) {
	n := []byte("message digest")
	// expected := fmt.Sprintf("%x", sha1.Sum(n))
	res := CalculateSHA0(n)
	assert.Equal(t, "c1b0f222d150ebb9aa36a40cafdc8bcbed830b14", res)
}
