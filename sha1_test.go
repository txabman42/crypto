package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateSHA1OK(t *testing.T) {
	n := []byte("dummy text")
	res, err := CalculateSHA1([]byte(n))
	t.Log(res)
	//assert.Equal(t, n, res)
	assert.NoError(t, err)
}
