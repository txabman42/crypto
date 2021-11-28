package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// pseudo code: https://en.wikipedia.org/wiki/SHA-1

// CalculateSHA1 returns the SHA1 checksum of the input
// accepts a max 2^64 - 1 bits array length
func CalculateSHA0(input []byte) string {
	const chunkSize = 64
	H := []uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	K := []uint32{0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6}

	// pre-processing
	ml := len(input) * 8

	// append the bit '1' to the input message e.g. by adding 0x80 if message length is a multiple of 8 bits.
	input = append(input, 0x80)

	// append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512)
	var message []byte
	mlBits := int64(len(input)) + 64
	if uint64(len(input))%64 >= 8 {
		mlBits -= int64(len(input)) % 64
	}
	message = make([]byte, mlBits)
	copy(message[:len(input)], input[:])

	// append ml, the original message length in bits, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
	binary.BigEndian.PutUint64(message[len(message)-8:], uint64(ml))

	// break message into 512-bit chunks
	// for each chunk
	// break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
	chunks := make([][]uint32, len(message)/chunkSize)
	for i := range chunks {
		chunks[i] = make([]uint32, 80)
	}

	for i := 0; i < len(message)/chunkSize; i++ {
		initialPosition := i * chunkSize
		for j := 0; j < 16; j++ {
			chunks[i][j] = binary.BigEndian.Uint32(message[initialPosition+(j*4) : initialPosition+((j+1)*4)])
		}

		// z := 0
		// w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
		// Bitwise right shift
		for j := 16; j < 80; j++ {
			chunks[i][j] = chunks[i][j-3]^chunks[i][j-8]^chunks[i][j-14]^chunks[i][j-16]
		}

		// Initialize hash value for this chunk
		a := H[0]
		b := H[1]
		c := H[2]
		d := H[3]
		e := H[4]
		var temp uint32 = 0
		var f uint32 = 0
		var k uint32

		// Main loop
		for j := 0; j <= 79; j++ {
			if j >= 0 && j <= 19 {
				f = (b & c) | ((^b) & d)
				k = K[0]
			} else if j >= 20 && j <= 39 {
				f = b ^ c ^ d
				k = K[1]
			} else if j >= 40 && j <= 59 {
				f = (b & c) | (b & d) | (c & d)
				k = K[2]
			} else if j >= 60 && j <= 79 {
				f = b ^ c ^ d
				k = K[3]
			}

			temp = rotateLeft(a, 5) + f + e + k + chunks[i][j]

			e = d
			d = c
			c = rotateLeft(b, 30)
			b = a
			a = temp
		}

		// Add this chunk's hash to result so far
		H[0] = H[0] + a
		H[1] = H[1] + b
		H[2] = H[2] + c
		H[3] = H[3] + d
		H[4] = H[4] + e
	}

	var result bytes.Buffer
	var hex string
	for i := 0; i < len(H); i++ {
	  hex = fmt.Sprintf("%x", H[i])
	  if len(hex) < 8 {
		result.WriteString("0")
	  }
	  result.WriteString(hex)
	}

	// Produce the final hash value (big-endian) as a 160-bit number
	return result.String()
}
