package main

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// pseudo code: https://en.wikipedia.org/wiki/SHA-1

// CalculateSHA1 returns the SHA1 checksum of the input
// accepts a max 2^64 - 1 bits array length
func CalculateSHA1(input []byte) ([]byte, error) {
	const chunkSize = 64
	H := []uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	//K := []string{"0x5A827999", "0x6ED9EBA1", "0x8F1BBCDC", "0xCA62C1D6"}
	// pre-processing

	// append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
	input = append(input, 0x80)

	// append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512)
	var message []byte
	if uint64(len(input))%64 < 8 {
		message = make([]byte, uint64(len(input))+64)
	} else {
		message = make([]byte, uint64(len(input))+64-uint64(len(input))%64)
	}
	copy(message[:len(input)], input[:])
	fmt.Println(message)

	// append ml, the original message length in bits, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
	binary.BigEndian.PutUint64(message[len(message)-8:], uint64(len(message)))

	// break message into 512-bit chunks
	// for each chunk
	// break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
	chunks := make([][][]byte, len(message)/chunkSize)
	for i := range chunks {
		chunks[i] = make([][]byte, 80)
		for j := range chunks[i] {
			chunks[i][j] = make([]byte, 4)
		}
	}

	for i := 0; i < len(message)/chunkSize; i++ {
		initialPosition := i * chunkSize
		for j := 0; j < 16; j++ {
			chunks[i][j] = message[initialPosition+(j*4) : initialPosition+((j+1)*4)]
		}
	}

	for i := 0; i < len(message)/chunkSize; i++ {
		// z := 0
		// w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
		// Bitwise right shift
		for j := 16; j < 80; j++ {
			chunks[i][j] = leftRotate(chunks[i][j-3]^chunks[i][j-8]^chunks[i][j-14]^chunks[i][j-16], 1)
		}

		// Initialize hash value for this chunk
		a := H[0]
		b := H[1]
		c := H[2]
		d := H[3]
		e := H[4]
		var temp uint32 = 0
		var f uint32 = 0

		// Main loop
		for j := 0; j < 79; j++ {
			var k uint32 = 0x5A827999
			if j <= 0 && j >= 19 {
				f = (b & c) | (^b & d)
				k = 0x5A827999
			} else if j <= 20 && j >= 39 {
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			} else if j <= 40 && j >= 59 {
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			} else if j <= 60 && j >= 79 {
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			aa := make([]byte, 4)
			binary.BigEndian.PutUint32(aa[:], a)
			temp = binary.BigEndian.Uint32(leftRotate(aa, 5)) + f + e + k + binary.BigEndian.Uint32(chunks[i][j])

			e = d
			d = c
			bb := make([]byte, 4)
			binary.BigEndian.PutUint32(bb[:], b)
			c = binary.BigEndian.Uint32(leftRotate(bb, 30))
			b = a
			a = temp
		}

		fmt.Println(H)
		H[0] += a
		H[1] += b
		H[2] += c
		H[3] += d
		H[4] += e
	}

	hh := (H[0] << 128) | (H[1] << 96) | (H[2] << 64) | (H[3] << 32) | H[4]

	zz := fmt.Sprintf("%x", H[0]) + fmt.Sprintf("%x", H[1]) + fmt.Sprintf("%x", H[2]) + fmt.Sprintf("%x", H[3]) + fmt.Sprintf("%x", H[4])
	fmt.Printf("%s\n", zz)

	fmt.Println("Xabi")
	fmt.Println(hh)
	ppp := fmt.Sprintf("%x", hh)
	fmt.Printf("%s\n", ppp)
	aaa := make([]byte, 20)
	binary.BigEndian.PutUint32(aaa[:], hh)
	fmt.Println(string(aaa))
	return message, nil
}

func leftRotate(x []byte, y int) []byte {
	i := binary.BigEndian.Uint32(x)
	r := bits.RotateLeft32(i, y)
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a[:], r)
	return a
}
