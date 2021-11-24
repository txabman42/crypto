package ma

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
)

// pseudo code: https://en.wikipedia.org/wiki/SHA-1

// CalculateSHA1 returns the SHA1 checksum of the input
// accepts a max 2^64 - 1 bits array length
func CalculateSHA1(input []byte) ([]byte, error) {
	const chunkSize = 64
	H := []int{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	//K := []string{"0x5A827999", "0x6ED9EBA1", "0x8F1BBCDC", "0xCA62C1D6"}
	// pre-processing
	ml := len(input)

	// append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
	input = append(input, 0x80)

	// append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512)
	var message []byte
	if uint64(len(input))%64 < 8 {
		message = make([]byte, int64(len(input))+64)
	} else {
		message = make([]byte, int64(len(input))+64-int64(len(input))%64)
	}
	copy(message[:len(input)], input[:])
	fmt.Println(input)
	fmt.Println(message)
	fmt.Println(binary.BigEndian.Uint64(message))

	// append ml, the original message length in bits, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
	binary.BigEndian.PutUint64(message[len(message)-8:], uint64(ml))
	fmt.Printf("% 08b", message)
	fmt.Println()

	cccc := "01100100011101010110110101101101011110010010000001110100011001010111100001110100100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000"
	message, _ = bitStringToBytes(cccc)

	// break message into 512-bit chunks
	// for each chunk
	// break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
	fmt.Println(len(message))
	fmt.Println(len(message) / chunkSize)
	chunks := make([][]int32, len(message)/chunkSize)
	for i := range chunks {
		chunks[i] = make([]int32, 80)
	}

	for i := 0; i < len(message)/chunkSize; i++ {
		initialPosition := i * chunkSize
		fmt.Println("Xabi")
		for j := 0; j < 16; j++ {
			chunks[i][j] = int32(binary.BigEndian.Uint32(message[initialPosition+(j*4) : initialPosition+((j+1)*4)]))
			mmm := fmt.Sprintf("%x", chunks[i][j])
			fmt.Printf("%s", mmm)
		}

		// z := 0
		// w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
		// Bitwise right shift
		for j := 16; j < 80; j++ {
			chunks[i][j] = int32(RotateLeft32(int(chunks[i][j-3]^chunks[i][j-8]^chunks[i][j-14]^chunks[i][j-16]), 1))
		}

		// Initialize hash value for this chunk
		a := int32(H[0])
		b := int32(H[1])
		c := int32(H[2])
		d := int32(H[3])
		e := int32(H[4])
		var temp int32 = 0
		var f int32 = 0

		// Main loop
		for j := 0; j <= 79; j++ {
			var k int = 0x5A827999
			if j >= 0 && j <= 19 {
				f = int32((b & c) | ((^b) & d))
				k = 0x5A827999
			} else if j >= 20 && j <= 39 {
				f = int32(b ^ c ^ d)
				k = 0x6ED9EBA1
			} else if j >= 40 && j <= 59 {
				f = int32((b & c) | (b & d) | (c & d))
				k = 0x8F1BBCDC
			} else if j >= 60 && j <= 79 {
				f = int32(b ^ c ^ d)
				k = 0xCA62C1D6
			}

			temp = int32(RotateLeft32(int(a), 5)) + f + e + int32(k) + chunks[i][j]

			e = d
			d = c
			c = int32(RotateLeft32(int(b), 30))
			b = a
			a = temp
		}

		H[0] = int(int32(H[0])) + int(a)
		H[1] = int(int32(H[1])) + int(b)
		H[2] = int(int32(H[2])) + int(c)
		H[3] = int(int32(H[3])) + int(d)
		H[4] = int(int32(H[4])) + int(e)
	}

	//hh := (H[0] << 128) | (H[1] << 96) | (H[2] << 64) | (H[3] << 32) | H[4]
	aaaa := hex.EncodeToString([]byte(fmt.Sprintf("%08x", H[0])))
	fmt.Printf("%v\n", aaaa)
	bbbb := hex.EncodeToString([]byte(fmt.Sprintf("%08x", uint32(H[0]))))
	fmt.Printf("%s\n", bbbb)
	bbbb = fmt.Sprintf("%x", uint32(H[0]))
	fmt.Printf("%s\n", bbbb)
	zz := fmt.Sprintf("%x", H[0]) + fmt.Sprintf("%x", H[1]) + fmt.Sprintf("%x", H[2]) + fmt.Sprintf("%x", H[3]) + fmt.Sprintf("%x", H[4])
	fmt.Printf("%s\n", zz)

	return message, nil
}

func leftRotate(x uint32, y int) uint32 {
	return bits.RotateLeft32(x, y)
}

func RotateLeft32(x int, k int) int {
	const n = 32
	s := int(k) & (n - 1)
	return int(int32(x)<<s | int32(int(uint32(x))>>(32-s)))
}

var ErrRange = errors.New("value out of range")

func bitStringToBytes(s string) ([]byte, error) {
	b := make([]byte, (len(s)+(8-1))/8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '1' {
			return nil, ErrRange
		}
		b[i>>3] |= (c - '0') << uint(7-i&7)
	}
	return b, nil
}

func GetTwoComplement(num int8) string {
	var ret = []byte("00000000")

	for i := range ret {
		if ((1 << uint(i)) & uint(num)) > 0 {
			ret[i] = '1'
		}
	}
	beg := 0
	end := len(ret) - 1
	for beg <= end {
		ret[beg], ret[end] = ret[end], ret[beg]
		beg++
		end--
	}
	return string(ret)
}
