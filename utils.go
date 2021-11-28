package crypto

func rotateLeft(x uint32, k uint32) uint32 {
	const n = 32
	s := int(k) & (n - 1)
	return x<<s | x>>(32-s)
}
