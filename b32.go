// Package b32 implements loop unrolled uint64 to/from base32-encoded
// string/[]byte conversion, using a variant of RFC 4648 standard base32
// encoding alphabet (lowercase, unpadded).
package b32

import "bytes"

// RFC 4648 standard base32 encoding alphabet; lowercase.
const StdEncoding = "abcdefghijklmnopqrstuvwxyz234567"

var (
	encMap [32]byte
	decMap [256]byte
)

// EncodeUint64 writes a base32 encoding of uint64 n to dst, writing exactly 13
// bytes. It will panic if dst is of insufficient size.
func EncodeUint64(n uint64, dst []byte) {
	dst[12] = encMap[(n&0xf)<<1]
	dst[11] = encMap[(n>>4)&0x1f]
	dst[10] = encMap[(n>>9)&0x1f]
	dst[9] = encMap[(n>>14)&0x1f]
	dst[8] = encMap[(n>>19)&0x1f]
	dst[7] = encMap[(n>>24)&0x1f]
	dst[6] = encMap[(n>>29)&0x1f]
	dst[5] = encMap[(n>>34)&0x1f]
	dst[4] = encMap[(n>>39)&0x1f]
	dst[3] = encMap[(n>>44)&0x1f]
	dst[2] = encMap[(n>>49)&0x1f]
	dst[1] = encMap[(n>>54)&0x1f]
	dst[0] = encMap[n>>59]
}

// EncodeUint64ToString returns string containing base32 encoding of uint64 n.
func EncodeUint64ToString(n uint64) string {
	var buf [13]byte
	EncodeUint64(n, buf[:])

	return string(buf[:])
}

// DecodeUint64 decodes bytes of base32-encoded src, and returns the decoded
// value as uint64, and a bool value indicating whether the input is valid
// (i.e. contains valid base32 alphabet). It will attempt to decode exactly 13
// bytes from src, and will panic if src is of insufficient size.
func DecodeUint64(src []byte) (uint64, bool) {
	n := (uint64(decMap[src[12]]) >> 1) |
		(uint64(decMap[src[11]]) << 4) |
		(uint64(decMap[src[10]]) << 9) |
		(uint64(decMap[src[9]]) << 14) |
		(uint64(decMap[src[8]]) << 19) |
		(uint64(decMap[src[7]]) << 24) |
		(uint64(decMap[src[6]]) << 29) |
		(uint64(decMap[src[5]]) << 34) |
		(uint64(decMap[src[4]]) << 39) |
		(uint64(decMap[src[3]]) << 44) |
		(uint64(decMap[src[2]]) << 49) |
		(uint64(decMap[src[1]]) << 54) |
		(uint64(decMap[src[0]]) << 59)

	m := decMap[src[12]] | decMap[src[11]] | decMap[src[10]] | decMap[src[9]] |
		decMap[src[8]] | decMap[src[9]] | decMap[src[8]] | decMap[src[7]] |
		decMap[src[6]] | decMap[src[5]] | decMap[src[4]] | decMap[src[3]] |
		decMap[src[2]] | decMap[src[1]] | decMap[src[0]]

	return n, m&0xe0 == 0
}

// DecodeUint64FromString returns the decoded uint64 from base32-encoded string
// s, and a bool value indicating whether the input is valid (i.e. contains
// valid base32 alphabet). It will panic if the encoded input string is of
// insufficient size.
func DecodeUint64FromString(s string) (uint64, bool) {
	return DecodeUint64([]byte(s))
}

func init() {
	copy(encMap[:], []byte(StdEncoding))
	for i := range 256 {
		decMap[i] = byte(bytes.IndexByte(encMap[:], byte(i)))
	}
}
