package invite

import (
	"crypto/rand"
	"encoding/hex"
)

// NewUUIDv4 returns a RFC-4122 UUIDv4 string.
func NewUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Set version (4) and variant (10).
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	hex32 := hex.EncodeToString(b[:])
	// 8-4-4-4-12
	return hex32[0:8] + "-" + hex32[8:12] + "-" + hex32[12:16] + "-" + hex32[16:20] + "-" + hex32[20:32], nil
}
