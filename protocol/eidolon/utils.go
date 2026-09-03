package eidolon

import (
	"crypto/rand"
	"io"
)

// GenerateFlowID генерирует 16 криптографически стойких байт
func GenerateFlowID() []byte {
	id := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		// Если системный RNG сломан, лучше упасть, чем использовать нули
		panic("crypto/rand is unavailable: uncompromising security requires a secure RNG")
	}
	return id
}