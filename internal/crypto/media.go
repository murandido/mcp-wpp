package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Sealed media layout: magic (5 bytes) | nonce (12 bytes) | AES-256-GCM
// ciphertext+tag. The additional data is the magic plus the file's path
// relative to the store, so a sealed file moved or swapped onto another
// message's path fails to open.
var mediaMagic = []byte("WPPM\x01")

const nonceSize = 12

// ErrNotSealed means the file is not in the sealed media format.
var ErrNotSealed = errors.New("media file is not sealed")

// MediaCipher seals and opens cached media files.
type MediaCipher struct {
	aead cipher.AEAD
}

// NewMediaCipher builds a cipher from a 32-byte media sub-key.
func NewMediaCipher(key []byte) (*MediaCipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("media key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &MediaCipher{aead: aead}, nil
}

func aad(relPath string) []byte {
	return append(append([]byte(nil), mediaMagic...), relPath...)
}

// Seal encrypts plaintext for the file at relPath.
func (m *MediaCipher) Seal(plaintext []byte, relPath string) ([]byte, error) {
	out := make([]byte, len(mediaMagic)+nonceSize, len(mediaMagic)+nonceSize+len(plaintext)+m.aead.Overhead())
	copy(out, mediaMagic)
	if _, err := rand.Read(out[len(mediaMagic):]); err != nil {
		return nil, err
	}
	nonce := out[len(mediaMagic):]
	return m.aead.Seal(out, nonce, plaintext, aad(relPath)), nil
}

// Open decrypts a sealed file read from relPath.
func (m *MediaCipher) Open(sealed []byte, relPath string) ([]byte, error) {
	if !IsSealed(sealed) {
		return nil, ErrNotSealed
	}
	hdr := len(mediaMagic) + nonceSize
	if len(sealed) < hdr+m.aead.Overhead() {
		return nil, errors.New("sealed media file is truncated")
	}
	plain, err := m.aead.Open(nil, sealed[len(mediaMagic):hdr], sealed[hdr:], aad(relPath))
	if err != nil {
		return nil, errors.New("sealed media file failed authentication (wrong key, corrupted, or moved)")
	}
	return plain, nil
}

// IsSealed reports whether data starts with the sealed media magic.
func IsSealed(data []byte) bool {
	return bytes.HasPrefix(data, mediaMagic)
}
