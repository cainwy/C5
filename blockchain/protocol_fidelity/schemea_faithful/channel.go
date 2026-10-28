package schemeafaithful


import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

type ChannelKey []byte

func NewChannelKey(keyLenBits int, r io.Reader) (ChannelKey, error) {
	if keyLenBits != 128 && keyLenBits != 192 && keyLenBits != 256 {
		return nil, errf(ErrChannel, "AES key length %d unsupported", keyLenBits)
	}
	k := make([]byte, keyLenBits/8)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return ChannelKey(k), nil
}

func (k ChannelKey) Seal(plaintext []byte) ([]byte, error) {
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (k ChannelKey) Open(sealed []byte) ([]byte, error) {
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errf(ErrChannel, "ciphertext too short")
	}
	nonce, ct := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errf(ErrChannel, "auth failed (wrong key or tampered)")
	}
	return pt, nil
}

func (k ChannelKey) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveKey(k))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func deriveKey(k ChannelKey) []byte {
	sum := sha256.Sum256(k)
	out := sum[:]
	switch l := len(k); {
	case l <= 16:
		return out[:16]
	case l <= 24:
		return out[:24]
	default:
		return out[:32]
	}
}
