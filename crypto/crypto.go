// Package crypto provides message security using the NaCl secretbox
// ciphers and scrypt-derived keys from passphrases.
package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/scrypt"

	"code.google.com/p/go.crypto/nacl/secretbox"
)

const (
	// keySize is the size of a NaCl secret key.
	keySize = 32

	// nonceSize is the size of a NaCl nonce.
	nonceSize = 24

	// saltSize is the size of the scrypt salt.
	saltSize = 32
)

var (
	// IterationsHigh is the recommended number of iterations for
	// file encryption according to the scrypt docs.
	IterationsHigh = 1048576

	// IterationsLow is twice the number of iterations for interactive
	// encryption as specified in the scrypt docs.
	IterationsLow  = 32768

	// Iterations contains the number of iterations to be used by
	// filecrypt; the default is the standard filecrypt number.
	Iterations     = IterationsHigh
)

func randBytes(size int) ([]byte, error) {
	r := make([]byte, size)
	_, err := rand.Read(r)
	return r, err
}

// generateNonce creates a new random nonce.
func generateNonce() (*[nonceSize]byte, error) {
	nonce := new([nonceSize]byte)
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

var (
	// ErrEncrypt is returned when encryption fails.
	ErrEncrypt = errors.New("crypto: encryption failed")

	// ErrDecrypt is returned when decryption fails.
	ErrDecrypt = errors.New("crypto: decryption failed")
)

// encrypt generates a random nonce and encrypts the input using
// NaCl's secretbox package. The nonce is prepended to the ciphertext.
// A sealed message will the same size as the original message plus
// secretbox.Overhead bytes long.
func encrypt(key *[keySize]byte, message []byte) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, ErrEncrypt
	}

	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, message, nonce, key)
	return out, nil
}

// decrypt extracts the nonce from the ciphertext, and attempts to
// decrypt with NaCl's secretbox.
func decrypt(key *[keySize]byte, message []byte) ([]byte, error) {
	if len(message) < (nonceSize + secretbox.Overhead) {
		return nil, ErrDecrypt
	}

	var nonce [nonceSize]byte
	copy(nonce[:], message[:nonceSize])
	out, ok := secretbox.Open(nil, message[nonceSize:], &nonce, key)
	if !ok {
		return nil, ErrDecrypt
	}

	return out, nil
}

// deriveKey generates a new NaCl key from a passphrase and salt.
func deriveKey(pass, salt []byte) *[keySize]byte {
	var naclKey = new([keySize]byte)

	// Key only fails with invalid scrypt params.
	key, _ := scrypt.Key(pass, salt, Iterations, 8, 1, keySize)

	copy(naclKey[:], key)
	Zero(key)
	return naclKey
}

// Seal secures a message using a passphrase.
func Seal(pass, message []byte) ([]byte, error) {
	salt, err := randBytes(saltSize)
	if err != nil {
		return nil, ErrEncrypt
	}

	key := deriveKey(pass, salt)
	out, err := encrypt(key, message)
	Zero(key[:]) // Zero key immediately after
	if err != nil {
		return nil, ErrEncrypt
	}

	out = append(salt, out...)
	return out, nil
}

const overhead = saltSize + secretbox.Overhead + nonceSize

// Open recovers a message encrypted using a passphrase.
func Open(pass, message []byte) ([]byte, error) {
	if len(message) < overhead {
		return nil, ErrDecrypt
	}

	key := deriveKey(pass, message[:saltSize])
	out, err := decrypt(key, message[saltSize:])
	Zero(key[:]) // Zero key immediately after
	if err != nil {
		return nil, ErrDecrypt
	}

	return out, nil
}

// Zero attempts to zeroise its input.
func Zero(in []byte) {
	for i := 0; i < len(in); i++ {
		in[i] = 0
	}
}
