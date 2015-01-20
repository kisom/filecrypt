package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

var (
	testMessage   = []byte("Do not go gentle into that good night.")
	testPassword1 = []byte("correct horse battery staple")
	testPassword2 = []byte("incorrect horse battery staple")
	testKey       *[32]byte
)

/*
 * The following tests verify the positive functionality of this package:
 * can an encrypted message be decrypted?
 */

// generateKey creates a new random secret key.
func generateKey() (*[keySize]byte, error) {
	key := new([keySize]byte)
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}

	return key, nil
}

func TestGenerateKey(t *testing.T) {
	var err error
	testKey, err = generateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestEncrypt(t *testing.T) {
	ct, err := encrypt(testKey, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	pt, err := decrypt(testKey, ct)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(testMessage, pt) {
		t.Fatalf("messages don't match")
	}
}

/*
 * The following tests verify the negative functionality of this package:
 * does it fail when it should?
 */

func prngTester(size int, testFunc func()) {
	prng := rand.Reader
	buf := &bytes.Buffer{}

	rand.Reader = buf
	defer func() { rand.Reader = prng }()

	for i := 0; i < size; i++ {
		tmp := make([]byte, i)
		buf.Write(tmp)
		testFunc()
	}
}

func TestPRNGFailures(t *testing.T) {
	testFunc := func() {
		_, err := generateKey()
		if err == nil {
			t.Fatal("expected key generation failure with bad PRNG")
		}
	}
	prngTester(32, testFunc)

	testFunc = func() {
		_, err := generateNonce()
		if err == nil {
			t.Fatal("expected nonce generation failure with bad PRNG")
		}
	}
	prngTester(24, testFunc)

	testFunc = func() {
		_, err := encrypt(testKey, testMessage)
		if err == nil {
			t.Fatal("expected encryption failure with bad PRNG")
		}
	}
	prngTester(24, testFunc)
}

func TestDecryptFailures(t *testing.T) {
	targetLength := 24 + secretbox.Overhead

	for i := 0; i < targetLength; i++ {
		buf := make([]byte, i)
		if _, err := decrypt(testKey, buf); err == nil {
			t.Fatal("expected decryption failure with bad message length")
		}
	}

	otherKey, err := generateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}

	ct, err := encrypt(testKey, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, err = decrypt(otherKey, ct); err == nil {
		t.Fatal("decrypt should fail with wrong key")
	}
}

func TestEncryptCycle(t *testing.T) {
	out, err := Seal(testPassword1, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err = Open(testPassword1, out)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(testMessage, out) {
		t.Fatal("recovered plaintext doesn't match original")
	}
}
