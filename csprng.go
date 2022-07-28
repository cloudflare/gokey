package gokey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	keySeedLength = 256
)

type devZero struct{}

func (dz devZero) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func passKey(password, realm string) []byte {
	return pbkdf2.Key([]byte(password), []byte(realm), 4096, 32, sha256.New)
}

func NewDRNG(password, realm string) io.Reader {
	block, _ := aes.NewCipher(passKey(password, realm))
	stream := cipher.NewCTR(block, make([]byte, 16))

	return cipher.StreamReader{S: stream, R: devZero{}}
}

func NewDRNGwithSeed(password, realm string, seed []byte) (io.Reader, error) {
	uSeed, err := unwrapSeed(password, seed)
	if err != nil {
		return nil, err
	}

	// will reuse some of the public seed info
	salt := make([]byte, 12+16)
	copy(salt[:12], uSeed[:12])
	copy(salt[12:], uSeed[len(uSeed)-16:])

	hkdf := hkdf.New(sha256.New, uSeed, salt, []byte(realm))
	rngSeed := make([]byte, 32)
	_, err = io.ReadFull(hkdf, rngSeed)
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(rngSeed)
	stream := cipher.NewCTR(block, make([]byte, 16))

	return cipher.StreamReader{S: stream, R: devZero{}}, nil
}

func GenerateEncryptedKeySeed(password string) ([]byte, error) {
	seed := make([]byte, keySeedLength)

	_, err := rand.Read(seed)
	if err != nil {
		return nil, err
	}

	masterkey := passKey(password, string(seed[:12]))

	aes, err := aes.NewCipher(masterkey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	pt := seed[12 : len(seed)-16]

	// encrypt in place
	gcm.Seal(pt[:0], seed[:12], pt, nil)

	return seed, nil
}

func unwrapSeed(password string, seed []byte) ([]byte, error) {
	masterkey := passKey(password, string(seed[:12]))

	aes, err := aes.NewCipher(masterkey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	pt := make([]byte, len(seed))
	_, err = gcm.Open(pt[12:], seed[:12], seed[12:], nil)
	if err != nil {
		return nil, err
	}

	copy(pt[:12], seed[:12])
	copy(pt[len(pt)-16:], seed[len(seed)-16:])
	return pt, nil
}
