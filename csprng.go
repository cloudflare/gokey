package gokey

// we are using Fortuna Generator as our "reproducible" CSPRNG
// this implementation is simplified as we need only a repeatable PRNG and we seed it only once
// also, every instance of this PRNG will be used to generate only one password/key

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	keySeedLength = 256
)

type fortunaGenerator struct {
	key     []byte
	counter [16]byte
	cipher  cipher.Block
	buffer  *bytes.Buffer
}

func (g *fortunaGenerator) increment() {
	// from cipher/ctr/ctr.go (changed byte order)
	for i := 0; i < len(g.counter); i++ {
		g.counter[i]++
		if g.counter[i] != 0 {
			break
		}
	}
}

func (g *fortunaGenerator) isCountZero() bool {
	for i := len(g.counter) - 1; i >= 0; i-- {
		if g.counter[i] != 0 {
			return false
		}
	}

	return true
}

func (g *fortunaGenerator) Reseed(seed []byte) {
	hash := sha256.New()
	hash.Write(g.key)
	hash.Write(seed)
	g.key = hash.Sum(nil)

	aes, err := aes.NewCipher(g.key)
	if err != nil {
		panic(err)
	}

	g.cipher = aes
	if g.buffer == nil {
		g.buffer = bytes.NewBuffer(nil)
	}
	g.increment()
}

func (g *fortunaGenerator) generateBlocks(blockCount int) ([]byte, error) {
	if g.isCountZero() {
		return nil, errors.New("PRNG has not been seeded")
	}

	r := make([]byte, blockCount*16)

	for i := 0; i < blockCount; i++ {
		g.cipher.Encrypt(r[i*16:], g.counter[:])
		g.increment()
	}

	return r, nil
}

func (g *fortunaGenerator) Read(p []byte) (n int, err error) {
	// to be reproducible we will generate data in blocks and buffer them
	// so, for example, Read(24) == Read(5) + Read(9)

	for len(p) > g.buffer.Len() {
		blocks, err := g.generateBlocks(256 / 16)
		if err != nil {
			return 0, err
		}

		g.key, err = g.generateBlocks(2)
		if err != nil {
			return 0, err
		}

		g.cipher, err = aes.NewCipher(g.key)
		if err != nil {
			return 0, err
		}

		g.buffer.Write(blocks)
	}

	return g.buffer.Read(p)
}

func passKey(password, realm string) []byte {
	return pbkdf2.Key([]byte(password), []byte(realm), 4096, 32, sha256.New)
}

func NewDRNG(password, realm string) io.Reader {
	rng := &fortunaGenerator{}
	rng.Reseed(passKey(password, realm))

	return rng
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

	rng := &fortunaGenerator{}
	rng.Reseed(rngSeed)

	return rng, nil
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
