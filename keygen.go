package gokey

import (
	"crypto"
	"crypto/elliptic"
	"errors"
	"io"
	"strings"
	"unicode"

	deterministicEcdsaKeygen "github.com/cloudflare/gokey/ecdsa"
	deterministicRsaKeygen "github.com/cloudflare/gokey/rsa"
	"golang.org/x/crypto/ed25519"
)

type KeyType int

const (
	EC256 KeyType = iota
	EC384
	EC521
	RSA2048
	RSA4096
	X25519
	ED25519
)

//go:generate stringer -type KeyType

type KeyGen struct {
	rng io.Reader
}

type PasswordSpec struct {
	Length         int
	Upper          int
	Lower          int
	Digits         int
	Special        int
	AllowedSpecial string
}

func (spec *PasswordSpec) Valid() bool {
	if spec.AllowedSpecial != "" {
		for _, c := range spec.AllowedSpecial {
			if !unicode.IsSymbol(c) && !unicode.IsPunct(c) {
				return false
			}
		}
	}

	return spec.Length >= spec.Upper+spec.Lower+spec.Digits+spec.Special
}

func allowed(num, fromSpec int) bool {
	if num > 0 && fromSpec == 0 {
		return false
	}

	if num < fromSpec {
		return false
	}

	return true
}

func (spec *PasswordSpec) Compliant(password string) bool {
	var upper, lower, digits, special int
	for _, c := range password {
		if unicode.IsUpper(c) {
			upper++
		}

		if unicode.IsLower(c) {
			lower++
		}

		if unicode.IsDigit(c) {
			digits++
		}

		if unicode.IsSymbol(c) || unicode.IsPunct(c) {
			if spec.AllowedSpecial == "" {
				special++
			} else {
				if strings.ContainsRune(spec.AllowedSpecial, c) {
					special++
				} else {
					return false
				}
			}
		}
	}

	if !allowed(upper, spec.Upper) || !allowed(lower, spec.Lower) || !allowed(digits, spec.Digits) || !allowed(special, spec.Special) {
		return false
	}

	return true
}

const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"

func randRange(rng io.Reader, max byte) (byte, error) {
	var base [1]byte

	for {
		_, err := io.ReadFull(rng, base[:])
		if err != nil {
			return 0, err
		}

		if 255 == base[0] {
			continue
		}

		rem := 255 % max
		buck := 255 / max

		if base[0] < 255-rem {
			return base[0] / buck, nil
		}
	}
}

func (keygen *KeyGen) genRandStr(length int) (string, error) {
	bytes := make([]byte, length)

	for i := 0; i < length; i++ {
		pos, err := randRange(keygen.rng, byte(len(chars)))
		if err != nil {
			return "", err
		}

		bytes[i] = chars[pos]
	}

	return string(bytes), nil
}

func (keygen *KeyGen) GeneratePassword(spec *PasswordSpec) (string, error) {
	if !spec.Valid() {
		return "", errors.New("invalid password specification")
	}

	for {
		password, err := keygen.genRandStr(spec.Length)
		if err != nil {
			return "", err
		}

		if spec.Compliant(password) {
			return password, nil
		}
	}
}

func (keygen *KeyGen) generateRsa(kt KeyType) (crypto.PrivateKey, error) {
	bits := 0

	switch kt {
	case RSA2048:
		bits = 2048
	case RSA4096:
		bits = 4096
	default:
		return nil, errors.New("invalid RSA key size requested")
	}

	return deterministicRsaKeygen.GenerateKey(keygen.rng, bits)
}

func (keygen *KeyGen) generateEc(kt KeyType) (crypto.PrivateKey, error) {
	var curve elliptic.Curve

	switch kt {
	case EC256:
		curve = elliptic.P256()
	case EC384:
		curve = elliptic.P384()
	case EC521:
		curve = elliptic.P521()
	default:
		return nil, errors.New("invalid EC key size requested")
	}

	return deterministicEcdsaKeygen.GenerateKey(curve, keygen.rng)
}

func (keygen *KeyGen) generate25519(kt KeyType) (crypto.PrivateKey, error) {
	switch kt {
	case X25519:
		var privKey [32]byte
		_, err := io.ReadFull(keygen.rng, privKey[:])

		// from https://cr.yp.to/ecdh.html
		privKey[0] &= 248
		privKey[31] &= 127
		privKey[31] |= 64

		return x25519PrivateKey(privKey[:]), err
	case ED25519:
		_, privKey, err := ed25519.GenerateKey(keygen.rng)
		return &privKey, err
	}

	return nil, errors.New("invalid key type requested")
}

func (keygen *KeyGen) GenerateKey(kt KeyType) (crypto.PrivateKey, error) {
	switch kt {
	case EC256, EC384, EC521:
		return keygen.generateEc(kt)
	case RSA2048, RSA4096:
		return keygen.generateRsa(kt)
	case X25519, ED25519:
		return keygen.generate25519(kt)
	}

	return nil, errors.New("invalid key type requested")
}
