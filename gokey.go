package gokey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ed25519"
)

func getReader(password, realm string, seed []byte, allowUnsafe bool) (io.Reader, error) {
	var rng io.Reader
	var err error

	if seed != nil {
		rng, err = NewDRNGwithSeed(password, realm, seed)
		if err != nil {
			return nil, err
		}
	} else if allowUnsafe {
		rng = NewDRNG(password, realm)
	} else {
		return nil, errors.New("generating keys without strong seed is not allowed")
	}

	return rng, nil
}

func GetPass(password, realm string, seed []byte, spec *PasswordSpec) (string, error) {
	rng, err := getReader(password, realm+"-pass", seed, true)
	if err != nil {
		return "", err
	}

	gen := &KeyGen{rng}
	return gen.GeneratePassword(spec)
}

func GetKey(password, realm string, seed []byte, kt KeyType, allowUnsafe bool) (crypto.PrivateKey, error) {
	rng, err := getReader(password, realm+fmt.Sprintf("-key(%v)", kt), seed, allowUnsafe)
	if err != nil {
		return nil, err
	}

	gen := &KeyGen{rng}
	return gen.GenerateKey(kt)
}

func GetRaw(password, realm string, seed []byte, allowUnsafe bool) (io.Reader, error) {
	rng, err := getReader(password, realm+"-raw", seed, allowUnsafe)
	if err != nil {
		return nil, err
	}

	return rng, nil
}

// below code implements asn1 encoding of x25519 and ed25519 keys according
// to https://tools.ietf.org/id/draft-ietf-curdle-pkix-10.txt
// the output should be compatible to OpenSSL pkey functions
// this code is considered temporal and is expected to go away, when Go
// implements native marshalling for these types of keys
// as https://tools.ietf.org/id/draft-ietf-curdle-pkix-10.txt is still a draft
// future versions of gokey may produce different output

// p.3 https://tools.ietf.org/id/draft-ietf-curdle-pkix-10.txt
// id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
// id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
const (
	x25519OidSuffix  = 110
	ed25519OidSuffix = 112
)

// x25519/ed25519 asn1 private key structure
// p.7 https://tools.ietf.org/id/draft-ietf-curdle-pkix-10.txt
// this implementation does not support optional attributes or public key
type asn25519 struct {
	Version    int
	AlgId      pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// Golang does not have a declaration for x25519 keys
type x25519PrivateKey []byte

func marshal25519PrivateKey(key crypto.PrivateKey) ([]byte, error) {
	var a25519 asn25519
	var keyBytes []byte

	switch key.(type) {
	case x25519PrivateKey:
		a25519.AlgId = pkix.AlgorithmIdentifier{asn1.ObjectIdentifier{1, 3, 101, x25519OidSuffix}, asn1.RawValue{}}
		keyBytes = key.(x25519PrivateKey)
	case *ed25519.PrivateKey:
		a25519.AlgId = pkix.AlgorithmIdentifier{asn1.ObjectIdentifier{1, 3, 101, ed25519OidSuffix}, asn1.RawValue{}}
		keyBytes = key.(*ed25519.PrivateKey).Seed()
	}

	// actual key bytes are double wrapped in octet strings
	// see p.7 https://tools.ietf.org/id/draft-ietf-curdle-pkix-10.txt
	privKeyOctetString, err := asn1.Marshal(keyBytes)
	if err != nil {
		return nil, err
	}

	a25519.PrivateKey = privKeyOctetString

	return asn1.Marshal(a25519)
}

func EncodeToPem(key crypto.PrivateKey, w io.Writer) error {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
		if err != nil {
			return err
		}

		return pem.Encode(w, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
		return pem.Encode(w, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	case x25519PrivateKey, *ed25519.PrivateKey:
		der, err := marshal25519PrivateKey(key)
		if err != nil {
			return err
		}

		return pem.Encode(w, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}

	return fmt.Errorf("unable to encode key type %T", key)
}
