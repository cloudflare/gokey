package gokey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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

func GetKey(password, realm string, seed []byte, keyType int, allowUnsafe bool) (crypto.PrivateKey, error) {
	rng, err := getReader(password, realm+fmt.Sprintf("-key(%v)", keyType), seed, allowUnsafe)
	if err != nil {
		return nil, err
	}

	gen := &KeyGen{rng}
	return gen.GenerateKey(keyType)
}

func GetRaw(password, realm string, seed []byte, allowUnsafe bool) (io.Reader, error) {
	rng, err := getReader(password, realm+"-raw", seed, allowUnsafe)
	if err != nil {
		return nil, err
	}

	return rng, nil
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
	}

	return fmt.Errorf("unable to encode key type %T", key)
}
