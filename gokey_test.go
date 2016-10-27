package gokey

import (
	"bytes"
	"crypto"
	"strings"
	"testing"
)

var (
	passSpec = &PasswordSpec{16, 3, 3, 2, 1, ""}
)

func TestGetPass(t *testing.T) {
	pass1Seed1, err := GenerateEncryptedKeySeed("pass1")
	if err != nil {
		t.Fatal(err)
	}

	pass1Seed2, err := GenerateEncryptedKeySeed("pass1")
	if err != nil {
		t.Fatal(err)
	}

	pass1Example1, err := GetPass("pass1", "example.com", nil, passSpec)
	if err != nil {
		t.Fatal(err)
	}

	pass1Example2, err := GetPass("pass1", "example2.com", nil, passSpec)
	if err != nil {
		t.Fatal(err)
	}

	pass2Example1, err := GetPass("pass2", "example.com", nil, passSpec)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Compare(pass1Example1, pass1Example2) == 0 {
		t.Fatal("passwords match for different realms")
	}

	if strings.Compare(pass1Example1, pass2Example1) == 0 {
		t.Fatal("passwords match for different master passwords")
	}

	pass1Example1Seed1, err := GetPass("pass1", "example.com", pass1Seed1, passSpec)
	if err != nil {
		t.Fatal(err)
	}

	pass1Example1Seed2, err := GetPass("pass1", "example.com", pass1Seed2, passSpec)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Compare(pass1Example1, pass1Example1Seed1) == 0 {
		t.Fatal("passwords match for seeded and non-seeded master password")
	}

	if strings.Compare(pass1Example1Seed1, pass1Example1Seed2) == 0 {
		t.Fatal("passwords match for different seeds")
	}

	pass1Example1Retry, err := GetPass("pass1", "example.com", nil, passSpec)
	if err != nil {
		t.Fatal(err)
	}

	pass1Example1Seed1Retry, err := GetPass("pass1", "example.com", pass1Seed1, passSpec)
	if err != nil {
		t.Fatal(err)
	}

	if (strings.Compare(pass1Example1, pass1Example1Retry) != 0) || (strings.Compare(pass1Example1Seed1, pass1Example1Seed1Retry) != 0) {
		t.Fatal("passwords with same invocation options do not match")
	}
}

func keyToBytes(key crypto.PrivateKey, t *testing.T) []byte {
	buf := bytes.NewBuffer(nil)

	err := EncodeToPem(key, buf)
	if err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func testGetKeyType(keyType int, t *testing.T) {
	pass1Seed1, err := GenerateEncryptedKeySeed("pass1")
	if err != nil {
		t.Fatal(err)
	}

	pass1Seed2, err := GenerateEncryptedKeySeed("pass1")
	if err != nil {
		t.Fatal(err)
	}

	key1Example1, err := GetKey("pass1", "example.com", nil, keyType, true)
	if err != nil {
		t.Fatal(err)
	}

	key1Example2, err := GetKey("pass1", "example2.com", nil, keyType, true)
	if err != nil {
		t.Fatal(err)
	}

	key2Example1, err := GetKey("pass2", "example.com", nil, keyType, true)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(keyToBytes(key1Example1, t), keyToBytes(key1Example2, t)) == 0 {
		t.Fatal("keys match for different realms")
	}

	if bytes.Compare(keyToBytes(key1Example1, t), keyToBytes(key2Example1, t)) == 0 {
		t.Fatal("keys match for different master passwords")
	}

	key1Example1Seed1, err := GetKey("pass1", "example.com", pass1Seed1, keyType, false)
	if err != nil {
		t.Fatal(err)
	}

	key1Example1Seed2, err := GetKey("pass1", "example.com", pass1Seed2, keyType, false)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(keyToBytes(key1Example1, t), keyToBytes(key1Example1Seed1, t)) == 0 {
		t.Fatal("keys match for seeded and non-seeded master password")
	}

	if bytes.Compare(keyToBytes(key1Example1Seed1, t), keyToBytes(key1Example1Seed2, t)) == 0 {
		t.Fatal("keys match for different seeds")
	}

	key1Example1Retry, err := GetKey("pass1", "example.com", nil, keyType, true)
	if err != nil {
		t.Fatal(err)
	}

	key1Example1Seed1Retry, err := GetKey("pass1", "example.com", pass1Seed1, keyType, false)
	if err != nil {
		t.Fatal(err)
	}

	if (bytes.Compare(keyToBytes(key1Example1, t), keyToBytes(key1Example1Retry, t)) != 0) || (bytes.Compare(keyToBytes(key1Example1Seed1, t), keyToBytes(key1Example1Seed1Retry, t)) != 0) {
		t.Fatal("keys with same invocation options do not match")
	}
}

func TestGetKey(t *testing.T) {
	testGetKeyType(KEYTYPE_EC256, t)
	testGetKeyType(KEYTYPE_EC521, t)
	testGetKeyType(KEYTYPE_RSA2048, t)
	testGetKeyType(KEYTYPE_RSA4096, t)
}

func TestGetKeyUnsafe(t *testing.T) {
	_, err := GetKey("pass1", "example.com", nil, KEYTYPE_EC256, false)
	if err == nil {
		t.Fatal("allowed unsafe key generation")
	}
}
