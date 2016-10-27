package gokey

import (
	"crypto/rand"
	"testing"
	"unicode"
)

func TestGenPass(t *testing.T) {
	spec := &PasswordSpec{16, 2, 2, 1, 1, ""}
	keygen := &KeyGen{rand.Reader}

	_, err := keygen.GeneratePassword(spec)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAllowedChars(t *testing.T) {
	for _, c := range chars {
		if !unicode.IsLower(c) && !unicode.IsUpper(c) && !unicode.IsSymbol(c) && !unicode.IsPunct(c) && !unicode.IsDigit(c) {
			t.Fatalf("not used character %c in allowed character string", c)
		}
	}
}
