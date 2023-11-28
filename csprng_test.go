package gokey

import (
	"bytes"
	"io"
	"testing"
)

func TestDRNG(t *testing.T) {
	var rngs [5]io.Reader

	rngs[0] = NewDRNG("pass1", "realm1")
	rngs[1] = NewDRNG("pass1", "realm2")
	rngs[2] = NewDRNG("pass2", "realm1")
	rngs[3] = NewDRNG("pass2", "realm2")
	rngs[4] = NewDRNG("pass1", "realm1")

	stream1 := make([]byte, 512)
	_, err := io.ReadFull(rngs[0], stream1)
	if err != nil {
		t.Fatal(err)
	}

	stream2 := make([]byte, 512)
	for i := 0; i < 4; i++ {
		_, err = io.ReadFull(rngs[i], stream2)
		if err != nil {
			t.Fatal(err)
		}

		if bytes.Equal(stream1, stream2) {
			t.Fatal("generated streams match")
		}
	}

	_, err = io.ReadFull(rngs[4], stream2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(stream1, stream2) {
		t.Fatal("generated streams do not match")
	}
}

func TestDRNGwithSeed(t *testing.T) {
	var rngs [5]io.Reader

	seed1, err := GenerateEncryptedKeySeed("pass1")
	if err != nil {
		t.Fatal(err)
	}

	seed2, err := GenerateEncryptedKeySeed("pass2")
	if err != nil {
		t.Fatal(err)
	}

	rngs[0], err = NewDRNGwithSeed("pass1", "realm1", seed1)
	if err != nil {
		t.Fatal(err)
	}
	rngs[1], err = NewDRNGwithSeed("pass1", "realm2", seed1)
	if err != nil {
		t.Fatal(err)
	}
	rngs[2], err = NewDRNGwithSeed("pass2", "realm1", seed2)
	if err != nil {
		t.Fatal(err)
	}
	rngs[3], err = NewDRNGwithSeed("pass2", "realm2", seed2)
	if err != nil {
		t.Fatal(err)
	}
	rngs[4], err = NewDRNGwithSeed("pass1", "realm1", seed1)
	if err != nil {
		t.Fatal(err)
	}

	// invalid password for a seed
	_, err = NewDRNGwithSeed("pass1", "realm2", seed2)
	if err == nil {
		t.Fatal("incorrect password for seed unwrap succeeded")
	}

	stream1 := make([]byte, 512)
	_, err = io.ReadFull(rngs[0], stream1)
	if err != nil {
		t.Fatal(err)
	}

	stream2 := make([]byte, 512)
	for i := 0; i < 4; i++ {
		_, err = io.ReadFull(rngs[i], stream2)
		if err != nil {
			t.Fatal(err)
		}

		if bytes.Equal(stream1, stream2) {
			t.Fatal("generated streams match")
		}
	}

	_, err = io.ReadFull(rngs[4], stream2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(stream1, stream2) {
		t.Fatal("generated streams do not match")
	}
}

func TestEncryptedSeed(t *testing.T) {
	seed, err := GenerateEncryptedKeySeed("pass1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = unwrapSeed("pass2", seed)
	if err == nil {
		t.Fatal("incorrect password for seed unwrap succeeded")
	}

	uSeed, err := unwrapSeed("pass1", seed)
	if err != nil {
		t.Fatal(err)
	}

	// do not waste precious random bytes
	if len(uSeed) != len(seed) {
		t.Fatal("unwrapped seed is shorter than encrypted seed")
	}

	if !bytes.Equal(uSeed[:12], seed[:12]) {
		t.Fatal("no nonce in unwrapped seed")
	}

	if !bytes.Equal(uSeed[len(uSeed)-16:], seed[len(seed)-16:]) {
		t.Fatal("no auth tag in unwrapped seed")
	}

	// rest should have been encrypted
	if bytes.Equal(uSeed[12:len(uSeed)-16], seed[12:len(seed)-16]) {
		t.Fatal("seed was not properly encrypted")
	}
}
