package gokey

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"io"
	"testing"
)

var (
	sha256_of_abc = []byte{0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}
)

func TestCSPRNGSeed(t *testing.T) {
	fg := &fortunaGenerator{}

	fg.Reseed([]byte{'a', 'b', 'c'})
	counter := binary.LittleEndian.Uint64(fg.counter[:])

	if bytes.Compare(fg.key, sha256_of_abc) != 0 || counter != 1 {
		t.Fatal("seed operation failed")
	}

}

func TestGenBlocks(t *testing.T) {
	fg := &fortunaGenerator{}
	fg.Reseed([]byte{'a', 'b', 'c'})

	blocks, err := fg.generateBlocks(8)
	if err != nil {
		t.Fatal(err)
	}

	if len(blocks) != 8*16 {
		t.Fatal("invalid length of generated data")
	}

	for i := 0; i < 8; i++ {
		aes, err := aes.NewCipher(sha256_of_abc)
		if err != nil {
			t.Fatal(err)
		}

		counter := make([]byte, 16)
		binary.LittleEndian.PutUint64(counter, uint64(i+1))
		aes.Encrypt(counter, counter)

		if bytes.Compare(blocks[i*16:(i+1)*16], counter) != 0 {
			t.Fatal("generated bad data")
		}
	}
}

func TestReproduce(t *testing.T) {
	fg := &fortunaGenerator{}
	fg.Reseed([]byte{'a', 'b', 'c'})

	stream1 := make([]byte, 512)
	_, err := io.ReadFull(fg, stream1)
	if err != nil {
		t.Fatal(err)
	}

	fg = &fortunaGenerator{}
	fg.Reseed([]byte{'a', 'b', 'c'})

	stream2 := make([]byte, 512)
	_, err = io.ReadFull(fg, stream2[:258])
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadFull(fg, stream2[258:])
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(stream1, stream2) != 0 {
		t.Fatal("generated streams do not match")
	}
}

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

		if bytes.Compare(stream1, stream2) == 0 {
			t.Fatal("generated streams match")
		}
	}

	_, err = io.ReadFull(rngs[4], stream2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(stream1, stream2) != 0 {
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

		if bytes.Compare(stream1, stream2) == 0 {
			t.Fatal("generated streams match")
		}
	}

	_, err = io.ReadFull(rngs[4], stream2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(stream1, stream2) != 0 {
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

	if bytes.Compare(uSeed[:12], seed[:12]) != 0 {
		t.Fatal("no nonce in unwrapped seed")
	}

	if bytes.Compare(uSeed[len(uSeed)-16:], seed[len(seed)-16:]) != 0 {
		t.Fatal("no auth tag in unwrapped seed")
	}

	// rest should have been encrypted
	if bytes.Compare(uSeed[12:len(uSeed)-16], seed[12:len(seed)-16]) == 0 {
		t.Fatal("seed was not properly encrypted")
	}
}
