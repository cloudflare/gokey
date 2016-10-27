// Command gokey is a vaultless password and key manager.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/cloudflare/gokey"
)

var (
	pass, keyType, seedPath, realm, output string
	unsafe                                 bool
	seedSkipCount                          int
)

func init() {
	flag.StringVar(&pass, "p", "", "master password")
	flag.StringVar(&keyType, "t", "pass", "output type (can be pass, seed, raw, ec256, ec521, rsa2048, rsa4096)")
	flag.StringVar(&seedPath, "s", "", "path to master seed file (optional)")
	flag.IntVar(&seedSkipCount, "skip", 0, "number of bytes to skip from master seed file (default 0)")
	flag.StringVar(&realm, "r", "", "password/key realm (most probably purpose of the password/key)")
	flag.StringVar(&output, "o", "", "output path to store generated key/password (default stdout)")
	flag.BoolVar(&unsafe, "u", false, "UNSAFE: allow key generation without a seed")
}

var keyTypes = map[string]int{
	"ec256":   gokey.KEYTYPE_EC256,
	"ec521":   gokey.KEYTYPE_EC521,
	"rsa2048": gokey.KEYTYPE_RSA2048,
	"rsa4096": gokey.KEYTYPE_RSA4096,
}

func genSeed(w io.Writer) {
	seed, err := gokey.GenerateEncryptedKeySeed(pass)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = w.Write(seed)
	if err != nil {
		log.Fatalln(err)
	}
}

func genPass(seed []byte, w io.Writer) {
	password, err := gokey.GetPass(pass, realm, seed, &gokey.PasswordSpec{10, 3, 3, 1, 1, ""})
	if err != nil {
		log.Fatalln(err)
	}

	_, err = io.WriteString(w, password)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Fprintln(w, "")
}

func genKey(seed []byte, w io.Writer) {
	key, err := gokey.GetKey(pass, realm, seed, keyTypes[keyType], unsafe)
	if err != nil {
		log.Fatalln(err)
	}

	err = gokey.EncodeToPem(key, w)
	if err != nil {
		log.Fatalln(err)
	}
}

// TODO: parametrize size
// generates raw 32 bytes
func genRaw(seed []byte, w io.Writer) {
	raw, err := gokey.GetRaw(pass, realm, seed, unsafe)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = io.CopyN(w, raw, 32)
	if err != nil {
		log.Fatalln(err)
	}
}

func logFatal(format string, args ...interface{}) {
	log.Printf(format, args...)
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	flag.Parse()

	if pass == "" {
		logFatal("no password provided")
	}

	out := os.Stdout
	var err error
	if output != "" {
		out, err = os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalln(err)
		}
		defer out.Close()
	}

	if keyType == "seed" {
		genSeed(out)
	} else {
		if realm == "" {
			logFatal("no realm provided")
		}

		var seed []byte
		if seedPath != "" {
			seed, err = ioutil.ReadFile(seedPath)
			if err != nil {
				log.Fatalln(err)
			}

			if (seedSkipCount < 0) || (seedSkipCount >= len(seed)) {
				log.Fatalln("invalid skip parameter")
			}
			seed = seed[seedSkipCount:]
		}

		switch keyType {
		case "pass":
			genPass(seed, out)
		case "raw":
			genRaw(seed, out)
		default:
			if _, ok := keyTypes[keyType]; !ok {
				logFatal("unknown key type: %v", keyType)
			}
			genKey(seed, out)
		}
	}
}
