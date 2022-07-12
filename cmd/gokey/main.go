// Command gokey is a vaultless password and key manager.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/cloudflare/gokey"
	"golang.org/x/term"
)

var (
	pass, passFile, keyType, seedPath, realm, output string
	unsafe                                           bool
	seedSkipCount, length                            int
)

func init() {
	flag.StringVar(&pass, "p", "", "master password (if not specified, will be asked interactively)")
	flag.StringVar(&passFile, "P", "", "master password file (if not specified, will be asked interactively)")
	flag.StringVar(&keyType, "t", "pass", "output type (can be pass, seed, raw, ec256, ec384, ec521, rsa2048, rsa4096, x25519, ed25519)")
	flag.StringVar(&seedPath, "s", "", "path to master seed file (optional)")
	flag.IntVar(&seedSkipCount, "skip", 0, "number of bytes to skip from master seed file (default 0)")
	flag.StringVar(&realm, "r", "", "password/key realm (most probably purpose of the password/key)")
	flag.StringVar(&output, "o", "", "output path to store generated key/password (default stdout)")
	flag.BoolVar(&unsafe, "u", false, "UNSAFE: allow key generation without a seed")
	flag.IntVar(&length, "l", 10, `number of characters in the generated password or number of bytes in the generated raw stream (default 10 for "pass" type and 32 for "raw" type)`)
}

var keyTypes = map[string]gokey.KeyType{
	"ec256":   gokey.EC256,
	"ec384":   gokey.EC384,
	"ec521":   gokey.EC521,
	"rsa2048": gokey.RSA2048,
	"rsa4096": gokey.RSA4096,
	"x25519":  gokey.X25519,
	"ed25519": gokey.ED25519,
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
	password, err := gokey.GetPass(pass, realm, seed, &gokey.PasswordSpec{length, 3, 3, 1, 1, ""})
	if err != nil {
		log.Fatalln(err)
	}

	_, err = io.WriteString(w, password)
	if err != nil {
		log.Fatalln(err)
	}
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

func genRaw(seed []byte, w io.Writer) {
	raw, err := gokey.GetRaw(pass, realm, seed, unsafe)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = io.CopyN(w, raw, int64(length))
	if err != nil {
		log.Fatalln(err)
	}
}

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func logFatal(format string, args ...interface{}) {
	log.Printf(format, args...)
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	flag.Parse()

	var err error
	if pass == "" && passFile != "" {
		var content []byte
		content, err = ioutil.ReadFile(passFile)
		if err != nil {
			log.Fatalln(err)
		}
		pass = strings.TrimSpace(string(content[:]))
	}
	if pass == "" {
		var passBytes []byte
		var passBytesAgain []byte
		for {
			for len(passBytes) == 0 {
				fmt.Fprint(os.Stderr, "Master password: ")
				passBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					log.Fatalln(err)
				}
				fmt.Fprintln(os.Stderr, "")
			}

			if seedPath != "" {
				break
			}

			fmt.Fprint(os.Stderr, "Master password again: ")
			passBytesAgain, err = term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				log.Fatalln(err)
			}
			fmt.Fprintln(os.Stderr, "")
			if bytes.Equal(passBytes, passBytesAgain) {
				break
			} else {
				fmt.Fprintln(os.Stderr, "Passwords do not match. Try again.")
				passBytes = nil
				continue
			}
		}

		pass = string(passBytes)
	}

	out := os.Stdout
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
			if length <= 0 {
				logFatal("invalid length parameter")
			}
			genPass(seed, out)
			fmt.Fprintln(os.Stderr, "")
		case "raw":
			if !isFlagSet("l") {
				length = 32
			}
			if length <= 0 {
				logFatal("invalid length parameter")
			}
			genRaw(seed, out)
		default:
			if _, ok := keyTypes[keyType]; !ok {
				logFatal("unknown key type: %v", keyType)
			}
			if isFlagSet("l") {
				logFatal("key type %v does not support length parameter", keyType)
			}
			genKey(seed, out)
		}
	}
}
