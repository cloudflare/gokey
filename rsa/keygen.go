package rsa

import (
	"crypto/rsa"
	"errors"
	"io"
	"math"
	"math/big"
)

// below is taken from https://github.com/golang/go/blob/8a2553e380196dda556608e2fe79881004770eb9/src/crypto/rand/util.go#L31
// because later versions of rand.Prime() have a different algorithm and are not deterministic

// smallPrimes is a list of small, prime numbers that allows us to rapidly
// exclude some fraction of composite candidates when searching for a random
// prime. This list is truncated at the point where smallPrimesProduct exceeds
// a uint64. It does not include two because we ensure that the candidates are
// odd by construction.
var smallPrimes = []uint8{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

// smallPrimesProduct is the product of the values in smallPrimes and allows us
// to reduce a candidate prime by this number and then determine whether it's
// coprime to all the elements of smallPrimes without further big.Int
// operations.
var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)

// prime returns a number, p, of the given size, such that p is prime
// with high probability.
// prime will return error for any error returned by rand.Read or if bits < 2.
func prime(rand io.Reader, bits int) (p *big.Int, err error) {
	if bits < 2 {
		err = errors.New("crypto/rand: prime size must be at least 2-bit")
		return
	}

	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (bits+7)/8)
	p = new(big.Int)

	bigMod := new(big.Int)

	for {
		_, err = io.ReadFull(rand, bytes)
		if err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= bits.
		bytes[0] &= uint8(int(1<<b) - 1)
		// Don't let the value be too small, i.e, set the most significant two bits.
		// Setting the top two bits, rather than just the top bit,
		// means that when two of these values are multiplied together,
		// the result isn't ever one bit short.
		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			// Here b==1, because b cannot be zero.
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0x80
			}
		}
		// Make the value odd since an even number this large certainly isn't prime.
		bytes[len(bytes)-1] |= 1

		p.SetBytes(bytes)

		// Calculate the value mod the product of smallPrimes. If it's
		// a multiple of any of these primes we add two until it isn't.
		// The probability of overflowing is minimal and can be ignored
		// because we still perform Miller-Rabin tests on the result.
		bigMod.Mod(p, smallPrimesProduct)
		mod := bigMod.Uint64()

	NextDelta:
		for delta := uint64(0); delta < 1<<20; delta += 2 {
			m := mod + delta
			for _, prime := range smallPrimes {
				if m%uint64(prime) == 0 && (bits > 6 || m != uint64(prime)) {
					continue NextDelta
				}
			}

			if delta > 0 {
				bigMod.SetUint64(delta)
				p.Add(p, bigMod)
			}
			break
		}

		// There is a tiny possibility that, by adding delta, we caused
		// the number to be one bit too long. Thus we check BitLen
		// here.
		if p.ProbablyPrime(20) && p.BitLen() == bits {
			return
		}
	}
}

// below is taken from https://github.com/golang/go/blob/161874da2ab6d5372043a1f3938a81a19d1165ad/src/crypto/rsa/rsa.go#L220
// because later versions in standard crypto/rsa package are not deterministic
var bigOne = big.NewInt(1)

func GenerateKey(random io.Reader, bits int) (*rsa.PrivateKey, error) {
	return generateMultiPrimeKey(random, 2, bits)
}

func generateMultiPrimeKey(random io.Reader, nprimes int, bits int) (*rsa.PrivateKey, error) {
	priv := new(rsa.PrivateKey)
	priv.E = 65537

	if nprimes < 2 {
		return nil, errors.New("gokey/rsa: GenerateMultiPrimeKey: nprimes must be >= 2")
	}

	if bits < 64 {
		primeLimit := float64(uint64(1) << uint(bits/nprimes))
		// pi approximates the number of primes less than primeLimit
		pi := primeLimit / (math.Log(primeLimit) - 1)
		// Generated primes start with 11 (in binary) so we can only
		// use a quarter of them.
		pi /= 4
		// Use a factor of two to ensure that key generation terminates
		// in a reasonable amount of time.
		pi /= 2
		if pi <= float64(nprimes) {
			return nil, errors.New("gokey/rsa: too few primes of given length to generate an RSA key")
		}
	}

	primes := make([]*big.Int, nprimes)

NextSetOfPrimes:
	for {
		todo := bits
		// crypto/rand should set the top two bits in each prime.
		// Thus each prime has the form
		//   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
		// And the product is:
		//   P = 2^todo × α
		// where α is the product of nprimes numbers of the form 0.11...
		//
		// If α < 1/2 (which can happen for nprimes > 2), we need to
		// shift todo to compensate for lost bits: the mean value of 0.11...
		// is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
		// will give good results.
		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}
		for i := 0; i < nprimes; i++ {
			var err error
			primes[i], err = prime(random, todo/(nprimes-i))
			if err != nil {
				return nil, err
			}
			todo -= primes[i].BitLen()
		}

		// Make sure that primes is pairwise unequal.
		for i, prime := range primes {
			for j := 0; j < i; j++ {
				if prime.Cmp(primes[j]) == 0 {
					continue NextSetOfPrimes
				}
			}
		}

		n := new(big.Int).Set(bigOne)
		totient := new(big.Int).Set(bigOne)
		pminus1 := new(big.Int)
		for _, prime := range primes {
			n.Mul(n, prime)
			pminus1.Sub(prime, bigOne)
			totient.Mul(totient, pminus1)
		}
		if n.BitLen() != bits {
			// This should never happen for nprimes == 2 because
			// crypto/rand should set the top two bits in each prime.
			// For nprimes > 2 we hope it does not happen often.
			continue NextSetOfPrimes
		}

		priv.D = new(big.Int)
		e := big.NewInt(int64(priv.E))
		ok := priv.D.ModInverse(e, totient)

		if ok != nil {
			priv.Primes = primes
			priv.N = n
			break
		}
	}

	priv.Precompute()
	return priv, nil
}
