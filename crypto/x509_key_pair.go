package crypto

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"math/big"
	"math/rand"

	faketls "github.com/ptrbug/invis/tls"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

func generateFixedMultiPrimeKey(random io.Reader, nprimes int, bits int) (*rsa.PrivateKey, error) {
	//randutil.MaybeReadByte(random)

	priv := new(rsa.PrivateKey)
	priv.E = 65537

	if nprimes < 2 {
		return nil, errors.New("crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2")
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
			return nil, errors.New("crypto/rsa: too few primes of given length to generate an RSA key")
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
			primes[i], err = cryptorand.Prime(random, todo/(nprimes-i))
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

type composeRand struct {
	randSlice []*rand.Rand
	index     int
}

func (r *composeRand) nextByte() byte {
	r.index = (r.index + 1) % len(r.randSlice)
	return byte(r.randSlice[r.index].Int() % 256)
}

func (r *composeRand) Read(p []byte) (n int, err error) {
	n = len(p)
	for i := 0; i < n; i++ {
		p[i] = r.nextByte()
	}
	return n, nil
}

func bytesToInt64(b []byte) int64 {
	var result int64
	for _, v := range b {
		result = result<<8 + int64(v)
	}
	return result
}

func CreateX509KeyPair(uuid []byte, bits int) (faketls.Certificate, error) {

	randSlice := make([]*rand.Rand, 2)
	for i := 0; i < len(randSlice); i++ {
		randSlice[i] = rand.New(rand.NewSource(bytesToInt64(uuid[i*8 : (i+1)*8])))
	}
	random := &composeRand{randSlice: randSlice}

	privateKey, err := generateFixedMultiPrimeKey(random, 2, bits)
	if err != nil {
		return faketls.Certificate{}, err
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	derCert, err := x509.CreateCertificate(random, &tpl, &tpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return faketls.Certificate{}, err
	}

	buf := &bytes.Buffer{}
	err = pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCert,
	})
	if err != nil {
		return faketls.Certificate{}, err
	}
	certPEM := buf.Bytes()

	buf = &bytes.Buffer{}
	err = pem.Encode(buf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return faketls.Certificate{}, err
	}
	keyPEM := buf.Bytes()

	return faketls.X509KeyPair(certPEM, keyPEM)
}
