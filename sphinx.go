package sphinx

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

var (
	c = elliptic.P256()
)

func MaskPassword(password, domain string) (x, y, mask *big.Int, err error) {
	hash := sha512.Sum512_256([]byte(password + "|" + domain))

	pkx, pky := hashIntoCurvePoint(hash[:]) // turn password hash into elliptic curve point.

	mask, err = randScalar(c) // client's password mask value, random per every call
	if err != nil {
		return
	}

	x, y = c.ScalarMult(pkx, pky, mask.Bytes()) //client masks his password hash with a random value
	return
}

func UnmaskPassword(x, y, r *big.Int, buf []byte) error {

	if !c.IsOnCurve(x, y) {
		return errors.New("invalid point")
	}

	rInv := fermatInverse(r, c.Params().N)  // rInv = r ^-1
	x, y = c.ScalarMult(x, y, rInv.Bytes()) // client un-masks returned value by multiplying it to r ^-1

	kdf := hkdf.New(sha512.New512_256, append(x.Bytes(), y.Bytes()...), nil, []byte("Virgil"))
	_, err := kdf.Read(buf)
	return err
}

func DoServerPart(x, y, k *big.Int) (x1, y1 *big.Int, err error) {

	if !c.IsOnCurve(x, y) {
		err = errors.New("invalid point")
		return
	}

	x1, y1 = c.ScalarMult(x, y, k.Bytes())
	return
}

func randScalar(c elliptic.Curve) (k *big.Int, err error) {
	params := c.Params()
	k, err = rand.Int(rand.Reader, params.N)
	return
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

func hashIntoCurvePoint(r []byte) (x, y *big.Int) {
	t := make([]byte, 32)
	copy(t, r)

	x, y = tryPoint(t)
	for y == nil || !c.IsOnCurve(x, y) {
		increment(t)
		x, y = tryPoint(t)

	}
	return
}

func tryPoint(r []byte) (x, y *big.Int) {
	hash := sha512.Sum512_256(r)
	x = new(big.Int).SetBytes(hash[:])

	// y² = x³ - 3x + b
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, c.Params().B)

	y = x3.ModSqrt(x3, c.Params().P)
	return
}

func increment(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}
