package sphinx

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	k      = new(big.Int).SetBytes([]byte{165, 98, 192, 51, 205, 206, 226, 85, 22, 79, 248, 231, 248, 171, 160, 1, 248, 166, 173, 240, 47, 68, 92, 163, 33, 118, 150, 220, 69, 51, 98})
	one    = new(big.Int).SetInt64(1)
	pwd    = "p@ssw0rDD"   //master password
	domain = "example.com" //domain we want to log in to
)

func TestInvalidPointAtServer(t *testing.T) {

	x, y, _, err := MaskPassword(pwd, domain)
	assert.NoError(t, err)

	x = x.Add(x, one)
	x, y, err = DoServerPart(x, y, k)

	assert.Error(t, err)

}

func TestInvalidPointAtClient(t *testing.T) {

	x, y, r, err := MaskPassword(pwd, domain)
	assert.NoError(t, err)

	x, y, err = DoServerPart(x, y, k)
	assert.NoError(t, err)

	x = x.Add(x, one)

	seed := make([]byte, 0)
	err = UnmaskPassword(x, y, r, seed)

	assert.Error(t, err)
}

func BenchmarkSphinxVector(b *testing.B) {

	for i := 0; i < b.N; i++ {
		x, y, r, err := MaskPassword(pwd, domain)
		assert.NoError(b, err)

		x, y, err = DoServerPart(x, y, k)

		assert.NoError(b, err)

		seed := make([]byte, 32)
		err = UnmaskPassword(x, y, r, seed)

		assert.NoError(b, err)

		assert.Equal(b, hex.EncodeToString(seed), "bff10e229211385834b8d81863991b36a2cf0657183d6aeb966ec8bc2cf86bbd")
	}

}
