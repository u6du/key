package key

import (
	"crypto/rand"

	"github.com/phoreproject/bls/g1pubs"
	"github.com/u6du/ex"
)

// https://github.com/prysmaticlabs/prysm/blob/master/shared/bls/bls.go
var BlsPrivate g1pubs.SecretKey

func InitBls() {

	binary := initKey(
		"bls",
		func() ([]byte, []byte) {
			private, err := g1pubs.RandKey(rand.Reader)
			ex.Panic(err)

			public := g1pubs.PrivToPub(private).Serialize()

			t := private.Serialize()
			return t[:], public[:]
		})

	var key [32]byte
	copy(key[:], binary)
	BlsPrivate = *g1pubs.DeserializeSecretKey(key)
}

/*

import (
	"crypto/rand"
	"fmt"

	"github.com/phoreproject/bls"
	g1 "github.com/phoreproject/bls/g1pubs"
	"github.com/u6du/ex"
)

// https://github.com/phoreproject/bls/issues/9

func main() {
	private, err := g1.RandKey(rand.Reader)
	ex.Panic(err)

	alicePrivateKey := bls.FRReprFromBytes(private.Serialize())
	alicePublicKey := bls.G1AffineOne.MulFR(alicePrivateKey)

	bobPrivate, err := g1.RandKey(rand.Reader)
	ex.Panic(err)
	bobPrivateKey := bls.FRReprFromBytes(bobPrivate.Serialize())

	bobPublicKey := bls.G1AffineOne.MulFR(bobPrivateKey)

	s1 := bobPublicKey.MulFR(alicePrivateKey).ToAffine()

	s2 := alicePublicKey.MulFR(bobPrivateKey).ToAffine()

	if !s1.Equals(s2) {
		panic("shared secret should be the same")
	}

	secret := s1.SerializeBytes()
	fmt.Printf("secret len: %d\n", len(secret))
	fmt.Printf("shared secret: %x\n", secret)

}

*/
