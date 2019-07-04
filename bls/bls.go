package bls

import (
	"crypto/rand"

	"github.com/phoreproject/bls/g1pubs"
	"github.com/u6du/ex"

	"github.com/u6du/key"
)

type PrivateKey []byte
type PublicKey []byte

// https://github.com/prysmaticlabs/prysm/blob/master/shared/bls/bls.go
var Private PrivateKey

func (priv PrivateKey) Public() PublicKey {
	var r [32]byte
	copy(r[:], priv)
	secret := g1pubs.DeserializeSecretKey(r)
	t := g1pubs.PrivToPub(secret).Serialize()
	return t[:]
}

func InitBls() {

	binary := key.InitKey(
		"bls",
		func() ([]byte, []byte) {
			private, err := g1pubs.RandKey(rand.Reader)
			ex.Panic(err)

			public := g1pubs.PrivToPub(private).Serialize()

			t := private.Serialize()
			return t[:], public[:]
		})

	Private = binary
}

func init() {
	InitBls()
}
