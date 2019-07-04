package bls

import (
	"crypto/rand"

	"github.com/phoreproject/bls/g1pubs"
	"github.com/u6du/ex"

	"github.com/u6du/key"
)

// https://github.com/prysmaticlabs/prysm/blob/master/shared/bls/bls.go
var Private g1pubs.SecretKey

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

	var r [32]byte
	copy(r[:], binary)
	Private = *g1pubs.DeserializeSecretKey(r)
}

func init() {
	InitBls()
}
