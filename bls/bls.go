package bls

import (
	"crypto/rand"

	"github.com/phoreproject/bls/g1pubs"
	"github.com/u6du/ex"

	"github.com/u6du/key"
)

var Private key.BlsPrivateKey

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
