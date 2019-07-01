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
}

*/
