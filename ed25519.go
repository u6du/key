package key

import (
	"crypto/rand"
	"io/ioutil"

	"github.com/u6du/ex"
	"golang.org/x/crypto/ed25519"

	"github.com/u6du/config"
)

var Ed25519Private ed25519.PrivateKey

func InitEd25519() {
	name := "ed25519."
	binary := config.UserByte(
		name+"private",
		func() []byte {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			ex.Panic(err)

			err = ioutil.WriteFile(config.UserPath(name+"public"), private.Public().(ed25519.PublicKey), 0600)
			ex.Panic(err)

			return private.Seed()
		})

	Ed25519Private = ed25519.NewKeyFromSeed(binary)
}

func init() {
	InitEd25519()
}
