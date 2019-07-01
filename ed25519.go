package key

import (
	"crypto/rand"

	"github.com/u6du/ex"
	"golang.org/x/crypto/ed25519"
)

var Ed25519Private ed25519.PrivateKey

func InitEd25519() {
	binary := initKey(
		"ed25519",
		func() ([]byte, []byte) {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			ex.Panic(err)
			return private.Seed(), private.Public().(ed25519.PublicKey)
		})

	Ed25519Private = ed25519.NewKeyFromSeed(binary)
}
