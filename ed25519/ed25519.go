package ed25519

import (
	"crypto/rand"

	"github.com/u6du/ex"
	"golang.org/x/crypto/ed25519"

	"github.com/u6du/key"
)

var Private ed25519.PrivateKey

func InitEd25519() {
	binary := key.InitKey(
		"ed25519",
		func() ([]byte, []byte) {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			ex.Panic(err)
			return private.Seed(), private.Public().(ed25519.PublicKey)
		})

	Private = ed25519.NewKeyFromSeed(binary)
}

func init() {
	InitEd25519()
}
