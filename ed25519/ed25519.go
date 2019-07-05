package ed25519

import (
	"golang.org/x/crypto/ed25519"

	"github.com/u6du/key"
)

var Private ed25519.PrivateKey

func InitEd25519() {
	binary := key.InitKey("ed25519", key.NewEd25519PrivatePublicByte)

	Private = ed25519.NewKeyFromSeed(binary)
}

func init() {
	InitEd25519()
}
