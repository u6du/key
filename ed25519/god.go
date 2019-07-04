package ed25519

import (
	"github.com/u6du/ex"
	"github.com/u6du/go-rfc1924/base85"
	"golang.org/x/crypto/ed25519"
)

var GodPublic ed25519.PublicKey

func init() {
	key := "VDbqF61cW7shb7aIzdBjvvZkkhO0ndSCYNJjE6m0"
	keyByte, err := base85.DecodeString(key)
	ex.Panic(err)
	GodPublic = ed25519.PublicKey(keyByte)
}
