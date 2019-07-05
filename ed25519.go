package key

import (
	"crypto/rand"

	"github.com/u6du/ex"
	"golang.org/x/crypto/ed25519"
)

type Ed25519Private []byte

type Ed25519Public []byte

func NewEd25519Private() Ed25519Private {
	private, _ := NewEd25519PrivatePublicByte()
	return private
}

func LoadEd25519Private(binary []byte) Ed25519Private {
	return Ed25519Private(binary)
}

func LoadEd25519Public(binary []byte) Ed25519Public {
	return Ed25519Public(binary)
}

func (b Ed25519Private) Public() Ed25519Public {
	public := ed25519.PrivateKey(b).Public()
	return LoadEd25519Public(public.(ed25519.PublicKey))
}

func (b Ed25519Private) Sign(binary []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(b), binary)
}

func (b Ed25519Public) Verify(binary []byte, sign []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(b), binary, sign)
}

func NewEd25519PrivatePublicByte() ([]byte, []byte) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	ex.Panic(err)
	return private, public
}
