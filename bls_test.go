package key

import (
	"crypto/rand"
	"testing"

	"github.com/phoreproject/bls"
	g1 "github.com/phoreproject/bls/g1pubs"
	"github.com/u6du/ex"
)

// https://github.com/phoreproject/bls/issues/9

func TestBls(t *testing.T) {
	private, err := g1.RandKey(rand.Reader)
	ex.Panic(err)

	alicePrivateKey := private.GetFRElement().ToRepr()
	alicePublicKey := bls.G1AffineOne.MulFR(alicePrivateKey)

	bobPrivate, err := g1.RandKey(rand.Reader)
	ex.Panic(err)
	bobPrivateKey := bobPrivate.GetFRElement().ToRepr()

	bobPublicKey := bls.G1AffineOne.MulFR(bobPrivateKey)

	s1 := bobPublicKey.MulFR(alicePrivateKey).ToAffine()

	s2 := alicePublicKey.MulFR(bobPrivateKey).ToAffine()

	if !s1.Equals(s2) {
		t.Error("shared secret should be the same")
	}

	secret := s1.SerializeBytes()
	t.Logf("secret len: %d\n", len(secret))
	t.Logf("shared secret: %x\n", secret)
}
