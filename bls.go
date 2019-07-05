package key

import (
	"crypto/rand"

	"github.com/phoreproject/bls/g1pubs"
	"github.com/u6du/ex"
)

type BlsPrivateKey struct {
	BytePrivate
	key *g1pubs.SecretKey
}

type BlsPublicKey struct {
	BytePublic
	key *g1pubs.PublicKey
}

// https://github.com/prysmaticlabs/prysm/blob/master/shared/bls/bls.go
/*
func (p BlsPrivateKey) Public() BlsPublicKey {
	var r [32]byte
	copy(r[:], p)
	secret := g1pubs.DeserializeSecretKey(r)
	t := g1pubs.PrivToPub(secret).Serialize()
	return t[:]
}
*/
func LoadBlsPrivate(b []byte) *BlsPrivateKey {
	var t [32]byte
	copy(t[:], b)
	return &BlsPrivateKey{BytePrivate{b}, g1pubs.DeserializeSecretKey(t)}
}

func NewBlsPrivate() *BlsPrivateKey {
	private, err := g1pubs.RandKey(rand.Reader)
	ex.Panic(err)
	t := private.Serialize()
	var b []byte
	copy(b, t[:])
	return &BlsPrivateKey{BytePrivate{b}, private}
}

func (b *BlsPrivateKey) Public() Public {
	p := g1pubs.PrivToPub(b.key)
	var binary []byte
	t := b.key.Serialize()
	copy(binary, t[:])
	return &BlsPublicKey{BytePublic{binary}, p}
}
