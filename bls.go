package key

import (
	"crypto/rand"

	"github.com/phoreproject/bls/g1pubs"
	"github.com/u6du/ex"
)

type BlsPrivate struct {
	Byte []byte
	key  *g1pubs.SecretKey
}

type BlsPublic struct {
	Byte []byte
	key  *g1pubs.PublicKey
}

// https://github.com/prysmaticlabs/prysm/blob/master/shared/bls/bls.go

func LoadBlsPrivate(binary []byte) *BlsPrivate {
	var t [32]byte
	copy(t[:], binary)
	return &BlsPrivate{binary, g1pubs.DeserializeSecretKey(t)}
}

func LoadBlsPublic(binary []byte) *BlsPublic {
	b48 := [48]byte{}
	copy(b48[:], binary)
	p, err := g1pubs.DeserializePublicKey(b48)
	ex.Panic(err)
	return &BlsPublic{binary, p}
}

func NewBlsPrivate() *BlsPrivate {
	private, err := g1pubs.RandKey(rand.Reader)
	ex.Panic(err)
	t := private.Serialize()
	var binary []byte
	copy(binary, t[:])
	return &BlsPrivate{binary, private}
}

func NewBlsPrivatePublicByte() ([]byte, []byte) {
	private := NewBlsPrivate()
	return private.Byte, private.Public().Byte
}

func (b *BlsPrivate) Public() *BlsPublic {
	p := g1pubs.PrivToPub(b.key)
	var binary []byte
	t := b.key.Serialize()
	copy(binary, t[:])
	return &BlsPublic{binary, p}
}

func (b *BlsPrivate) Sign(binary []byte) []byte {

}

func (b *BlsPublic) Verify(binary []byte, sign []byte) bool {

}
