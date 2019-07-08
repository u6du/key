package key

import (
	"crypto/rand"

	"github.com/phoreproject/bls"
	"github.com/phoreproject/bls/g1pubs"
	"github.com/pkg/errors"
	"github.com/u6du/ex"
	"golang.org/x/crypto/blake2b"
)

type BlsPrivate struct {
	byte []byte
	key  *g1pubs.SecretKey
}

type BlsPublic struct {
	byte []byte
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
	binary := make([]byte, 32)
	copy(binary, t[:])
	return &BlsPrivate{binary, private}
}

func NewBlsPrivatePublicByte() ([]byte, []byte) {
	private := NewBlsPrivate()
	return private.Byte(), private.Public().Byte()
}

func (b *BlsPrivate) Byte() []byte {
	return b.byte
}

func (b *BlsPublic) Byte() []byte {
	return b.byte
}

func (b *BlsPrivate) Public() *BlsPublic {
	p := g1pubs.PrivToPub(b.key)
	binary := make([]byte, 48)
	t := p.Serialize()
	copy(binary, t[:])
	return &BlsPublic{binary, p}
}

func hash32(binary []byte) [32]byte {
	if len(binary) > 32 {
		return blake2b.Sum256(binary)
	}

	var b32 [32]byte
	copy(b32[:], binary)

	return b32
}

func (b *BlsPrivate) Sign(binary []byte) []byte {
	s := g1pubs.Sign(binary, b.key)
	r := s.Serialize()
	return r[:]
}

func (b *BlsPublic) Verify(binary []byte, sign []byte) bool {
	var b96 [96]byte
	copy(b96[:], sign)
	s, err := g1pubs.DeserializeSignature(b96)
	if err != nil {
		return false
	}
	return g1pubs.Verify(binary, b.key, s)
}

func (b *BlsPrivate) SignDomain(domain uint64, binary []byte) []byte {
	return b.SignHash(domain, hash32(binary))
}

func (b *BlsPublic) VerifyDomain(domain uint64, binary []byte, sign []byte) bool {
	return b.VerifyHash(domain, hash32(binary), sign)
}

func (b *BlsPrivate) SignHash(domain uint64, binary [32]byte) []byte {
	s := g1pubs.SignWithDomain(binary, b.key, domain)
	r := s.Serialize()
	return r[:]
}

func (b *BlsPublic) VerifyHash(domain uint64, binary [32]byte, sign []byte) bool {
	var b96 [96]byte
	copy(b96[:], sign)
	s, err := g1pubs.DeserializeSignature(b96)
	if err != nil {
		return false
	}
	return g1pubs.VerifyWithDomain(binary, b.key, s, domain)
}

var ErrEcdh = errors.New("ecdh")

func (b *BlsPrivate) Ecdh(other []byte) ([]byte, error) {
	b48 := [48]byte{}
	copy(b48[:], other)
	p, err := bls.DecompressG1(b48)
	if err != nil {
		return []byte{}, ErrEcdh
	}
	b96 := p.ToProjective().MulFR(b.key.GetFRElement().ToRepr()).ToAffine().SerializeBytes()
	r := make([]byte, 96)
	copy(r, b96[:])
	return r, nil
}

func (b *BlsPrivate) EcdhBlake2b(other []byte) (byte [32]byte, err error) {
	key, err := b.Ecdh(other)
	if err!=nil{
		return
	}
	byte = blake2b.Sum256(key)
	return
}