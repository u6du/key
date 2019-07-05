package key

import "github.com/phoreproject/bls/g1pubs"

type BlsPrivateKey []byte
type BlsPublicKey []byte

// https://github.com/prysmaticlabs/prysm/blob/master/shared/bls/bls.go

func (p BlsPublicKey) Public() BlsPublicKey {
	var r [32]byte
	copy(r[:], p)
	secret := g1pubs.DeserializeSecretKey(r)
	t := g1pubs.PrivToPub(secret).Serialize()
	return t[:]
}
