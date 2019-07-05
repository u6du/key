package bls

import (
	"github.com/u6du/key"
)

var Private *key.BlsPrivate

func InitBls() {

	binary := key.InitKey("bls", key.NewBlsPrivatePublicByte)
	Private = key.LoadBlsPrivate(binary)
}

func init() {
	InitBls()
}
