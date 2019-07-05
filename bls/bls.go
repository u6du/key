package bls

import (
	"github.com/u6du/key"
)

var Private *key.BlsPrivateKey

func InitBls() {

	binary := key.InitKey(
		"bls",
		func() key.Private {
			return key.NewBlsPrivate()
		})

	Private = key.LoadBlsPrivate(binary)
}

func init() {
	InitBls()
}
