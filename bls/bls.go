package bls

import (
	"github.com/u6du/key"
)

var Private key.Private

func InitBls() {

	binary := key.InitKey("bls", key.NewBlsPrivate)

	Private = key.LoadBlsPrivate(binary)
}

func init() {
	InitBls()
}
