package key

import (
	"io/ioutil"

	"github.com/u6du/config"
)

func initKey(name string, f func() ([]byte, []byte)) []byte {
	name = "key/" + name + "."
	return config.UserByte(
		name+"private",
		func() []byte {
			private, public := f()
			ioutil.WriteFile(config.UserPath(name+"public"), public, 0600)
			return private
		})
}
