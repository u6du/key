package key

import (
	"io/ioutil"

	"github.com/u6du/config/user"
)

func InitKey(name string, f func() ([]byte, []byte)) []byte {
	name = "key/" + name + "."
	return user.File.Byte(
		name+"private",
		func() []byte {
			private, public := f()
			ioutil.WriteFile(user.File.Path(name+"public"), public, 0600)
			return private
		})
}
