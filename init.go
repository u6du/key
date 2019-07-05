package key

import (
	"io/ioutil"

	"github.com/u6du/config/user"
)

func InitKey(name string, f func() Private) []byte {
	name = "key/" + name + "."
	return user.File.Byte(
		name+"private",
		func() []byte {
			private := f()
			ioutil.WriteFile(user.File.Path(name+"public"), private.Public().Self().Byte, 0600)
			return private.Self().Byte
		})
}
