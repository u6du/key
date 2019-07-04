package ed25519

import (
	"testing"
)

func TestEd25519(t *testing.T) {
	t.Logf("Ed25519 Public %x", Private.Public())
}
