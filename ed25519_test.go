package key

import "testing"

func TestEd25519(t *testing.T) {
	t.Logf("Ed25519 Public %x", Ed25519Private.Public())
}
