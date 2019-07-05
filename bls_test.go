package key

import (
	"crypto/rand"
	"testing"
)

// https://github.com/phoreproject/bls/issues/9

func TestBls(t *testing.T) {

	msg := make([]byte, 1024)
	rand.Read(msg)

	private := NewBlsPrivate()
	private = LoadBlsPrivate(private.Byte())

	sign := private.DomainSign(1, msg)
	public := private.Public()

	t.Logf("private len %d", len(private.Byte()))

	t.Logf("sign len %d", len(sign))

	if !public.DomainVerify(1, msg, sign) {
		t.Error("DomainSign 签名校验错误")
	}

	sign = private.Sign(msg)
	if !public.Verify(msg, sign) {
		t.Error("Sign 签名校验错误")
	}

}
