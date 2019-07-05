package key

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// https://github.com/phoreproject/bls/issues/9

func testBls(t *testing.T, size uint) {

	msg := make([]byte, size)
	rand.Read(msg)

	private := NewBlsPrivate()
	private = LoadBlsPrivate(private.Byte())

	sign := private.SignDomain(1, msg)
	public := private.Public()
	publicByte := public.Byte()
	public = LoadBlsPublic(publicByte)
	t.Logf("public len %d", len(publicByte))

	t.Logf("private len %d", len(private.Byte()))

	t.Logf("sign len %d", len(sign))

	if !public.VerifyDomain(1, msg, sign) {
		t.Error("SignDomain 签名校验错误")
	}

	sign = private.Sign(msg)
	if !public.Verify(msg, sign) {
		t.Error("Sign 签名校验错误")
	}
}

func TestBls(t *testing.T) {
	testBls(t, 2)
	testBls(t, 32)
	testBls(t, 33)
	testBls(t, 104)

	privateA := NewBlsPrivate()
	privateB := NewBlsPrivate()

	keyA, err := privateA.Ecdh(privateB.Public().Byte())
	if err != nil {
		t.Error(err)
	}

	keyB, err := privateB.Ecdh(privateA.Public().Byte())
	if err != nil {
		t.Error(err)
	}
	t.Logf("ecdh %x", keyA)
	t.Logf("ecdh %x", keyB)
	if 0 != bytes.Compare(keyA, keyB) {
		t.Error("echo not same")
	}
}
