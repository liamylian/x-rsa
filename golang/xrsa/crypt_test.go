package xrsa

import(
	"testing"
)

func TestEd(t *testing.T) {
	a := "Hello"
	key := "123456"

	b := ed([]byte(a), key)
	c := ed(b, key)
	if string(a) != string(c) {
		t.Fatal("failed")
	}
}

func TestEncryptDecryptt(t *testing.T) {
	a := "Hello"
	key := "123456"

	crypt := NewCrypt(key)
	encrypted := crypt.Encrypt([]byte(a))

	decrypted := crypt.Decrypt(encrypted)
	if string(decrypted) != a {
		t.Fatal("encrypt decrypt failed")
	}
}
