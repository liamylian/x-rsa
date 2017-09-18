package xrsa

import (
	"crypto/md5"
	"encoding/hex"
)

type Crypt struct {
	key string
}

func NewCrypt(key string) *Crypt {
	return &Crypt{ key:key }
}

func (c *Crypt) Encrypt(data []byte) []byte {
	sum := getMd5([]byte(c.key))
	dataLen := len(data)
	sumLen := len(sum)

	j := 0
	encrypted := make([]byte, dataLen * 2)
	for i := 0; i < dataLen; i++ {
		if j == sumLen - 1 {
			j = 0
		}
		encrypted[i*2] = sum[j]
		encrypted[i*2+1] = data[i] ^ sum[j]
		j++
	}

	return ed(encrypted, c.key)
}

func (c *Crypt) Decrypt(data []byte) []byte {
	ed := ed(data, c.key)
	dataLen := len(data)

	decrypted := make([]byte, dataLen / 2)
	for i := 0; i < dataLen / 2; i++ {
		decrypted[i] = ed[i*2] ^ ed[i*2+1]
	}

	return decrypted
}

func ed(data []byte, key string) []byte {
	sum := getMd5([]byte(key))
	dataLen := len(data)
	sumLen := len(sum)

	j := 0
	encrypted := make([]byte, dataLen)
	for i := 0; i < dataLen; i++ {
		if j == sumLen - 1 {
			j = 0
		}

		encrypted[i] = data[i] ^ sum[j]
		j++
	}

	return encrypted
}

func getMd5(data []byte) string {
	md5Ctx := md5.New()
	md5Ctx.Write(data)
	sum := md5Ctx.Sum(nil)
	return hex.EncodeToString(sum)
}