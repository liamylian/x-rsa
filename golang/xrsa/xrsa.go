package xrsa

import (
	"encoding/pem"
	"encoding/base64"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"errors"
	"crypto"
	"io"
	"bytes"
)

const (
	CHAR_SET = "UTF-8"
	ALGORITHM_RSA = "RSA"
	ALGORITHM_RSA_SIGN = crypto.SHA256
)

type XRsa struct {
	publicKey *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func createKeys(publicKeyWriter, privateKeyWriter io.Writer, keyLength int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derStream,
	}
	err = pem.Encode(privateKeyWriter, block)
	if err != nil {
		return err
	}

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	err = pem.Encode(publicKeyWriter, block)
	if err != nil {
		return err
	}

	return nil
}

func NewXRsa(publicKey []byte, privateKey []byte) (*XRsa, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)

	block, _ = pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &XRsa {
		publicKey: pub,
		privateKey: priv,
	}, nil
}

func (r *XRsa) publicEncrypt(data string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bytes, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(bytes)
	}

	return base64.URLEncoding.EncodeToString(buffer.Bytes()), nil
}

func (r *XRsa) privateDecrypt(encrypted string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8
	raw, err := base64.URLEncoding.DecodeString(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

func (r *XRsa) privateSign(data string) (string, error) {
	h := ALGORITHM_RSA_SIGN.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	sign, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, ALGORITHM_RSA_SIGN, hashed)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(sign), err
}

func (r *XRsa) verifySign(data string, sign string) error {
	h := ALGORITHM_RSA_SIGN.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	decodedSign, err := base64.URLEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(r.publicKey, ALGORITHM_RSA_SIGN, hashed, decodedSign)
}