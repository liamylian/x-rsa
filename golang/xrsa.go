package xrsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

const (
	RsaSignAlgorithm = crypto.SHA256
	// RsaPadding = PKCS#1
)

type XRsa struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func CreateKeys(keyLength int) (publicKey, privateKey string, err error) {
	priKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return
	}
	derStream, err := x509.MarshalPKCS8PrivateKey(priKey)
	if err != nil {
		return
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derStream,
	}

	privateKeyBuf := bytes.NewBufferString("")
	err = pem.Encode(privateKeyBuf, block)
	if err != nil {
		return
	}

	pubKey := &priKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	publicKeyBuf := bytes.NewBufferString("")
	err = pem.Encode(publicKeyBuf, block)
	if err != nil {
		return
	}

	return publicKeyBuf.String(), privateKeyBuf.String(), nil
}

func NewXRsa(publicKey string, privateKey string) (*XRsa, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)

	block, _ = pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pri, ok := priv.(*rsa.PrivateKey)
	if ok {
		return &XRsa{
			publicKey:  pub,
			privateKey: pri,
		}, nil
	} else {
		return nil, errors.New("private key not supported")
	}
}

func (r *XRsa) PublicEncrypt(data string) (string, error) {
	// The message must be no longer than the
	// length of the public modulus minus 11 bytes (taken by padding).
	partLen := r.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bts, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(bts)
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

func (r *XRsa) PrivateDecrypt(encrypted string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
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

func (r *XRsa) PrivateEncrypt(data string) (string, error) {
	// The message must be no longer than the
	// length of the public modulus minus 11 bytes (taken by padding).
	partLen := r.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bts, err := PrivateEncrypt(r.privateKey, chunk)
		if err != nil {
			return "", err
		}

		buffer.Write(bts)
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

func (r *XRsa) PublicDecrypt(encrypted string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := PublicDecrypt(r.publicKey, chunk)

		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

func (r *XRsa) Sign(data string) (string, error) {
	h := RsaSignAlgorithm.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	sign, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, RsaSignAlgorithm, hashed)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sign), err
}

func (r *XRsa) Verify(data string, sign string) error {
	h := RsaSignAlgorithm.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	decodedSign, err := base64.RawURLEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(r.publicKey, RsaSignAlgorithm, hashed, decodedSign)
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}
