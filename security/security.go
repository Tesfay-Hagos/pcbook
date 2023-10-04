package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
)

type security struct {
	Hash          hashs
	encryptionkey []byte
}

// the payload when you decrypt it could be base64 encoded. if you encrypt with the Encrypt function in this object or aes lib the default response is base64 encoded
func NewsecurEncryption(encryptionkey []byte) *security {
	return &security{
		Hash:          *NewHash(),
		encryptionkey: encryptionkey,
	}
}
func (s *security) Encrypt(payload []byte) (string, error) {
	block, err := aes.NewCipher([]byte(s.encryptionkey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(payload), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *security) Decrypt(payload string) (string, error) {
	block, err := aes.NewCipher([]byte(s.encryptionkey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext is too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (s *security) RandomKeyGenerator(size int) string {
	key := make([]byte, size)
	rand.Read(key)
	return string(key)
}

type asymetricsecurity struct {
	Hash             hashs
	hashing_function hash.Hash
	randomgenerator  io.Reader
	label            []byte
}

// , rand.Reader
func Newasymetricsecurity() *asymetricsecurity {
	return &asymetricsecurity{
		Hash:             *NewHash(),
		hashing_function: sha256.New(),
		randomgenerator:  rand.Reader,
		label:            nil,
	}
}
func (asc *asymetricsecurity) GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	// This method requires a random number of bits.
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	// The public key is part of the PrivateKey struct
	return privateKey, &privateKey.PublicKey
}
func (asc *asymetricsecurity) ExportPubKeyAsPEMStr(pubkey *rsa.PublicKey) string {
	pubKeyPem := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pubkey),
		},
	))
	return pubKeyPem
}

// Export private key as a string in PEM format
func (asc *asymetricsecurity) ExportPrivKeyAsPEMStr(privkey *rsa.PrivateKey) string {
	privKeyPem := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privkey),
		},
	))
	return privKeyPem

}
func (asc *asymetricsecurity) ExportPEMStrToPrivKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key
}

// Decode public key struct from PEM string
func (asc *asymetricsecurity) ExportPEMStrToPubKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	key, _ := x509.ParsePKCS1PublicKey(block.Bytes)
	return key
}

func (asc *asymetricsecurity) EncryptAsc(publicKey *rsa.PublicKey, message []byte) []byte {
	cipherText, _ := rsa.EncryptOAEP(
		asc.hashing_function,
		asc.randomgenerator,
		publicKey,
		message,
		asc.label,
	)
	return cipherText
}

func (asc *asymetricsecurity) DecryptAsc(privateKey *rsa.PrivateKey, cipherText []byte) []byte {
	decMessage, _ := rsa.DecryptOAEP(
		asc.hashing_function,
		asc.randomgenerator,
		privateKey,
		cipherText,
		asc.label,
	)
	return decMessage
}

func (asc *asymetricsecurity) ValidateRequest(privateKey *rsa.PrivateKey, cipherText []byte, object interface{}) (bool, error) {
	clienthash := hex.EncodeToString(asc.DecryptAsc(privateKey, cipherText))
	serverhash, err := asc.Hash.HashStruct(object)
	if err != nil {
		return false, err
	}
	if clienthash != serverhash {
		return false, errors.New("hashs Not Equal")
	}
	return true, nil
}
