package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/sirupsen/logrus"
)

func main() {
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey1 := &privateKey1.PublicKey
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(publicKey1)})
	logrus.Printf("Public Key:\n%s\n", string(publicKeyPEM))
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey1)})
	fmt.Printf("Private Key Insert To Database:\n%s\n", string(privateKeyPEM))

	apikey := EncodePublicKeyToBase64(publicKey1)
	logrus.Printf("Public Key Base64 X-Public-Key:\n%s\n", apikey)
}

func ParsePrivateKey(privateKeyStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privKey, nil
}

func EncodePublicKeyToBase64(publicKey *rsa.PublicKey) string {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(publicKeyBytes)
}

func DecodeBase64ToPublicKey(base64String string) (*rsa.PublicKey, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("decoded public key is not an RSA public key")
	}

	return rsaPubKey, nil
}
