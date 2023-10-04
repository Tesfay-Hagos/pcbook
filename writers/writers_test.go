package writers_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"pcbook/security"
	"pcbook/writers"
	"reflect"
	"testing"
)

type Person struct {
	Name      string
	Age       int
	Address   Address
	Languages []string
}

type Address struct {
	Street  string
	City    string
	ZipCode string
}

func TestCreateTopic(t *testing.T) {
	writers.CreatekafkaTopic()
}
func TestEncryption(t *testing.T) {
	// Generate a random symmetric key.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	object := Person{
		Name: "John Doe",
		Age:  30,
		Address: Address{
			Street:  "123 Main Street",
			City:    "New York",
			ZipCode: "10001",
		},
		Languages: []string{"English", "Spanish", "French"},
	}
	plaintext, err := json.Marshal(object)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Encrypt the encrypted data with the recipient's public key.
	sec := security.NewsecurEncryption(key)
	encrypted, err := sec.Encrypt([]byte(plaintext))
	if err != nil {
		fmt.Printf("err: %v", err)
	}
	sec1 := security.NewsecurEncryption(key)
	// Decrypt the data.
	decrypted, err := sec1.Decrypt(encrypted)
	if err != nil {
		fmt.Printf("err: %v", err)
	}
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("Encrypted:", encrypted)
	fmt.Println("Decrypted:", decrypted)
}

func TestAscSecurity(t *testing.T) {
	object := Person{
		Name: "John Doe",
		Age:  30,
		Address: Address{
			Street:  "123 Main Street",
			City:    "New York",
			ZipCode: "10001",
		},
		Languages: []string{"English", "Spanish", "French"},
	}
	plaintext, _ := json.Marshal(object)
	asc := security.Newasymetricsecurity()
	priv, pub := asc.GenerateKeyPair(2040)
	privst := asc.ExportPrivKeyAsPEMStr(priv)
	pubstr := asc.ExportPubKeyAsPEMStr(pub)

	priv1 := asc.ExportPEMStrToPrivKey([]byte(privst))
	pub1 := asc.ExportPEMStrToPubKey([]byte(pubstr))

	ciphertext := asc.EncryptAsc(pub1, plaintext)
	decrypttext := asc.DecryptAsc(priv1, ciphertext)
	person := Person{}
	json.Unmarshal(decrypttext, &person)
	if Ok := reflect.DeepEqual(object, person); Ok != true {
		t.Error(errors.New("Hash function not Equeal"))
	}

	ciphertext1 := asc.DecryptAsc(priv1, plaintext)
	fmt.Printf("\nDecryptedinreverse:%v", ciphertext)
	decrypttext1 := asc.EncryptAsc(pub1, ciphertext1)
	fmt.Printf("\nEncryptedinreverse:%v", decrypttext)
	person1 := Person{}
	json.Unmarshal(decrypttext1, &person)
	reflect.DeepEqual(object, person1)
}

func TestHash(t *testing.T) {
	asc := security.Newasymetricsecurity()
	priv, pub := asc.GenerateKeyPair(2040)
	h := security.NewHash()
	object := Persons{Name: "Alice", Age: 30}
	object1 := Persons{Name: "Alice", Age: 30}
	hash, err := h.HashStruct(object)
	if err != nil {
		t.Error(err)
	}
	hashobj, _ := hex.DecodeString(hash)
	ciphertext := asc.EncryptAsc(pub, hashobj)
	ok, err := asc.ValidateRequest(priv, ciphertext, object1)
	if err != nil {
		t.Error(err)
	}
	if ok != true {
		t.Error(errors.New("Hash function not Equeal"))
	}
	fmt.Println("Hash:", hash)
}

type Persons struct {
	Name string
	Age  int
}
