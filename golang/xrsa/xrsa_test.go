package xrsa

import(
	"testing"
	"bytes"
	"fmt"
	"io/ioutil"
	"encoding/json"
)

var publicKey *bytes.Buffer = bytes.NewBufferString("")
var privateKey *bytes.Buffer = bytes.NewBufferString("")
var xrsa *XRsa

func TestCreateKeys(t *testing.T) {
	err := CreateKeys(publicKey, privateKey, 2048)
	if err != nil {
		t.Error(err.Error())
	}
}

func TestNewXRsa(t *testing.T) {
	var err error
	xrsa, err = NewXRsa(publicKey.Bytes(), privateKey.Bytes())
	if err != nil {
		t.Error(err.Error())
	}
}

func TestEncryptDecrypt(t *testing.T) {
	data := "Estimates of the number of languages中国 in the world vary between 5,000 and 7,000. However, any precise estimate depends on a partly arbitrary distinction between languages and dialects. Natural languages are spoken or signed, but any language can be encoded into secondary media using auditory, visual, or tactile stimuli – for example, in whistling, signed, or braille. This is because human language is modality-independent. Depending on philosophical perspectives regarding the definition of language and meaning, when used as a general concept, language may refer to the cognitive ability to learn and use systems of complex communication, or to describe the set of rules that makes up these systems, or the set of utterances that can be produced from those rules. All languages rely on the process of semiosis to relate signs to particular meanings. Oral, manual and tactile languages contain a phonological system that governs how symbols are used to form sequences known as words or morphemes, and a syntactic system that governs how words and morphemes are combined to form phrases and utterances."
	encrypted, err := xrsa.PublicEncrypt(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	decrypted, err := xrsa.PrivateDecrypt(encrypted)
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(decrypted) != data {
		t.Fatal(fmt.Sprintf("Faild assert \"%s\" equals \"%s\"", decrypted, data))
	}
}

func TestSignVerify(t *testing.T) {
	data := "Hello, World"
	sign, err := xrsa.Sign(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = xrsa.Verify(data, sign)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestCrossLanguage(t *testing.T) {
	var data = make(map[string] string)
	pubKey, err := ioutil.ReadFile("../../test/pub.pem")
	if err != nil {
		t.Fatal(err.Error())
	}
	priKey, err := ioutil.ReadFile("../../test/pri.pem")
	if err != nil {
		t.Fatal(err.Error())
	}
	testData, err := ioutil.ReadFile("../../test/data.json")
	if err != nil {
		t.Fatal(err.Error())
	}
	err = json.Unmarshal(testData, &data)
	if err != nil {
		t.Fatal(err.Error())
	}

	rsa2, err := NewXRsa(pubKey, priKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	decrypted, err := rsa2.PrivateDecrypt(data["encrypted"])
	if err != nil {
		t.Fatal(err.Error())
	}
	if string(decrypted) != data["data"] {
		t.Fatal(fmt.Sprintf("Faild assert \"%s\" equals \"%s\"", decrypted, data))
	}

	err = rsa2.Verify(data["data"], data["sign"])
	if err != nil {
		t.Fatal(err.Error())
	}
}