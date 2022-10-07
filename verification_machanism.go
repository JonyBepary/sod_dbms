package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/libp2p/go-libp2p/core/crypto"
)

func isFileAvailable(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}


// Generate signature for each given digest
func generate_signature_of_a_file(target, privkeyfile, sig_destination string) []byte {

	// provision key pair
	cprivateKey, err := ioutil.ReadFile(privkeyfile)
	if err != nil {
		panic(err)
	}
	privateKey, err := crypto.UnmarshalECDSAPrivateKey(cprivateKey)
	data, err := ioutil.ReadFile(target)
	if err != nil {
		panic(err)
	}
	signature, err := privateKey.Sign([]byte(data))
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: %v\n", signature)
	ioutil.WriteFile(sig_destination, signature, 0644)
	return signature

}

// Generate signature for each given digest
func generate_signature_of_a_string_to_file(digest, privkeyfile, sig_destination string) []byte {

	// provision key pair
	cprivateKey, err := ioutil.ReadFile(privkeyfile)
	if err != nil {
		panic(err)
	}
	privateKey, err := crypto.UnmarshalECDSAPrivateKey(cprivateKey)
	if err != nil {
		panic(err)
	}
	signature, err := privateKey.Sign([]byte(digest))
	if err != nil {
		panic(err)
	}
	ioutil.WriteFile(sig_destination, signature, 0644)
	return signature

}

// Generate signature for each given digest
func generate_signature_of_a_string(digest, privkeyfile string) []byte {

	// provision key pair
	cprivateKey, err := ioutil.ReadFile(privkeyfile)
	if err != nil {
		panic(err)
	}
	privateKey, err := crypto.UnmarshalECDSAPrivateKey(cprivateKey)
	if err != nil {
		panic(err)
	}
	signature, err := privateKey.Sign([]byte(digest))
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: %v\n", signature)
	return signature

}

func GenerateKeyPairTofile(file string) bool {
	privateKey, publicKey, err := crypto.GenerateECDSAKeyPairWithCurve(elliptic.P384(), rand.Reader)
	if err != nil {
		return false
	}
	cpublicKey, err := publicKey.Raw()
	if err != nil {
		return false
	}
	cprivateKey, err := privateKey.Raw()
	if err != nil {
		return false
	}
	privateKey.Sign(cpublicKey)

	err = ioutil.WriteFile(file+"publickey", cpublicKey, 0644)
	if err != nil {
		return false
	}

	err = ioutil.WriteFile(file+"privateKey", cprivateKey, 0644)
	return err == nil

}

func string_hash_generation(str string) string {
	digest := sha256.New()
	digest.Write([]byte(fmt.Sprintf("%s", str)))
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func filenameGeneration(NID string, PSCODE string) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprint(NID)))
	hash.Write([]byte(fmt.Sprint(PSCODE)))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func filehashGeneration(filename string) string {
	hash := sha256.New()
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return ""
	}
	hash.Write([]byte(fmt.Sprintf("%v", file)))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func digestGeneration(voter *Voter) string {
	digest := sha256.New()
	digest.Write([]byte(fmt.Sprintf("%v", voter.NID)))
	digest.Write([]byte(fmt.Sprintf("%v", voter.Name)))
	digest.Write([]byte(fmt.Sprintf("%v", voter.PSCODE)))
	digest.Write([]byte(fmt.Sprintf("%v", voter.Address.Union)))
	digest.Write([]byte(fmt.Sprintf("%v", voter.Address.Thana)))
	digest.Write([]byte(fmt.Sprintf("%v", voter.Address.District)))
	digest.Write([]byte(fmt.Sprintf("%v", voter.Profile_Digest)))

	return fmt.Sprintf("%x", digest.Sum(nil))
}

func generate_signature(privkeyfile, digest string) string {

	// provision key pair

	cprivateKey, err := ioutil.ReadFile(privkeyfile)
	if err != nil {
		panic(err)
	}
	privateKey, err := crypto.UnmarshalECDSAPrivateKey(cprivateKey)
	if err != nil {
		panic(err)
	}
	signature, err := privateKey.Sign([]byte(digest))
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}
