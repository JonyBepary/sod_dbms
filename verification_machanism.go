package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/purnaresa/bulwark/crypto"
)

func isFileAvailable(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

//Generate signature for each given digest
func generate_signature(digest string) string {

	// provision key pair
	privateKey, err := ioutil.ReadFile("./privateKey")
	if err != nil {
		panic(err)
	}

	digestByte := []byte(digest)
	signature, err := crypto.SignDefault(digestByte, privateKey)
	if err != nil {
		log.Fatalln(err)
	}
	return string(signature)
	// else {
	// 	log.Printf("signature : %s\n\n", string(signature))
	// } // verify signature
	// log.Println("verifying signature and plaintext...")
	// errVerify := crypto.VerifyDefault(digestByte, publicKey, signature)
	// if errVerify != nil {
	// 	log.Fatalln(errVerify)
	// } else {
	// 	log.Println("verification success!")
	// }

}

func GenerateKeyPairTofile() {
	privateKey, publicKey, err := crypto.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	ioutil.WriteFile("publickey", publicKey, 0644)
	ioutil.WriteFile("privateKey", privateKey, 0644)

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

func filenameGeneration(NID string, PSCODE string) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprint(NID)))
	hash.Write([]byte(fmt.Sprint(PSCODE)))
	return fmt.Sprintf("%x", hash.Sum(nil))
}
