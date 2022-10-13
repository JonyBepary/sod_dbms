package main

import (
	"crypto/sha256"
	"encoding/json"
	"log"
	"mime/multipart"
	"os"

	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

type Voter struct {
	Profile        *multipart.FileHeader `form:"avatar" binding:"required"`
	NID            string                `form:"nid"`
	Name           string                `form:"name"`
	PSCODE         string                `form:"pscode"`
	Address        address
	Profile_Digest string `form:"profile_digest"`
	Digest         string `form:"digest"`
	SIGN           string `form:"signature"`
}
type address struct {
	Union    string `form:"union"`
	Thana    string `form:"thana"`
	District string `form:"district"`
	PO       string `form:"PO"`
}
type nid struct {
	Voters    []string `json:"voters"`
	Pscode    string   `json:"pscode"`
	Seed      string   `json:"seed"`
	Digest    string   `json:"digest"`
	Signature string   `json:"signature"`
}

// Initialize voter data in struct
// value passed as params from url query
func init_voter(voter *Voter, c *gin.Context) {
	voter.NID = c.DefaultQuery("nid", "")
	if voter.NID == "" {
		c.String(http.StatusBadRequest, "Mandatory api key: \"nid\" missing")
		return
	}

	voter.Name = c.Query("name")
	if voter.Name == "" {
		c.String(http.StatusBadRequest, "Mandatory api key: \"name\" missing")
		return
	}
	voter.PSCODE = c.Query("pscode") // shortcut for c.Request.URL.Query().Get("lastname")
	if voter.PSCODE == "" {
		c.String(http.StatusBadRequest, "Mandatory api key: \"pscode\" missing")
		return
	}
	voter.Address.Union = c.Query("union")
	if voter.Address.Union == "" {
		c.String(http.StatusBadRequest, "Mandatory api key: \"union\" missing")
		return
	}
	voter.Address.PO = c.Query("PO")
	if voter.Address.PO == "" {
		c.String(http.StatusBadRequest, "Mandatory api key: \"PO\" missing")
		return
	}
	voter.Address.Thana = c.Query("thana")
	if voter.Address.Thana == "" {
		c.String(http.StatusBadRequest, "Mandatory api key: \"thana\" missing")
		return
	}
	voter.Address.District = c.Query("district")
	if voter.Address.District == "" {
		c.String(http.StatusBadRequest, "Mandatory api key: \"district\" missing")
		return
	}

	// Avatar management
	if err := c.ShouldBind(voter); err != nil {
		c.String(http.StatusBadRequest, "Bad Request\n")
		return
	}

	if !isDirAvailable("data/") {
		os.Mkdir("data/", os.ModePerm)
	}
	if !isDirAvailable("data/assets/") {
		os.Mkdir("data/assets/", os.ModePerm)
	}
	// saved profile pic at avatar_pic_path
	avatar_pic_path := "data/assets/" + filenameGeneration(voter.NID, voter.PSCODE) + filepath.Ext(voter.Profile.Filename)
	err := c.SaveUploadedFile(voter.Profile, avatar_pic_path)
	if err != nil {
		c.String(http.StatusInternalServerError, "SaveUploadedFile error")
		return
	}

	// add a hash of profile pic for main digest
	voter.Profile_Digest = filehashGeneration(avatar_pic_path)

	// creates a hash digest of all the data parsed from query params and body
	voter.Digest = digestGeneration(voter)
	// check if private key availble in local directory
	if !isFileAvailable("./privateKey") {
		c.String(http.StatusNotAcceptable, "KeyNotAvailable\n")
		return
	}
	// with a private key it signs the digest
	//(means it encrypts to be decrypted by it's respective public key)
	voter.SIGN = generate_signature("./privateKey", voter.Digest)

}

func add_vote(c *gin.Context) {
	// create voter object
	voter := new(Voter)
	init_voter(voter, c)

	filename := "data/" + voter.PSCODE + "/"
	if !isFileAvailable(filename) {
		os.Mkdir(filename, os.ModePerm)
	}
	hashstr := filenameGeneration(voter.NID, voter.PSCODE)
	filename += hashstr
	if isFileAvailable(filename) {
		c.String(http.StatusConflict, "Unsuccessful, Voter already exist!!!")
		return
	}
	file, err := json.MarshalIndent(voter, "", " ")
	if err != nil {
		c.String(http.StatusInternalServerError, "Unsuccessfully, Data marshaling error!!!")
	}
	ioutil.WriteFile(filename, file, 0644)
	fmt.Println(filename)
	c.String(http.StatusOK, "Voter successfully added!!!")

}

// This function serve voter information
// according to nid and polling station code
func hid_my_call(c *gin.Context) {

	// parsing params from url query
	NID := c.DefaultQuery("nid", "Guest")
	PSCODE := c.Query("pscode") // shortcut for c.Request.URL.Query().Get("lastname")

	// generating hash from parsed data (nid, pscode)
	// filename is as same as hash
	hashstr := filenameGeneration(NID, PSCODE)
	filename := "data/" + PSCODE + "/" + hashstr //? adjusting file path
	if !isFileAvailable(filename) {
		c.String(http.StatusNotFound, "Entity, Not Found!")
		return
	}

	file, _ := ioutil.ReadFile(filename) //read voter data from file
	voter := new(Voter)                  //create a Voter struct object
	json.Unmarshal(file, voter)          //copy voter data from file to struct object
	c.IndentedJSON(http.StatusOK, voter) //*serve it to over api request
}
func remove_voter(c *gin.Context) {

	// parsing params from url query
	NID := c.DefaultQuery("nid", "Guest")
	PSCODE := c.Query("pscode") // shortcut for c.Request.URL.Query().Get("lastname")

	// generating hash from parsed data (nid, pscode)
	// filename is as same as hash
	hashstr := filenameGeneration(NID, PSCODE)

	filename := "data/" + PSCODE + "/" + hashstr //? adjusting file path
	if !isFileAvailable(filename) {
		c.String(http.StatusNotFound, "Entity, Not Found!")
	} else {
		err := os.Remove(filename)
		if err != nil {
			log.Println("Failed to remove: ", filename)
			return
		}
	}

	filename = "data/assets/" + hashstr //? adjusting file path
	if !isFileAvailable(filename) {
		c.String(http.StatusNotFound, "Entity, Not Found!")
		return
	}
	err := os.Remove(filename)
	if err != nil {
		log.Println("Failed to remove: ", filename)
		return
	}
}

func makekeypair(c *gin.Context) {
	if GenerateKeyPairTofile("./") {
		c.String(http.StatusOK, "key pair generated\n")
	} else {
		c.String(http.StatusBadRequest, "Failed to generate key pair\n")
	}
}
func list_voter(c *gin.Context) {
	PSCODE := c.Query("pscode") // shortcut for c.Request.URL.Query().Get("lastname")
	Seed := c.Query("seed")     // shortcut for c.Request.URL.Query().Get("lastname")
	filename := "data/" + PSCODE + "/"
	if !isDirAvailable(filename) {
		c.String(http.StatusBadRequest, fmt.Sprintf("No enity found on PSCODE: %s\n", PSCODE))
		return
	}
	list := new(nid)
	file, err := ioutil.ReadDir("data/" + PSCODE)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(file))
	digest := sha256.New()
	for _, v := range file {
		if !v.IsDir() {
			list.Voters = append(list.Voters, v.Name())
			digest.Write([]byte(fmt.Sprintf("%v", list.Voters[len(list.Voters)-1])))
		}
	}
	list.Pscode = PSCODE
	list.Seed = Seed
	digest.Write([]byte(fmt.Sprintf("%v", list.Pscode)))
	digest.Write([]byte(fmt.Sprintf("%v", list.Seed)))
	list.Digest = fmt.Sprintf("%x", digest.Sum(nil))
	list.Signature = generate_signature("privateKey", list.Digest)
	// json_byte, _ := json.Marshal(list)
	if err != nil {
		c.String(http.StatusExpectationFailed, "Failed to process json from struct") //*serve it to over api request
		return
	}
	// json.Unmarshal(json_byte, list)
	// fmt.Println(json_byte)
	c.IndentedJSON(http.StatusOK, list) //*serve it to over api request

}
func main() {

	router := gin.Default()

	//Serving public key for digital signature authentication.
	router.StaticFile("/sword_of_durant/publickey", "./publickey")
	//take a pscode and a seed return list of voter on that specific
	router.GET("/list_voter", list_voter)

	//take a pscode and a nid number to remove a voter from list
	router.GET("/remove_voter", remove_voter)
	//  Query string parameters are parsed using the existing underlying request object.
	// *The request responds to a url matching:
	// /sword_of_durant?nid=20215103018&pscode=12345678
	router.GET("/sword_of_durant", hid_my_call)
	router.Static("/sword_of_durant/data/assets", "./data/assets")
	router.GET("/makekeypair", makekeypair)

	// Query string parameters are parsed using the existing underlying request object.
	// * The request responds to a url matching:
	// /sword_of_durant?nid=20215103018&name=Sohel Ahmed Jony&pscode=12345678&PO=Naodoba&union=Naodoba&thana=Janjira&district=Shariatpur
	router.POST("/sword_of_durant", add_vote)
	router.Run(":8888")
}

//! todo1: add api pass public key
// todo2: add img support
//? router := gin.Default()
//? router.Static("/image", "./path-to-image-dir")
// todo3: separate folder for each data
// todo4: reduce filename size
//? base20, would that hamper performance
// todo5: add a authentication mechanism facilitate[].(RO, PA, PO)
