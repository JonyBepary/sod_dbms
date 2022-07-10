package main

import (
	"encoding/json"

	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Voter struct {
	NID     string `json:"nid"`
	Name    string `json:"name"`
	PSCODE  string `json:"pscode"`
	Address address
	Digest  string `json:"digest"`
	SIGN    string `json:"signature"`
}
type address struct {
	Union    string `json:"union"`
	Thana    string `json:"thana"`
	District string `json:"district"`
	PO       string `json:"PO"`
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

	if !isFileAvailable("./privateKey") {
		c.String(http.StatusNotAcceptable, "KeyNotAvailable")
		return
	}

	// create hash digest of all the data parsed from query params
	voter.Digest = digestGeneration(voter)

	// with a private key it signs the digest
	//(means it encrypts to be decrypted by it's respective public key)
	voter.SIGN = generate_signature(voter.Digest)

}

func add_vote(c *gin.Context) {

	// create voter object
	voter := new(Voter)
	init_voter(voter, c)
	hashstr := filenameGeneration(voter.NID, voter.PSCODE)
	file, _ := json.MarshalIndent(voter, "", " ")
	filename := "data/" + hashstr
	ioutil.WriteFile(filename, file, 0644)
	fmt.Println(filename)
	c.String(http.StatusOK, "Voter Succesfully added!!!")

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
	filename := "data/" + hashstr //? adjusting file path
	if !isFileAvailable(filename) {
		c.String(http.StatusNotFound, "Entity, Not Found!")
		return
	}

	file, _ := ioutil.ReadFile(filename) //read voter data from file
	voter := new(Voter)                  //create a Voter struct object
	json.Unmarshal(file, voter)          //copy voter data from file to struct object
	c.IndentedJSON(http.StatusOK, voter) //*serve it to over api request
}

func main() {

	router := gin.Default()

	//  Query string parameters are parsed using the existing underlying request object.
	// *The request responds to a url matching:
	// /sword_of_durant?nid=20215103018&pscode=12345678
	router.GET("/sword_of_durant", hid_my_call)

	// Query string parameters are parsed using the existing underlying request object.
	// * The request responds to a url matching:
	// /sword_of_durant?nid=20215103018&name=Sohel Ahmed Jony&pscode=12345678&PO=Naodoba&union=Naodoba&thana=Janjira&district=Shariatpur
	router.POST("/sword_of_durant", add_vote)
	//

	router.Run(":8888")
}
	// todo1: add api pass public key
	// todo2: add img support
	//? router := gin.Default()
	//? router.Static("/image", "./path-to-image-dir")
	// todo3: separate folder for each data
	// todo4: reduce filename size
	//? base20, would that hamper performance
	// todo5: add a authentication mechanism facilitate[].(RO, PA, PO)
