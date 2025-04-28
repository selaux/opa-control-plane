package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

var urlFlag = flag.String("u", "", "set URL of Styra DAS tenant to export from")
var styraToken = os.Getenv("STYRA_TOKEN")

type DASClient struct {
	url    string
	token  string
	client *http.Client
}

type DASResponse struct {
	Result    *interface{} `json:"result"`
	RequestId string       `json:"request_id"`
}

func (c *DASClient) Get(path string) (*DASResponse, error) {
	url := fmt.Sprintf("%v/%v", c.url, "/"+strings.TrimPrefix(path, "/"))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("authorization", fmt.Sprintf("Bearer %v", c.token))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DAS returned unexpected status code (%v) for %v %v", resp.StatusCode, "GET", url)
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var r DASResponse
	return &r, decoder.Decode(&r)
}

func main() {

	flag.Parse()

	if *urlFlag == "" {
		log.Fatal("Please set Styra DAS URL with -u flag (e.g., https://example.styra.com)")
	}

	if styraToken == "" {
		log.Fatal("Please set STYRA_TOKEN environment variable to token with WorkspaceViewer permission.")
	}

	c := DASClient{
		url:    *urlFlag,
		token:  styraToken,
		client: http.DefaultClient,
	}

	resp, err := c.Get("v1/systems")
	if err != nil {
		log.Fatal(err)
	}

	log.Println(resp, err)
}
