package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tsandall/lighthouse/internal/config"
)

var urlFlag = flag.String("u", "", "set URL of Styra DAS tenant to export from")
var styraToken = os.Getenv("STYRA_TOKEN")

type DASClient struct {
	url    string
	token  string
	client *http.Client
}

type DASResponse struct {
	Result    json.RawMessage `json:"result"`
	RequestId string          `json:"request_id"`
}

func (r *DASResponse) Decode(x interface{}) error {
	buf := bytes.NewBuffer(r.Result)
	decoder := json.NewDecoder(buf)
	return decoder.Decode(x)
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

func mapV1SystemToSystemConfig(v1 *v1System) (*config.System, error) {
	var x config.System

	x.Name = v1.Name

	if v1.SourceControl == nil {
		return nil, fmt.Errorf("not git backed")
	}

	x.Git.Repo = v1.SourceControl.Origin.URL

	if v1.SourceControl.Origin.Commit != "" {
		x.Git.Commit = &v1.SourceControl.Origin.Commit
	} else if v1.SourceControl.Origin.Reference != "" {
		x.Git.Reference = &v1.SourceControl.Origin.Reference
	} else {
		return nil, fmt.Errorf("origin missing commit and reference")
	}

	if v1.SourceControl.Origin.Path != "" {
		x.Git.Path = &v1.SourceControl.Origin.Path
	}

	if v1.SourceControl.Origin.Credentials != "" {
		x.Git.Credentials.HTTP = &v1.SourceControl.Origin.Credentials
	} else if v1.SourceControl.Origin.SSHCredentials.PrivateKey != "" {
		x.Git.Credentials.SSHPrivateKey = &v1.SourceControl.Origin.SSHCredentials.PrivateKey
		if v1.SourceControl.Origin.SSHCredentials.Passphrase != "" {
			x.Git.Credentials.SSHPassphrase = &v1.SourceControl.Origin.SSHCredentials.Passphrase
		}
	}

	return &x, nil
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

	output := config.Root{
		Systems: map[string]*config.System{},
		Secrets: map[string]*config.Secret{},
	}

	resp, err := c.Get("v1/systems")
	if err != nil {
		log.Fatal(err)
	}

	var systems []*v1System
	err = resp.Decode(&systems)
	if err != nil {
		log.Fatal(err)
	}

	resp, err = c.Get("v1/secrets")
	if err != nil {
		log.Fatal(err)
	}

	var secrets []*v1Secret
	err = resp.Decode(&secrets)
	if err != nil {
		log.Fatal(err)
	}

	for _, system := range systems {
		sc, err := mapV1SystemToSystemConfig(system)
		if err != nil {
			log.Printf("skipping system %q: %v", system.Name, err)
			continue
		}

		output.Systems[sc.Name] = sc
	}

	secretsById := map[string]*v1Secret{}
	for _, secret := range secretsById {
		secretsById[secret.Id] = secret
	}

	for _, sc := range output.Systems {
		if sc.Git.Credentials.HTTP != nil {
			id := *sc.Git.Credentials.HTTP
			output.Secrets[id] = &config.Secret{Name: id}
		}
		if sc.Git.Credentials.SSHPassphrase != nil {
			id := *sc.Git.Credentials.SSHPassphrase
			output.Secrets[id] = &config.Secret{Name: id}
		}
		if sc.Git.Credentials.SSHPrivateKey != nil {
			id := *sc.Git.Credentials.SSHPrivateKey
			output.Secrets[id] = &config.Secret{Name: id}
		}
	}

	bs, err := yaml.Marshal(output)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(bs))
}

type v1System struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	SourceControl *struct {
		Origin v1GitRepoConfig `json:"origin"`
	} `json:"source_control"`
}

type v1Secret struct {
	Name string `json:"string"`
	Id   string `json:"id"`
}

type v1Library struct {
	Id            string `json:"id"`
	SourceControl *struct {
		UseWorkspaceSettings bool            `json:"use_workspace_settings"`
		Origin               v1GitRepoConfig `json:"origin"`
		LibraryOrigin        v1GitRepoConfig `json:"library_origin"`
	} `json:"source_control"`
}

type v1Stack struct {
	Name          string `json:"name"`
	Id            string `json:"id"`
	SourceControl *struct {
		UseWorkspaceSettings bool            `json:"use_workspace_settings"`
		Origin               v1GitRepoConfig `json:"origin"`
		StackOrigin          v1GitRepoConfig `json:"stack_origin"`
	} `json:"source_control"`
}

type v1GitRepoConfig struct {
	Commit         string `json:"commit"`
	Path           string `json:"path"`
	Reference      string `json:"reference"`
	Credentials    string `json:"credentials"`
	SSHCredentials struct {
		Passphrase string `json:"passphrase"`
		PrivateKey string `json:"private_key"`
	} `json:"ssh_credentials"`
	URL string `json:"url"`
}
