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

func mapV1SystemToSystemAndSecretConfig(v1 *v1System, secretsById map[string]*v1Secret) (*config.System, *config.Secret, error) {
	var system config.System
	var secret config.Secret

	system.Name = v1.Name

	if v1.SourceControl == nil {
		return nil, nil, fmt.Errorf("not git backed")
	}

	system.Git.Repo = v1.SourceControl.Origin.URL

	if v1.SourceControl.Origin.Commit != "" {
		system.Git.Commit = &v1.SourceControl.Origin.Commit
	} else if v1.SourceControl.Origin.Reference != "" {
		system.Git.Reference = &v1.SourceControl.Origin.Reference
	} else {
		return nil, nil, fmt.Errorf("origin missing commit and reference")
	}

	if v1.SourceControl.Origin.Path != "" {
		system.Git.Path = &v1.SourceControl.Origin.Path
	}

	if v1.SourceControl.Origin.Credentials != "" {
		secret.Name = v1.SourceControl.Origin.Credentials
		if s, ok := secretsById[v1.SourceControl.Origin.Credentials]; ok {
			secret.Value = map[string]interface{}{
				"type":     "http_basic_auth",
				"username": s.Name,
			}
		}
		system.Git.Credentials = &config.SecretRef{Name: secret.Name}
	} else if v1.SourceControl.Origin.SSHCredentials.PrivateKey != "" {
		secret.Name = v1.SourceControl.Origin.SSHCredentials.PrivateKey
		secret.Value = map[string]interface{}{
			"type": "ssh_private_key",
		}
		system.Git.Credentials = &config.SecretRef{Name: secret.Name}
	}

	return &system, &secret, nil
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

	secretsById := map[string]*v1Secret{}
	for _, secret := range secrets {
		secretsById[secret.Id] = secret
	}

	for _, system := range systems {
		sc, secret, err := mapV1SystemToSystemAndSecretConfig(system, secretsById)
		if err != nil {
			log.Printf("skipping system %q: %v", system.Name, err)
			continue
		}

		output.Systems[sc.Name] = sc
		output.Secrets[secret.Name] = secret
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
	Name string `json:"name"`
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
