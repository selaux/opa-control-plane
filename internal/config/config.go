package config

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Internal configuration data structures for Lighthouse.

// Root is the top-level configuration structure used by Lighthouse.
type Root struct {
	Systems map[string]*System `yaml:"systems"`
	Secrets map[string]*Secret `yaml:"secrets"`
}

func (r *Root) ValidateAndInjectDefaults() (errs []error) {
	for name, secret := range r.Secrets {
		secret.Name = name
		if secret.Value == nil {
			errs = append(errs, fmt.Errorf("secret %q is missing a value", name))
			delete(r.Secrets, name)
		}
	}
	for name, system := range r.Systems {
		system.Name = name
		if system.Git.Repo == "" {
			errs = append(errs, fmt.Errorf("system %q is missing a git repo", name))
			delete(r.Systems, name)
			continue
		}
		if system.Git.Credentials.HTTP != nil {
			_, ok := r.Secrets[*system.Git.Credentials.HTTP]
			if !ok {
				errs = append(errs, fmt.Errorf("system %q git http credential refers to secret %q that is invalid or undefined", name, *system.Git.Credentials.HTTP))
				delete(r.Systems, name)
				continue
			}
		}
		if system.Git.Credentials.SSHPassphrase != nil {
			_, ok := r.Secrets[*system.Git.Credentials.SSHPassphrase]
			if !ok {
				errs = append(errs, fmt.Errorf("system %q git ssh passphrase credential refers to secret %q that is invalid or undefined", name, *system.Git.Credentials.SSHPassphrase))
				delete(r.Systems, name)
				continue
			}
		}
		if system.Git.Credentials.SSHPrivateKey != nil {
			_, ok := r.Secrets[*system.Git.Credentials.SSHPrivateKey]
			if !ok {
				errs = append(errs, fmt.Errorf("system %q git ssh private key credential refers to secret %q that is invalid or undefined", name, *system.Git.Credentials.SSHPrivateKey))
				delete(r.Systems, name)
				continue
			}
		}
	}
	return errs
}

// System defines the configuration for a Lighthouse System.
type System struct {
	Name          string        `yaml:"name"`
	Git           Git           `yaml:"git"`
	ObjectStorage ObjectStorage `yaml:"object_storage"`
}

// Git defines the Git synchronization configuration used by Lighthouse
// resources like Systems, Stacks, and Libraries.
type Git struct {
	Repo        string         `yaml:"repo"`
	Reference   *string        `yaml:"reference,omitempty"`
	Commit      *string        `yaml:"commit,omitempty"`
	Path        *string        `yaml:"path,omitempty"`
	Credentials GitCredentials `yaml:"credentials"`
}

type GitCredentials struct {
	HTTP          *string `yaml:"http,omitempty"`
	SSHUserName   *string `yaml:"ssh_username,omitempty"`
	SSHPrivateKey *string `yaml:"ssh_private_key,omitempty"`
	SSHPassphrase *string `yaml:"ssh_passphrase,omitempty"`
}

// Secret defines the configuration for secrets/tokens used by Lighthouse
// for Git synchronization, datasources, etc. If the value is unset it indicates
// the Secret has not been configured completely.
type Secret struct {
	Name  string  `yaml:"name"`
	Value *string `yaml:"value,omitempty"`
}

func ParseFile(filename string) (root *Root, warnings []error, err error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
	}

	return Parse(bytes.NewReader(bs))
}

func Parse(r io.Reader) (root *Root, warnings []error, err error) {
	bs, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	if err := yaml.Unmarshal(bs, &root); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	errs := root.ValidateAndInjectDefaults()
	return root, errs, nil
}

type ObjectStorage struct {
	AmazonS3         *AmazonS3         `yaml:"aws,omitempty"`
	GCPCloudStorage  *GCPCloudStorage  `yaml:"gcp,omitempty"`
	AzureBlobStorage *AzureBlobStorage `yaml:"azure,omitempty"`
}

// AmazonS3 defines the configuration for an Amazon S3-compatible object storage.
type AmazonS3 struct {
	Bucket          string `yaml:"bucket"`
	Key             string `yaml:"key"`
	Region          string `yaml:"region,omitempty"`
	AccessKeyId     string `yaml:"access_key_id,omitempty"`
	SecretAccessKey string `yaml:"secret_access_key,omitempty"`
	SessionToken    string `yaml:"session_token,omitempty"`
}

// GCPCloudStorage defines the configuration for a Google Cloud Storage bucket.
type GCPCloudStorage struct {
	Project string `yaml:"project"`
	Bucket  string `yaml:"bucket"`
	Object  string `yaml:"object"`
}

// AzureBlobStorage defines the configuration for an Azure Blob Storage container.
type AzureBlobStorage struct {
	AccountURL string `yaml:"account_url"`
	Container  string `yaml:"container"`
	Path       string `yaml:"path"`
}
