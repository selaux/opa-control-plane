package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Internal configuration data structures for Lighthouse.

// Root is the top-level configuration structure used by Lighthouse.
type Root struct {
	Systems map[string]*System `yaml:"systems"`
	Secrets map[string]*Secret `yaml:"secrets"`
}

func (r *Root) ValidateAndInjectDefaults() (warnings []error, err error) {
	for name, system := range r.Systems {
		system.Name = name
		if system.Git.Repo == "" {
			return nil, fmt.Errorf("system %q is missing a git repo", name)
		}
	}
	for name, secret := range r.Secrets {
		secret.Name = name
		if secret.Value == nil {
			warnings = append(warnings, fmt.Errorf("secret %q is missing a value", name))
		}
	}
	return warnings, nil
}

// System defines the configuration for a Lighthouse System.
type System struct {
	Name string `yaml:"name"`
	Git  Git    `yaml:"git"`
}

// Git defines the Git synchronization configuration used by Lighthouse
// resources like Systems, Stacks, and Libraries.
type Git struct {
	Repo        string  `yaml:"repo"`
	Reference   *string `yaml:"reference,omitempty"`
	Commit      *string `yaml:"commit,omitempty"`
	Path        *string `yaml:"path,omitempty"`
	Credentials struct {
		HTTP          *string `yaml:"http,omitempty"`
		SSHPrivateKey *string `yaml:"ssh_private_key,omitempty"`
		SSHPassphrase *string `yaml:"ssh_passphrase,omitempty"`
	} `yaml:"credentials"`
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

	if err := yaml.Unmarshal(bs, &root); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config file %s: %w", filename, err)
	}

	warnings, err = root.ValidateAndInjectDefaults()
	if err != nil {
		return nil, nil, err
	}

	return root, warnings, nil
}

type ObjectStorage struct {
	Provider string `yaml:"provider"` // "aws" for Amazon S3, "gcp" for Google Cloud Storage, "azure" for Azure Blob Storage
}

// AmazonS3 defines the configuration for an Amazon S3-compatible object storage.
type AmazonS3 struct {
	Bucket string `yaml:"bucket"`
}

// GCPCloudStorage defines the configuration for a Google Cloud Storage bucket.
type GCPCloudStorage struct {
	Project string `yaml:"project"`
	Bucket  string `yaml:"bucket"`
}

// AzureBlobStorage defines the configuration for an Azure Blob Storage container.
type AzureBlobStorage struct {
	AccountURL string `yaml:"account_url"`
	Container  string `yaml:"container"`
}
