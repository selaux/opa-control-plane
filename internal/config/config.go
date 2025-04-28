package config

// Internal configuration data structures for Lighthouse.

// Root is the top-level configuration structure used by Lighthouse.
type Root struct {
	Systems map[string]*System `yaml:"systems"`
	Secrets map[string]*Secret `yaml:"secrets"`
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
