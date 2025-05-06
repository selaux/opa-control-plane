package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tsandall/lighthouse/internal/config"
)

// refreshCredentialsInterval sets the refreshing interval to ensure they are up to date.
const refreshCredentialsInterval = 5 * time.Minute

// SecretCredentialsProvider is a custom credentials provider that retrieves AWS credentials from a secret every 5 minutes.
// It implements the aws.CredentialsProvider interface.
type SecretCredentialsProvider struct {
	aws.Credentials
	credentials *config.SecretRef
}

func NewSecretCredentialsProvider(credentials *config.SecretRef) *SecretCredentialsProvider {
	return &SecretCredentialsProvider{
		credentials: credentials,
	}
}

func (s *SecretCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	secret, err := s.credentials.Resolve()
	if err != nil {
		return aws.Credentials{}, err
	}

	value, err := secret.Get(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	switch value["type"] {
	case "aws_auth":
		accessKeyId, _ := value["access_key_id"].(string)
		secretAccessKey, _ := value["secret_access_key"].(string)
		sessionToken, _ := value["session_token"].(string)
		if accessKeyId != "" || secretAccessKey != "" || sessionToken != "" {
			return aws.Credentials{
				AccessKeyID: accessKeyId, SecretAccessKey: secretAccessKey, SessionToken: sessionToken,
				Source:    "configurated credentials",
				CanExpire: true,
				Expires:   time.Now().Add(refreshCredentialsInterval),
			}, nil
		}

		return aws.Credentials{}, fmt.Errorf("missing access_key_id or secret_access_key in credentials")
	default:
		return aws.Credentials{}, fmt.Errorf("unsupported authentication type: %s", value["type"])
	}
}
