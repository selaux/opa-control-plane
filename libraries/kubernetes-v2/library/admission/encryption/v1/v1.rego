package library.v1.kubernetes.admission.encryption.v1

import data.library.parameters
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Encryption: Restrict Key Management Service Providers"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "encryption"
# description: >-
#   Allow only key management service (KMS) providers with approved names and
#   corresponding endpoints.
# schema:
#   type: object
#   properties:
#     approved_kms_configs:
#       type: object
#       title: KMS name-endpoint pairs
#       patternNames:
#         title: "Plugin display name (Example: myKmsPlugin)"
#       additionalProperties:
#         type: array
#         title: "Server address (Example: unix:///tmp/socketfile.sock)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_kms_configs

check_kms_encryptionconfig[reason] {
	utils.kind_matches({"EncryptionConfiguration"})
	single_resources := input.request.object.resources[_]
	providers := single_resources.providers
	pos_identity := exist_key(providers, "identity")
	pos_kms := exist_key(providers, "kms")
	pos_kms > pos_identity
	reason := sprintf("Resource %v defines an identity provider before a key management service provider.", [utils.input_id])
}

check_kms_encryptionconfig[reason] {
	utils.kind_matches({"EncryptionConfiguration"})
	single_resources := input.request.object.resources[_]
	providers := single_resources.providers
	exist_key(providers, "identity")
	not exist_key(providers, "kms")
	reason := sprintf("Resource %v does not define a valid key management service provider.", [utils.input_id])
}

check_kms_encryptionconfig[reason] {
	count(parameters.approved_kms_configs) > 0
	utils.kind_matches({"EncryptionConfiguration"})
	kms_name = input.request.object.resources[_].providers[_].kms.name
	not parameters.approved_kms_configs[kms_name]
	reason := sprintf("Resource %v does not define an allowed key management service name and endpoint.", [utils.input_id])
}

check_kms_encryptionconfig[reason] {
	count(parameters.approved_kms_configs) > 0
	utils.kind_matches({"EncryptionConfiguration"})
	kms := input.request.object.resources[_].providers[_].kms
	kms_name := kms.name
	endpoint := kms.endpoint
	endpoints := parameters.approved_kms_configs[kms_name]
	not endpoints[endpoint]
	reason := sprintf("Resource %v does not define an allowed key management service name and endpoint.", [utils.input_id])
}

exist_key(providers, key) = pos {
	some i
	providers[i][key]
	pos := i
}

# METADATA: library-snippet
# version: v1
# title: "Encryption: Require Secrets to be Encrypted"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "encryption"
# description: >-
#   Prohibit the `identity` provider from being used to store secret data.

deny_identity_provider[reason] {
	utils.kind_matches({"EncryptionConfiguration"})
	secret_exists
	providers := input.request.object.resources[_].providers
	pos_identity := exist_key(providers, "identity")
	pos_kms := exist_key(providers, "kms")
	pos_identity < pos_kms
	reason := sprintf("Resource %v uses an `identity` provider for secrets encryption.", [utils.input_id])
}

deny_identity_provider[reason] {
	utils.kind_matches({"EncryptionConfiguration"})
	secret_exists
	providers := input.request.object.resources[_].providers
	pos_identity := exist_key(providers, "identity")
	not exist_key(providers, "kms")
	pos_identity != count(providers) - 1
	reason := sprintf("Resource %v uses an `identity` provider for secrets encryption.", [utils.input_id])
}

deny_identity_provider[reason] {
	utils.kind_matches({"EncryptionConfiguration"})
	secret_exists
	providers := input.request.object.resources[_].providers
	pos_identity := exist_key(providers, "identity")
	not exist_key(providers, "kms")
	pos_identity == count(providers) - 1
	count(providers) == 1
	reason := sprintf("Resource %v uses an `identity` provider for secrets encryption.", [utils.input_id])
}

kms_provider_exist {
	input.request.object.resources[_].providers.kms
}

secret_exists {
	protected_resources = input.request.object.resources[_].resources
	protected := protected_resources[_]
	protected == "secrets"
}
