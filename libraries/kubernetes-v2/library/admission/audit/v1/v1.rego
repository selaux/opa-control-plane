package library.v1.kubernetes.admission.audit.v1

import data.library.parameters
import data.library.v1.kubernetes.admission.util.v1 as util
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Audits: Require HTTPS"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "audit"
# description: >-
#   Require HTTPS for dynamic audit webhook backends (`AuditSink` resources). Using HTTPS ensures network traffic is encrypted.

require_auditsink[reason] {
	utils.kind_matches({"AuditSink"})
	input.request.object.spec.webhook

	# Although the doc says this field can only be https, kubernetes does not enforce it, verified on minikube. So we need this rule.
	not startswith(input.request.object.spec.webhook.clientConfig.url, "https://")
	reason := sprintf("AuditSink %v uses an insecure HTTP URL.", [utils.input_id])
}
