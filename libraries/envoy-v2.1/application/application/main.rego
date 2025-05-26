package application

# app rules entry point. Could not include it in conflict.rego , reason being, cannot identify from 
# input what if the request is of app type, hence kept the entry point separate

main["allowed"] = allow

main["code"] = code

main["http_status"] = code

main["outcome"] = {
	"allowed": allow,
	"code": code,
	"http_status": code,
	"policy_type": "app",
	"system_type": data.self.metadata.system_type,
}

code = 200 {
	allow
}

code = 403 {
	deny
}

default allow = false

deny {
	not allow
}

allow {
	system_allow
	not system_deny
}

system_allow {
	data.policy.app.allow
}

system_deny {
	data.policy.app.deny
}
