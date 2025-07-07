package policy["com.styra.envoy.app"].main

main["allowed"] = allow

main["code"] = code

main["http_status"] = code

main["outcome"] = {
	"allowed": allow,
	"code": code,
	"http_status": code,
	"policy_type": "app",
	"system_type": "envoy",
}

code = 200 {
	allow == true
}

code = 403 {
	not allow == true
}

default allow = false

allow {
	system_allow == true
	not system_deny == true
}

system_allow {
	data.policy["com.styra.envoy.app"].rules.rules.allow
}

system_deny {
	not system_allow
}
