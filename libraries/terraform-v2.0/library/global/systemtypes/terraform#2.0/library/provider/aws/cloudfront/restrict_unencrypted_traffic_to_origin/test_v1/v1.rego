package global.systemtypes["terraform:2.0"].library.provider.aws.cloudfront.restrict_unencrypted_traffic_to_origin.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.cloudfront.restrict_unencrypted_traffic_to_origin.v1

test_restrict_unencrypted_traffic_to_origin_viewer_protocol_allow_all_origin_protocol_https_only_good {
	origin_protocol_policy := "https-only"
	default_cache_behavior_viewer_protocol_policy := "allow-all"
	ordered_cache_behavior_viewer_protocol_policy := "allow-all"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 0
}

test_restrict_unencrypted_traffic_to_origin_viewer_protocol_https_only_origin_protocol_https_only_good {
	origin_protocol_policy := "https-only"
	default_cache_behavior_viewer_protocol_policy := "https-only"
	ordered_cache_behavior_viewer_protocol_policy := "https-only"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 0
}

test_restrict_unencrypted_traffic_to_origin_viewer_protocol_redirect_to_https_origin_protocol_https_only_good {
	origin_protocol_policy := "https-only"
	default_cache_behavior_viewer_protocol_policy := "redirect-to-https"
	ordered_cache_behavior_viewer_protocol_policy := "redirect-to-https"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 0
}

test_restrict_unencrypted_traffic_to_origin_viewer_protocol_https_only_origin_protocol_http_only_bad {
	origin_protocol_policy := "http-only"
	default_cache_behavior_viewer_protocol_policy := "https-only"
	ordered_cache_behavior_viewer_protocol_policy := "https-only"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 1
}

test_restrict_unencrypted_traffic_to_origin_viewer_protocol_redirect_to_https_origin_protocol_http_only_good {
	origin_protocol_policy := "http-only"
	default_cache_behavior_viewer_protocol_policy := "redirect-to-https"
	ordered_cache_behavior_viewer_protocol_policy := "redirect-to-https"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 1
}

test_restrict_unencrypted_traffic_to_origin_viewer_protocol_https_only_origin_protocol_match_viewer_good {
	origin_protocol_policy := "match-viewer"
	default_cache_behavior_viewer_protocol_policy := "https-only"
	ordered_cache_behavior_viewer_protocol_policy := "https-only"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 0
}

test_restrict_unencrypted_traffic_to_origin_viewer_protocol_redirect_to_https_origin_protocol_match_viewer_good {
	origin_protocol_policy := "match-viewer"
	default_cache_behavior_viewer_protocol_policy := "redirect-to-https"
	ordered_cache_behavior_viewer_protocol_policy := "redirect-to-https"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 0
}

test_restrict_unencrypted_traffic_to_origin_both_viewer_protocol_allow_all_origin_protocol_http_only_bad {
	origin_protocol_policy := "http-only"
	default_cache_behavior_viewer_protocol_policy := "allow-all"
	ordered_cache_behavior_viewer_protocol_policy := "allow-all"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 1
}

test_restrict_unencrypted_traffic_to_origin_default_cache_behavior_viewer_protocol_allow_all_origin_protocol_http_only_bad {
	origin_protocol_policy := "http-only"
	default_cache_behavior_viewer_protocol_policy := "allow-all"
	ordered_cache_behavior_viewer_protocol_policy := "https-only"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 1
}

test_restrict_unencrypted_traffic_to_origin_ordered_cache_behavior_viewer_protocol_allow_all_origin_protocol_http_only_bad {
	origin_protocol_policy := "http-only"
	default_cache_behavior_viewer_protocol_policy := "https-only"
	ordered_cache_behavior_viewer_protocol_policy := "allow-all"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 1
}

test_restrict_unencrypted_traffic_to_origin_both_viewer_protocol_allow_all_origin_protocol_match_viewer_bad {
	origin_protocol_policy := "match-viewer"
	default_cache_behavior_viewer_protocol_policy := "allow-all"
	ordered_cache_behavior_viewer_protocol_policy := "allow-all"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 1
}

test_restrict_unencrypted_traffic_to_origin_default_cache_behavior_viewer_protocol_allow_all_origin_protocol_match_viewer_bad {
	origin_protocol_policy := "match-viewer"
	default_cache_behavior_viewer_protocol_policy := "allow-all"
	ordered_cache_behavior_viewer_protocol_policy := "https-only"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 1
}

test_restrict_unencrypted_traffic_to_origin_ordered_cache_behavior_viewer_protocol_allow_all_origin_protocol_macth_viewer_bad {
	origin_protocol_policy := "match-viewer"
	default_cache_behavior_viewer_protocol_policy := "https-only"
	ordered_cache_behavior_viewer_protocol_policy := "allow-all"
	in := input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy)
	actual := v1.prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin with input as in
	count(actual) == 1
}

input_cloudfront_distribution(origin_protocol_policy, default_cache_behavior_viewer_protocol_policy, ordered_cache_behavior_viewer_protocol_policy) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.5",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [
				{
					"address": "module.sample_cloudfront_distribution.aws_cloudfront_distribution.custom_distribution",
					"mode": "managed",
					"type": "aws_cloudfront_distribution",
					"name": "custom_distribution",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 1,
					"values": {
						"aliases": [
							"mysite.example.com",
							"yoursite.example.com",
						],
						"comment": "Some comment",
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								"DELETE",
								"GET",
								"HEAD",
								"OPTIONS",
								"PATCH",
								"POST",
								"PUT",
							],
							"cache_policy_id": null,
							"cached_methods": [
								"GET",
								"HEAD",
							],
							"compress": false,
							"default_ttl": 3600,
							"field_level_encryption_id": null,
							"forwarded_values": [{
								"cookies": [{"forward": "none"}],
								"query_string": false,
							}],
							"function_association": [],
							"lambda_function_association": [],
							"max_ttl": 86400,
							"min_ttl": 0,
							"origin_request_policy_id": null,
							"realtime_log_config_arn": null,
							"response_headers_policy_id": null,
							"smooth_streaming": null,
							"target_origin_id": "myS3Origin",
							"viewer_protocol_policy": default_cache_behavior_viewer_protocol_policy,
						}],
						"default_root_object": "index.html",
						"enabled": true,
						"http_version": "http2",
						"is_ipv6_enabled": true,
						"logging_config": [],
						"ordered_cache_behavior": [{
							"allowed_methods": [
								"GET",
								"HEAD",
								"OPTIONS",
							],
							"cache_policy_id": null,
							"cached_methods": [
								"GET",
								"HEAD",
								"OPTIONS",
							],
							"compress": true,
							"default_ttl": 86400,
							"field_level_encryption_id": null,
							"forwarded_values": [{
								"cookies": [{
									"forward": "none",
									"whitelisted_names": null,
								}],
								"headers": ["Origin"],
								"query_string": false,
							}],
							"function_association": [],
							"lambda_function_association": [],
							"max_ttl": 31536000,
							"min_ttl": 0,
							"origin_request_policy_id": null,
							"path_pattern": "/content/immutable/*",
							"realtime_log_config_arn": null,
							"response_headers_policy_id": null,
							"smooth_streaming": null,
							"target_origin_id": "myS3Origin",
							"trusted_key_groups": null,
							"trusted_signers": null,
							"viewer_protocol_policy": ordered_cache_behavior_viewer_protocol_policy,
						}],
						"origin": [{
							"connection_attempts": 3,
							"connection_timeout": 10,
							"custom_header": [],
							"custom_origin_config": [{
								"http_port": 80,
								"https_port": 443,
								"origin_keepalive_timeout": 5,
								"origin_protocol_policy": origin_protocol_policy,
								"origin_read_timeout": 30,
								"origin_ssl_protocols": ["TLSv1.1"],
							}],
							"domain_name": "site.example.com",
							"origin_id": "ABCDEFG1234567",
							"origin_path": "*",
							"origin_shield": [],
							"s3_origin_config": [],
						}],
						"origin_group": [],
						"price_class": "PriceClass_200",
						"restrictions": [{"geo_restriction": [{
							"locations": [
								"CA",
								"DE",
								"GB",
								"US",
							],
							"restriction_type": "whitelist",
						}]}],
						"retain_on_delete": false,
						"tags": {"Environment": "production"},
						"tags_all": {"Environment": "production"},
						"viewer_certificate": [{
							"acm_certificate_arn": null,
							"cloudfront_default_certificate": true,
							"iam_certificate_id": null,
							"minimum_protocol_version": "TLSv1",
							"ssl_support_method": null,
						}],
						"wait_for_deployment": true,
						"web_acl_id": null,
					},
					"sensitive_values": {
						"aliases": [
							false,
							false,
						],
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								false,
								false,
								false,
								false,
								false,
								false,
								false,
							],
							"cached_methods": [
								false,
								false,
							],
							"forwarded_values": [{
								"cookies": [{"whitelisted_names": []}],
								"headers": [],
								"query_string_cache_keys": [],
							}],
							"function_association": [],
							"lambda_function_association": [],
							"trusted_key_groups": [],
							"trusted_signers": [],
						}],
						"logging_config": [],
						"ordered_cache_behavior": [{
							"allowed_methods": [
								false,
								false,
								false,
							],
							"cached_methods": [
								false,
								false,
								false,
							],
							"forwarded_values": [{
								"cookies": [{}],
								"headers": [false],
								"query_string_cache_keys": [],
							}],
							"function_association": [],
							"lambda_function_association": [],
						}],
						"origin": [{
							"custom_header": [],
							"custom_origin_config": [{"origin_ssl_protocols": [false]}],
							"origin_shield": [],
							"s3_origin_config": [],
						}],
						"origin_group": [],
						"restrictions": [{"geo_restriction": [{"locations": [
							false,
							false,
							false,
							false,
						]}]}],
						"tags": {},
						"tags_all": {},
						"trusted_key_groups": [],
						"trusted_signers": [],
						"viewer_certificate": [{}],
					},
				},
				{
					"address": "module.sample_cloudfront_distribution.aws_cloudfront_distribution.s3_distribution",
					"mode": "managed",
					"type": "aws_cloudfront_distribution",
					"name": "s3_distribution",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 1,
					"values": {
						"aliases": [
							"mysite.example.com",
							"yoursite.example.com",
						],
						"comment": "Some comment",
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								"DELETE",
								"GET",
								"HEAD",
								"OPTIONS",
								"PATCH",
								"POST",
								"PUT",
							],
							"cache_policy_id": null,
							"cached_methods": [
								"GET",
								"HEAD",
							],
							"compress": false,
							"default_ttl": 3600,
							"field_level_encryption_id": null,
							"forwarded_values": [{
								"cookies": [{"forward": "none"}],
								"query_string": false,
							}],
							"function_association": [],
							"lambda_function_association": [],
							"max_ttl": 86400,
							"min_ttl": 0,
							"origin_request_policy_id": null,
							"realtime_log_config_arn": null,
							"response_headers_policy_id": null,
							"smooth_streaming": null,
							"target_origin_id": "myS3Origin",
							"viewer_protocol_policy": "allow-all",
						}],
						"default_root_object": null,
						"enabled": true,
						"http_version": "http2",
						"is_ipv6_enabled": true,
						"logging_config": [{
							"bucket": "mylogs.s3.amazonaws.com",
							"include_cookies": false,
							"prefix": "myprefix",
						}],
						"ordered_cache_behavior": [
							{
								"allowed_methods": [
									"GET",
									"HEAD",
									"OPTIONS",
								],
								"cache_policy_id": null,
								"cached_methods": [
									"GET",
									"HEAD",
									"OPTIONS",
								],
								"compress": true,
								"default_ttl": 86400,
								"field_level_encryption_id": null,
								"forwarded_values": [{
									"cookies": [{
										"forward": "none",
										"whitelisted_names": null,
									}],
									"headers": ["Origin"],
									"query_string": false,
								}],
								"function_association": [],
								"lambda_function_association": [],
								"max_ttl": 31536000,
								"min_ttl": 0,
								"origin_request_policy_id": null,
								"path_pattern": "/content/immutable/*",
								"realtime_log_config_arn": null,
								"response_headers_policy_id": null,
								"smooth_streaming": null,
								"target_origin_id": "myS3Origin",
								"trusted_key_groups": null,
								"trusted_signers": null,
								"viewer_protocol_policy": "redirect-to-https",
							},
							{
								"allowed_methods": [
									"GET",
									"HEAD",
									"OPTIONS",
								],
								"cache_policy_id": null,
								"cached_methods": [
									"GET",
									"HEAD",
								],
								"compress": true,
								"default_ttl": 3600,
								"field_level_encryption_id": null,
								"forwarded_values": [{
									"cookies": [{
										"forward": "none",
										"whitelisted_names": null,
									}],
									"query_string": false,
								}],
								"function_association": [],
								"lambda_function_association": [],
								"max_ttl": 86400,
								"min_ttl": 0,
								"origin_request_policy_id": null,
								"path_pattern": "/content/*",
								"realtime_log_config_arn": null,
								"response_headers_policy_id": null,
								"smooth_streaming": null,
								"target_origin_id": "myS3Origin",
								"trusted_key_groups": null,
								"trusted_signers": null,
								"viewer_protocol_policy": "redirect-to-https",
							},
						],
						"origin": [{
							"connection_attempts": 3,
							"connection_timeout": 10,
							"custom_header": [],
							"custom_origin_config": [],
							"origin_id": "myS3Origin",
							"origin_path": "",
							"origin_shield": [],
							"s3_origin_config": [{"origin_access_identity": "origin-access-identity/cloudfront/ABCDEFG1234567"}],
						}],
						"origin_group": [],
						"price_class": "PriceClass_200",
						"restrictions": [{"geo_restriction": [{
							"locations": [
								"CA",
								"DE",
								"GB",
								"US",
							],
							"restriction_type": "whitelist",
						}]}],
						"retain_on_delete": false,
						"tags": {"Environment": "production"},
						"tags_all": {"Environment": "production"},
						"viewer_certificate": [{
							"acm_certificate_arn": null,
							"cloudfront_default_certificate": true,
							"iam_certificate_id": null,
							"minimum_protocol_version": "TLSv1",
							"ssl_support_method": null,
						}],
						"wait_for_deployment": true,
						"web_acl_id": null,
					},
					"sensitive_values": {
						"aliases": [
							false,
							false,
						],
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								false,
								false,
								false,
								false,
								false,
								false,
								false,
							],
							"cached_methods": [
								false,
								false,
							],
							"forwarded_values": [{
								"cookies": [{"whitelisted_names": []}],
								"headers": [],
								"query_string_cache_keys": [],
							}],
							"function_association": [],
							"lambda_function_association": [],
							"trusted_key_groups": [],
							"trusted_signers": [],
						}],
						"logging_config": [{}],
						"ordered_cache_behavior": [
							{
								"allowed_methods": [
									false,
									false,
									false,
								],
								"cached_methods": [
									false,
									false,
									false,
								],
								"forwarded_values": [{
									"cookies": [{}],
									"headers": [false],
									"query_string_cache_keys": [],
								}],
								"function_association": [],
								"lambda_function_association": [],
							},
							{
								"allowed_methods": [
									false,
									false,
									false,
								],
								"cached_methods": [
									false,
									false,
								],
								"forwarded_values": [{
									"cookies": [{}],
									"headers": [],
									"query_string_cache_keys": [],
								}],
								"function_association": [],
								"lambda_function_association": [],
							},
						],
						"origin": [{
							"custom_header": [],
							"custom_origin_config": [],
							"origin_shield": [],
							"s3_origin_config": [{}],
						}],
						"origin_group": [],
						"restrictions": [{"geo_restriction": [{"locations": [
							false,
							false,
							false,
							false,
						]}]}],
						"tags": {},
						"tags_all": {},
						"trusted_key_groups": [],
						"trusted_signers": [],
						"viewer_certificate": [{}],
					},
				},
				{
					"address": "module.sample_cloudfront_distribution.aws_s3_bucket.b",
					"mode": "managed",
					"type": "aws_s3_bucket",
					"name": "b",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"acl": "private",
						"bucket": "mybucket",
						"bucket_prefix": null,
						"cors_rule": [],
						"force_destroy": false,
						"grant": [],
						"lifecycle_rule": [],
						"logging": [],
						"policy": null,
						"replication_configuration": [],
						"server_side_encryption_configuration": [],
						"tags": {"Name": "My bucket"},
						"tags_all": {"Name": "My bucket"},
						"website": [],
					},
					"sensitive_values": {
						"cors_rule": [],
						"grant": [],
						"lifecycle_rule": [],
						"logging": [],
						"object_lock_configuration": [],
						"replication_configuration": [],
						"server_side_encryption_configuration": [],
						"tags": {},
						"tags_all": {},
						"versioning": [],
						"website": [],
					},
				},
				{
					"address": "module.sample_cloudfront_distribution.aws_s3_bucket_acl.b_acl",
					"mode": "managed",
					"type": "aws_s3_bucket_acl",
					"name": "b_acl",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"acl": "private",
						"expected_bucket_owner": null,
					},
					"sensitive_values": {"access_control_policy": []},
				},
			],
			"address": "module.sample_cloudfront_distribution",
		}]}},
		"resource_changes": [
			{
				"address": "module.sample_cloudfront_distribution.aws_cloudfront_distribution.custom_distribution",
				"module_address": "module.sample_cloudfront_distribution",
				"mode": "managed",
				"type": "aws_cloudfront_distribution",
				"name": "custom_distribution",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"aliases": [
							"mysite.example.com",
							"yoursite.example.com",
						],
						"comment": "Some comment",
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								"DELETE",
								"GET",
								"HEAD",
								"OPTIONS",
								"PATCH",
								"POST",
								"PUT",
							],
							"cache_policy_id": null,
							"cached_methods": [
								"GET",
								"HEAD",
							],
							"compress": false,
							"default_ttl": 3600,
							"field_level_encryption_id": null,
							"forwarded_values": [{
								"cookies": [{"forward": "none"}],
								"query_string": false,
							}],
							"function_association": [],
							"lambda_function_association": [],
							"max_ttl": 86400,
							"min_ttl": 0,
							"origin_request_policy_id": null,
							"realtime_log_config_arn": null,
							"response_headers_policy_id": null,
							"smooth_streaming": null,
							"target_origin_id": "myS3Origin",
							"viewer_protocol_policy": default_cache_behavior_viewer_protocol_policy,
						}],
						"default_root_object": "index.html",
						"enabled": true,
						"http_version": "http2",
						"is_ipv6_enabled": true,
						"logging_config": [],
						"ordered_cache_behavior": [{
							"allowed_methods": [
								"GET",
								"HEAD",
								"OPTIONS",
							],
							"cache_policy_id": null,
							"cached_methods": [
								"GET",
								"HEAD",
								"OPTIONS",
							],
							"compress": true,
							"default_ttl": 86400,
							"field_level_encryption_id": null,
							"forwarded_values": [{
								"cookies": [{
									"forward": "none",
									"whitelisted_names": null,
								}],
								"headers": ["Origin"],
								"query_string": false,
							}],
							"function_association": [],
							"lambda_function_association": [],
							"max_ttl": 31536000,
							"min_ttl": 0,
							"origin_request_policy_id": null,
							"path_pattern": "/content/immutable/*",
							"realtime_log_config_arn": null,
							"response_headers_policy_id": null,
							"smooth_streaming": null,
							"target_origin_id": "myS3Origin",
							"trusted_key_groups": null,
							"trusted_signers": null,
							"viewer_protocol_policy": ordered_cache_behavior_viewer_protocol_policy,
						}],
						"origin": [{
							"connection_attempts": 3,
							"connection_timeout": 10,
							"custom_header": [],
							"custom_origin_config": [{
								"http_port": 80,
								"https_port": 443,
								"origin_keepalive_timeout": 5,
								"origin_protocol_policy": origin_protocol_policy,
								"origin_read_timeout": 30,
								"origin_ssl_protocols": ["TLSv1.1"],
							}],
							"domain_name": "site.example.com",
							"origin_id": "ABCDEFG1234567",
							"origin_path": "*",
							"origin_shield": [],
							"s3_origin_config": [],
						}],
						"origin_group": [],
						"price_class": "PriceClass_200",
						"restrictions": [{"geo_restriction": [{
							"locations": [
								"CA",
								"DE",
								"GB",
								"US",
							],
							"restriction_type": "whitelist",
						}]}],
						"retain_on_delete": false,
						"tags": {"Environment": "production"},
						"tags_all": {"Environment": "production"},
						"viewer_certificate": [{
							"acm_certificate_arn": null,
							"cloudfront_default_certificate": true,
							"iam_certificate_id": null,
							"minimum_protocol_version": "TLSv1",
							"ssl_support_method": null,
						}],
						"wait_for_deployment": true,
						"web_acl_id": null,
					},
					"after_unknown": {
						"aliases": [
							false,
							false,
						],
						"arn": true,
						"caller_reference": true,
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								false,
								false,
								false,
								false,
								false,
								false,
								false,
							],
							"cached_methods": [
								false,
								false,
							],
							"forwarded_values": [{
								"cookies": [{"whitelisted_names": true}],
								"headers": true,
								"query_string_cache_keys": true,
							}],
							"function_association": [],
							"lambda_function_association": [],
							"trusted_key_groups": true,
							"trusted_signers": true,
						}],
						"domain_name": true,
						"etag": true,
						"hosted_zone_id": true,
						"id": true,
						"in_progress_validation_batches": true,
						"last_modified_time": true,
						"logging_config": [],
						"ordered_cache_behavior": [{
							"allowed_methods": [
								false,
								false,
								false,
							],
							"cached_methods": [
								false,
								false,
								false,
							],
							"forwarded_values": [{
								"cookies": [{}],
								"headers": [false],
								"query_string_cache_keys": true,
							}],
							"function_association": [],
							"lambda_function_association": [],
						}],
						"origin": [{
							"custom_header": [],
							"custom_origin_config": [{"origin_ssl_protocols": [false]}],
							"origin_shield": [],
							"s3_origin_config": [],
						}],
						"origin_group": [],
						"restrictions": [{"geo_restriction": [{"locations": [
							false,
							false,
							false,
							false,
						]}]}],
						"status": true,
						"tags": {},
						"tags_all": {},
						"trusted_key_groups": true,
						"trusted_signers": true,
						"viewer_certificate": [{}],
					},
					"before_sensitive": false,
					"after_sensitive": {
						"aliases": [
							false,
							false,
						],
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								false,
								false,
								false,
								false,
								false,
								false,
								false,
							],
							"cached_methods": [
								false,
								false,
							],
							"forwarded_values": [{
								"cookies": [{"whitelisted_names": []}],
								"headers": [],
								"query_string_cache_keys": [],
							}],
							"function_association": [],
							"lambda_function_association": [],
							"trusted_key_groups": [],
							"trusted_signers": [],
						}],
						"logging_config": [],
						"ordered_cache_behavior": [{
							"allowed_methods": [
								false,
								false,
								false,
							],
							"cached_methods": [
								false,
								false,
								false,
							],
							"forwarded_values": [{
								"cookies": [{}],
								"headers": [false],
								"query_string_cache_keys": [],
							}],
							"function_association": [],
							"lambda_function_association": [],
						}],
						"origin": [{
							"custom_header": [],
							"custom_origin_config": [{"origin_ssl_protocols": [false]}],
							"origin_shield": [],
							"s3_origin_config": [],
						}],
						"origin_group": [],
						"restrictions": [{"geo_restriction": [{"locations": [
							false,
							false,
							false,
							false,
						]}]}],
						"tags": {},
						"tags_all": {},
						"trusted_key_groups": [],
						"trusted_signers": [],
						"viewer_certificate": [{}],
					},
				},
			},
			{
				"address": "module.sample_cloudfront_distribution.aws_cloudfront_distribution.s3_distribution",
				"module_address": "module.sample_cloudfront_distribution",
				"mode": "managed",
				"type": "aws_cloudfront_distribution",
				"name": "s3_distribution",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"aliases": [
							"mysite.example.com",
							"yoursite.example.com",
						],
						"comment": "Some comment",
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								"DELETE",
								"GET",
								"HEAD",
								"OPTIONS",
								"PATCH",
								"POST",
								"PUT",
							],
							"cache_policy_id": null,
							"cached_methods": [
								"GET",
								"HEAD",
							],
							"compress": false,
							"default_ttl": 3600,
							"field_level_encryption_id": null,
							"forwarded_values": [{
								"cookies": [{"forward": "none"}],
								"query_string": false,
							}],
							"function_association": [],
							"lambda_function_association": [],
							"max_ttl": 86400,
							"min_ttl": 0,
							"origin_request_policy_id": null,
							"realtime_log_config_arn": null,
							"response_headers_policy_id": null,
							"smooth_streaming": null,
							"target_origin_id": "myS3Origin",
							"viewer_protocol_policy": "allow-all",
						}],
						"default_root_object": null,
						"enabled": true,
						"http_version": "http2",
						"is_ipv6_enabled": true,
						"logging_config": [{
							"bucket": "mylogs.s3.amazonaws.com",
							"include_cookies": false,
							"prefix": "myprefix",
						}],
						"ordered_cache_behavior": [
							{
								"allowed_methods": [
									"GET",
									"HEAD",
									"OPTIONS",
								],
								"cache_policy_id": null,
								"cached_methods": [
									"GET",
									"HEAD",
									"OPTIONS",
								],
								"compress": true,
								"default_ttl": 86400,
								"field_level_encryption_id": null,
								"forwarded_values": [{
									"cookies": [{
										"forward": "none",
										"whitelisted_names": null,
									}],
									"headers": ["Origin"],
									"query_string": false,
								}],
								"function_association": [],
								"lambda_function_association": [],
								"max_ttl": 31536000,
								"min_ttl": 0,
								"origin_request_policy_id": null,
								"path_pattern": "/content/immutable/*",
								"realtime_log_config_arn": null,
								"response_headers_policy_id": null,
								"smooth_streaming": null,
								"target_origin_id": "myS3Origin",
								"trusted_key_groups": null,
								"trusted_signers": null,
								"viewer_protocol_policy": "redirect-to-https",
							},
							{
								"allowed_methods": [
									"GET",
									"HEAD",
									"OPTIONS",
								],
								"cache_policy_id": null,
								"cached_methods": [
									"GET",
									"HEAD",
								],
								"compress": true,
								"default_ttl": 3600,
								"field_level_encryption_id": null,
								"forwarded_values": [{
									"cookies": [{
										"forward": "none",
										"whitelisted_names": null,
									}],
									"query_string": false,
								}],
								"function_association": [],
								"lambda_function_association": [],
								"max_ttl": 86400,
								"min_ttl": 0,
								"origin_request_policy_id": null,
								"path_pattern": "/content/*",
								"realtime_log_config_arn": null,
								"response_headers_policy_id": null,
								"smooth_streaming": null,
								"target_origin_id": "myS3Origin",
								"trusted_key_groups": null,
								"trusted_signers": null,
								"viewer_protocol_policy": "redirect-to-https",
							},
						],
						"origin": [{
							"connection_attempts": 3,
							"connection_timeout": 10,
							"custom_header": [],
							"custom_origin_config": [],
							"origin_id": "myS3Origin",
							"origin_path": "",
							"origin_shield": [],
							"s3_origin_config": [{"origin_access_identity": "origin-access-identity/cloudfront/ABCDEFG1234567"}],
						}],
						"origin_group": [],
						"price_class": "PriceClass_200",
						"restrictions": [{"geo_restriction": [{
							"locations": [
								"CA",
								"DE",
								"GB",
								"US",
							],
							"restriction_type": "whitelist",
						}]}],
						"retain_on_delete": false,
						"tags": {"Environment": "production"},
						"tags_all": {"Environment": "production"},
						"viewer_certificate": [{
							"acm_certificate_arn": null,
							"cloudfront_default_certificate": true,
							"iam_certificate_id": null,
							"minimum_protocol_version": "TLSv1",
							"ssl_support_method": null,
						}],
						"wait_for_deployment": true,
						"web_acl_id": null,
					},
					"after_unknown": {
						"aliases": [
							false,
							false,
						],
						"arn": true,
						"caller_reference": true,
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								false,
								false,
								false,
								false,
								false,
								false,
								false,
							],
							"cached_methods": [
								false,
								false,
							],
							"forwarded_values": [{
								"cookies": [{"whitelisted_names": true}],
								"headers": true,
								"query_string_cache_keys": true,
							}],
							"function_association": [],
							"lambda_function_association": [],
							"trusted_key_groups": true,
							"trusted_signers": true,
						}],
						"domain_name": true,
						"etag": true,
						"hosted_zone_id": true,
						"id": true,
						"in_progress_validation_batches": true,
						"last_modified_time": true,
						"logging_config": [{}],
						"ordered_cache_behavior": [
							{
								"allowed_methods": [
									false,
									false,
									false,
								],
								"cached_methods": [
									false,
									false,
									false,
								],
								"forwarded_values": [{
									"cookies": [{}],
									"headers": [false],
									"query_string_cache_keys": true,
								}],
								"function_association": [],
								"lambda_function_association": [],
							},
							{
								"allowed_methods": [
									false,
									false,
									false,
								],
								"cached_methods": [
									false,
									false,
								],
								"forwarded_values": [{
									"cookies": [{}],
									"headers": true,
									"query_string_cache_keys": true,
								}],
								"function_association": [],
								"lambda_function_association": [],
							},
						],
						"origin": [{
							"custom_header": [],
							"custom_origin_config": [],
							"domain_name": true,
							"origin_shield": [],
							"s3_origin_config": [{}],
						}],
						"origin_group": [],
						"restrictions": [{"geo_restriction": [{"locations": [
							false,
							false,
							false,
							false,
						]}]}],
						"status": true,
						"tags": {},
						"tags_all": {},
						"trusted_key_groups": true,
						"trusted_signers": true,
						"viewer_certificate": [{}],
					},
					"before_sensitive": false,
					"after_sensitive": {
						"aliases": [
							false,
							false,
						],
						"custom_error_response": [],
						"default_cache_behavior": [{
							"allowed_methods": [
								false,
								false,
								false,
								false,
								false,
								false,
								false,
							],
							"cached_methods": [
								false,
								false,
							],
							"forwarded_values": [{
								"cookies": [{"whitelisted_names": []}],
								"headers": [],
								"query_string_cache_keys": [],
							}],
							"function_association": [],
							"lambda_function_association": [],
							"trusted_key_groups": [],
							"trusted_signers": [],
						}],
						"logging_config": [{}],
						"ordered_cache_behavior": [
							{
								"allowed_methods": [
									false,
									false,
									false,
								],
								"cached_methods": [
									false,
									false,
									false,
								],
								"forwarded_values": [{
									"cookies": [{}],
									"headers": [false],
									"query_string_cache_keys": [],
								}],
								"function_association": [],
								"lambda_function_association": [],
							},
							{
								"allowed_methods": [
									false,
									false,
									false,
								],
								"cached_methods": [
									false,
									false,
								],
								"forwarded_values": [{
									"cookies": [{}],
									"headers": [],
									"query_string_cache_keys": [],
								}],
								"function_association": [],
								"lambda_function_association": [],
							},
						],
						"origin": [{
							"custom_header": [],
							"custom_origin_config": [],
							"origin_shield": [],
							"s3_origin_config": [{}],
						}],
						"origin_group": [],
						"restrictions": [{"geo_restriction": [{"locations": [
							false,
							false,
							false,
							false,
						]}]}],
						"tags": {},
						"tags_all": {},
						"trusted_key_groups": [],
						"trusted_signers": [],
						"viewer_certificate": [{}],
					},
				},
			},
			{
				"address": "module.sample_cloudfront_distribution.aws_s3_bucket.b",
				"module_address": "module.sample_cloudfront_distribution",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "b",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"acl": "private",
						"bucket": "mybucket",
						"bucket_prefix": null,
						"cors_rule": [],
						"force_destroy": false,
						"grant": [],
						"lifecycle_rule": [],
						"logging": [],
						"policy": null,
						"replication_configuration": [],
						"server_side_encryption_configuration": [],
						"tags": {"Name": "My bucket"},
						"tags_all": {"Name": "My bucket"},
						"website": [],
					},
					"after_unknown": {
						"acceleration_status": true,
						"arn": true,
						"bucket_domain_name": true,
						"bucket_regional_domain_name": true,
						"cors_rule": [],
						"grant": [],
						"hosted_zone_id": true,
						"id": true,
						"lifecycle_rule": [],
						"logging": [],
						"object_lock_configuration": true,
						"object_lock_enabled": true,
						"region": true,
						"replication_configuration": [],
						"request_payer": true,
						"server_side_encryption_configuration": [],
						"tags": {},
						"tags_all": {},
						"versioning": true,
						"website": [],
						"website_domain": true,
						"website_endpoint": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"cors_rule": [],
						"grant": [],
						"lifecycle_rule": [],
						"logging": [],
						"object_lock_configuration": [],
						"replication_configuration": [],
						"server_side_encryption_configuration": [],
						"tags": {},
						"tags_all": {},
						"versioning": [],
						"website": [],
					},
				},
			},
			{
				"address": "module.sample_cloudfront_distribution.aws_s3_bucket_acl.b_acl",
				"module_address": "module.sample_cloudfront_distribution",
				"mode": "managed",
				"type": "aws_s3_bucket_acl",
				"name": "b_acl",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"acl": "private",
						"expected_bucket_owner": null,
					},
					"after_unknown": {
						"access_control_policy": true,
						"bucket": true,
						"id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {"access_control_policy": []},
				},
			},
		],
		"configuration": {
			"provider_config": {"module.sample_cloudfront_distribution:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 3.27",
				"module_address": "module.sample_cloudfront_distribution",
				"expressions": {
					"profile": {"constant_value": "default"},
					"region": {"references": ["var.region"]},
				},
			}},
			"root_module": {"module_calls": {"sample_cloudfront_distribution": {
				"source": "../../../../modules/cloudfront",
				"module": {
					"resources": [
						{
							"address": "aws_cloudfront_distribution.custom_distribution",
							"mode": "managed",
							"type": "aws_cloudfront_distribution",
							"name": "custom_distribution",
							"provider_config_key": "module.sample_cloudfront_distribution:aws",
							"expressions": {
								"aliases": {"constant_value": [
									"mysite.example.com",
									"yoursite.example.com",
								]},
								"comment": {"constant_value": "Some comment"},
								"default_cache_behavior": [{
									"allowed_methods": {"constant_value": [
										"DELETE",
										"GET",
										"HEAD",
										"OPTIONS",
										"PATCH",
										"POST",
										"PUT",
									]},
									"cached_methods": {"constant_value": [
										"GET",
										"HEAD",
									]},
									"default_ttl": {"constant_value": 3600},
									"forwarded_values": [{
										"cookies": [{"forward": {"constant_value": "none"}}],
										"query_string": {"constant_value": false},
									}],
									"max_ttl": {"constant_value": 86400},
									"min_ttl": {"constant_value": 0},
									"target_origin_id": {"references": ["local.s3_origin_id"]},
									"viewer_protocol_policy": {"constant_value": "allow-all"},
								}],
								"default_root_object": {"constant_value": "index.html"},
								"enabled": {"constant_value": true},
								"is_ipv6_enabled": {"constant_value": true},
								"ordered_cache_behavior": [{
									"allowed_methods": {"constant_value": [
										"GET",
										"HEAD",
										"OPTIONS",
									]},
									"cached_methods": {"constant_value": [
										"GET",
										"HEAD",
										"OPTIONS",
									]},
									"compress": {"constant_value": true},
									"default_ttl": {"constant_value": 86400},
									"forwarded_values": [{
										"cookies": [{"forward": {"constant_value": "none"}}],
										"headers": {"constant_value": ["Origin"]},
										"query_string": {"constant_value": false},
									}],
									"max_ttl": {"constant_value": 31536000},
									"min_ttl": {"constant_value": 0},
									"path_pattern": {"constant_value": "/content/immutable/*"},
									"target_origin_id": {"references": ["local.s3_origin_id"]},
									"viewer_protocol_policy": {"constant_value": "redirect-to-https"},
								}],
								"origin": [{
									"custom_origin_config": [{
										"http_port": {"constant_value": "80"},
										"https_port": {"constant_value": "443"},
										"origin_protocol_policy": {"constant_value": "http-only"},
										"origin_ssl_protocols": {"constant_value": ["TLSv1.1"]},
									}],
									"domain_name": {"constant_value": "site.example.com"},
									"origin_id": {"constant_value": "ABCDEFG1234567"},
									"origin_path": {"constant_value": "*"},
								}],
								"price_class": {"constant_value": "PriceClass_200"},
								"restrictions": [{"geo_restriction": [{
									"locations": {"constant_value": [
										"US",
										"CA",
										"GB",
										"DE",
									]},
									"restriction_type": {"constant_value": "whitelist"},
								}]}],
								"tags": {"constant_value": {"Environment": "production"}},
								"viewer_certificate": [{"cloudfront_default_certificate": {"constant_value": true}}],
							},
							"schema_version": 1,
						},
						{
							"address": "aws_cloudfront_distribution.s3_distribution",
							"mode": "managed",
							"type": "aws_cloudfront_distribution",
							"name": "s3_distribution",
							"provider_config_key": "module.sample_cloudfront_distribution:aws",
							"expressions": {
								"aliases": {"constant_value": [
									"mysite.example.com",
									"yoursite.example.com",
								]},
								"comment": {"constant_value": "Some comment"},
								"default_cache_behavior": [{
									"allowed_methods": {"constant_value": [
										"DELETE",
										"GET",
										"HEAD",
										"OPTIONS",
										"PATCH",
										"POST",
										"PUT",
									]},
									"cached_methods": {"constant_value": [
										"GET",
										"HEAD",
									]},
									"default_ttl": {"constant_value": 3600},
									"forwarded_values": [{
										"cookies": [{"forward": {"constant_value": "none"}}],
										"query_string": {"constant_value": false},
									}],
									"max_ttl": {"constant_value": 86400},
									"min_ttl": {"constant_value": 0},
									"target_origin_id": {"references": ["local.s3_origin_id"]},
									"viewer_protocol_policy": {"constant_value": "allow-all"},
								}],
								"enabled": {"constant_value": true},
								"is_ipv6_enabled": {"constant_value": true},
								"logging_config": [{
									"bucket": {"constant_value": "mylogs.s3.amazonaws.com"},
									"include_cookies": {"constant_value": false},
									"prefix": {"constant_value": "myprefix"},
								}],
								"ordered_cache_behavior": [
									{
										"allowed_methods": {"constant_value": [
											"GET",
											"HEAD",
											"OPTIONS",
										]},
										"cached_methods": {"constant_value": [
											"GET",
											"HEAD",
											"OPTIONS",
										]},
										"compress": {"constant_value": true},
										"default_ttl": {"constant_value": 86400},
										"forwarded_values": [{
											"cookies": [{"forward": {"constant_value": "none"}}],
											"headers": {"constant_value": ["Origin"]},
											"query_string": {"constant_value": false},
										}],
										"max_ttl": {"constant_value": 31536000},
										"min_ttl": {"constant_value": 0},
										"path_pattern": {"constant_value": "/content/immutable/*"},
										"target_origin_id": {"references": ["local.s3_origin_id"]},
										"viewer_protocol_policy": {"constant_value": "redirect-to-https"},
									},
									{
										"allowed_methods": {"constant_value": [
											"GET",
											"HEAD",
											"OPTIONS",
										]},
										"cached_methods": {"constant_value": [
											"GET",
											"HEAD",
										]},
										"compress": {"constant_value": true},
										"default_ttl": {"constant_value": 3600},
										"forwarded_values": [{
											"cookies": [{"forward": {"constant_value": "none"}}],
											"query_string": {"constant_value": false},
										}],
										"max_ttl": {"constant_value": 86400},
										"min_ttl": {"constant_value": 0},
										"path_pattern": {"constant_value": "/content/*"},
										"target_origin_id": {"references": ["local.s3_origin_id"]},
										"viewer_protocol_policy": {"constant_value": "redirect-to-https"},
									},
								],
								"origin": [{
									"domain_name": {"references": [
										"aws_s3_bucket.b.bucket_regional_domain_name",
										"aws_s3_bucket.b",
									]},
									"origin_id": {"references": ["local.s3_origin_id"]},
									"s3_origin_config": [{"origin_access_identity": {"constant_value": "origin-access-identity/cloudfront/ABCDEFG1234567"}}],
								}],
								"price_class": {"constant_value": "PriceClass_200"},
								"restrictions": [{"geo_restriction": [{
									"locations": {"constant_value": [
										"US",
										"CA",
										"GB",
										"DE",
									]},
									"restriction_type": {"constant_value": "whitelist"},
								}]}],
								"tags": {"constant_value": {"Environment": "production"}},
								"viewer_certificate": [{"cloudfront_default_certificate": {"constant_value": true}}],
							},
							"schema_version": 1,
						},
						{
							"address": "aws_s3_bucket.b",
							"mode": "managed",
							"type": "aws_s3_bucket",
							"name": "b",
							"provider_config_key": "module.sample_cloudfront_distribution:aws",
							"expressions": {
								"bucket": {"constant_value": "mybucket"},
								"tags": {"constant_value": {"Name": "My bucket"}},
							},
							"schema_version": 0,
						},
						{
							"address": "aws_s3_bucket_acl.b_acl",
							"mode": "managed",
							"type": "aws_s3_bucket_acl",
							"name": "b_acl",
							"provider_config_key": "module.sample_cloudfront_distribution:aws",
							"expressions": {
								"acl": {"constant_value": "private"},
								"bucket": {"references": [
									"aws_s3_bucket.b.id",
									"aws_s3_bucket.b",
								]},
							},
							"schema_version": 0,
						},
					],
					"variables": {"region": {"default": "us-west-2"}},
				},
			}}},
		},
		"relevant_attributes": [
			{
				"resource": "module.sample_cloudfront_distribution.aws_s3_bucket.b",
				"attribute": ["id"],
			},
			{
				"resource": "module.sample_cloudfront_distribution.aws_s3_bucket.b",
				"attribute": ["bucket_regional_domain_name"],
			},
		],
	}
}
