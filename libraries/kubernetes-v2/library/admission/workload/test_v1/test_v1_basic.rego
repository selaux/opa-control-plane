package library.v1.kubernetes.admission.workload.test_v1

import data.library.v1.kubernetes.admission.workload.v1

test_is_image_tag_latest {
	v1.is_image_tag_latest(v1.parse_image("localhost/foo/bar:latest"))

	not v1.is_image_tag_latest(v1.parse_image("localhost/foo/bar:not-latest"))

	v1.is_image_tag_latest(v1.parse_image("localhost/foo/bar"))

	not v1.is_image_tag_latest(v1.parse_image("localhost/foo/bar@123456abc:713"))
}
