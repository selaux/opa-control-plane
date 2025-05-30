resource "aws_ssm_document" "tf_ssm" {
  name          = "test_document"
  document_type = "Command"

  permissions = {
    type = "Share",
    account_ids = "All" # change this to specific account ids to make it private
  }

  content = <<DOC
  {
    "schemaVersion": "1.2",
    "description": "Check ip configuration of a Linux instance.",
    "parameters": {
    },
    "runtimeConfig": {
      "aws:runShellScript": {
        "properties": [
          {
            "id": "0.aws:runShellScript",
            "runCommand": ["ifconfig"]
          }
        ]
      }
    }
  }
DOC
}
