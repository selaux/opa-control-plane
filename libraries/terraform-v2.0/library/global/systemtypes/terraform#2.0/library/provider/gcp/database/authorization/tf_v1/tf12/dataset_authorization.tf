resource "google_bigquery_dataset" "dataset" {
  dataset_id                  = "example_dataset"
  friendly_name               = "test"
  description                 = "This is a test description"
  location                    = "EU"
  default_table_expiration_ms = 3600000

  labels = {
    env = "default"
  }

  access {
    role          = "OWNER"
    special_group = "allAuthenticatedUsers"
  }
}

resource "google_bigquery_dataset" "dataset_with_access" {
  dataset_id = "dataset_with_access"
}

resource "google_bigquery_dataset_access" "access" {
  dataset_id    = google_bigquery_dataset.dataset_with_access.dataset_id
  role          = "OWNER"
  special_group = "allAuthenticatedUsers"
}

terraform {

  required_version = ">= 1.2"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4"
    }
  }
}

provider "google" {
  project = "tfc-test-370816"
  region  = "us-central1"
  zone    = "us-central1-c"
}
