resource "google_project_iam_member" "project" {
  project = "your-project-id"
  role    = "roles/owner"
  member  = "user:jane@developer.gserviceaccount.com"
}