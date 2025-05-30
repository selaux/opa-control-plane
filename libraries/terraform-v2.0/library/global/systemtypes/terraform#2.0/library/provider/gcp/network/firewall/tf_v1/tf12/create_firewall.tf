resource "google_compute_firewall" "default" {
  name    = "test-firewall"
  network = "test-network"

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "1000-2000", "22"]
  }

  source_ranges = ["0.0.0.0/0"]
}