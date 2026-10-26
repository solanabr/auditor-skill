# Fixture: an organization runner group that public repositories may use.
resource "github_actions_runner_group" "build" {
  name                       = "build-runners"
  visibility                 = "all"
  allows_public_repositories = true
}
