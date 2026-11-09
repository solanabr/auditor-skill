# Fixture: a Vault JWT role for GitHub's tokens, bound to one workflow file on the default branch.
resource "vault_jwt_auth_backend" "github" {
  path               = "github"
  oidc_discovery_url = "https://token.actions.githubusercontent.com"
  bound_issuer       = "https://token.actions.githubusercontent.com"
}

resource "vault_jwt_auth_backend_role" "deploy" {
  backend         = vault_jwt_auth_backend.github.path
  role_name       = "deploy"
  role_type       = "jwt"
  user_claim      = "actor"
  bound_audiences = ["https://github.com/example"]
  bound_claims = {
    job_workflow_ref = "example/app/.github/workflows/deploy.yml@refs/heads/main"
  }
  token_policies = ["deploy"]
}
