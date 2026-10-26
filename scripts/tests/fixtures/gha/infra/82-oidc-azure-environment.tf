# Fixture: an Azure federated credential bound to one repository's production environment, and that
# repository's customized OIDC subject claim.
resource "azuread_application_federated_identity_credential" "deploy" {
  application_id = azuread_application.deploy.id
  display_name   = "github-production"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:example/app:environment:production"
}

resource "github_actions_repository_oidc_subject_claim_customization_template" "app" {
  repository         = "app"
  use_default        = false
  include_claim_keys = ["repo", "context"]
}
