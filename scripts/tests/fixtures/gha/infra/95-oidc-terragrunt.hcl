# Fixture: Terragrunt inputs for a role module that trusts GitHub's OIDC tokens from one environment.
terraform {
  source = "git::https://github.com/example/terraform-aws-github-oidc-role.git?ref=v2.0.0"
}

inputs = {
  provider_url = "https://token.actions.githubusercontent.com"
  subjects     = ["repo:example/app:environment:production"]
}
