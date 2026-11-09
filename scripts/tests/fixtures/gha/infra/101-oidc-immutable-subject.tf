# Fixture: trust policies written for GitHub's immutable OIDC subject format, which follows the owner and the
# repository with their numeric IDs: an AWS role that trusts every repository of the owner, and a Vault role bound
# to one repository's production environment.
data "aws_iam_policy_document" "deploy_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:example@1234567/*"]
    }
  }
}

resource "vault_jwt_auth_backend_role" "deploy" {
  backend         = "github"
  role_name       = "deploy"
  role_type       = "jwt"
  user_claim      = "actor"
  bound_audiences = ["https://github.com/example"]
  bound_subject   = "repo:example@1234567/app@7654321:environment:production"
}
