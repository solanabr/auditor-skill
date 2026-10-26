#!/bin/sh
# Fixture: a setup script that registers GitHub's OIDC issuer with AWS and writes a role's trust policy for
# one branch.
aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com
cat > trust.json <<'EOF'
{"Condition": {"StringEquals": {"aud": "sts.amazonaws.com", "sub": "repo:example/app:ref:refs/heads/release"}}}
EOF
