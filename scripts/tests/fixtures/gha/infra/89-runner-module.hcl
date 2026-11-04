# Fixture: Terragrunt inputs for a runner module that keeps each runner between jobs.
terraform {
  source = "git::https://github.com/example/terraform-aws-github-runner.git//modules/runners?ref=v6.0.0"
}

inputs = {
  enable_ephemeral_runners = false
  runner_extra_labels      = ["linux"]
}
