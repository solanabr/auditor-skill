#!/bin/sh
# Fixture: a runner registration that keeps the runner after its first job, and a runner that takes one job.
./config.sh --unattended --url https://github.com/example --token "$RUNNER_TOKEN" --labels linux
./run.sh
./run.sh --jitconfig "$JIT_CONFIG"
