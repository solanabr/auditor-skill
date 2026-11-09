#!/bin/sh
# Fixture (near misses for KV-080 Step 8 and KV-140 Step 7): a build script whose lines resemble runner and
# OIDC settings; neither step lists any of them.
./configure --prefix=/usr/local
./config.sh --prefix=/usr/local --enable-tls
# ./config.sh --url https://github.com/example --token "$RUNNER_TOKEN"
# issuer: https://token.actions.githubusercontent.com
echo "the runner group is chosen in the console; repo: example/app"
