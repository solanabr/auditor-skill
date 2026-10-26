#!/bin/sh
# Fixture (near misses for KV-080 Step 8): a build script whose lines resemble runner settings; the step lists
# none of them.
./configure --prefix=/usr/local
./config.sh --prefix=/usr/local --enable-tls
# ./config.sh --url https://github.com/example --token "$RUNNER_TOKEN"
echo "the runner group is chosen in the console"
