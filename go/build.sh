#!/bin/bash
# Prepare for release.

# Abort on first error.
set -e

V=${1:-devel}

# This script should be placed in "go" subdirectory, where Go sources
# are placed.  Get directory where this script is located.
dir=$(dirname $(readlink -f $0))

# Compile all commands.
for d in $dir/cmd/*; do
    ( cd $d; go build -ldflags="-X 'main.version=$V'" )
done

# Do static analysis of source code.
cd $dir
go vet ./...
