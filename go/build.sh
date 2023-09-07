#!/bin/bash
# Prepare for release.

# Abort on first error.
trap 'echo Failed: $BASH_COMMAND >&2; exit 1' ERR

# Get version as argument or use 'devel'.
V=${1:-devel}
# Add version to this variable.
NAME='github.com/hknutzen/Netspoc/go/pkg/pass1.version'

# This script should be placed in "go" subdirectory, where Go sources
# are placed.  Get directory where this script is located.
dir=$(dirname $(readlink -f $0))

# Compile all commands.
# Prevent error: /lib64/libc.so.6: version `GLIBC_2.34' not found
export CGO_ENABLED=0
for d in $dir/cmd/*; do
    ( cd $d;
      go build -ldflags="-X '$NAME=$V'" )
done

# Do static analysis of source code.
cd $dir
go vet ./...

# Generate IPv6 tests
make --silent --directory=testdata/ipv6

# Execute tests.
( cd test; go test )
