#!/bin/bash

set -e
abort () { echo "Aborted: $*" >&2; exit 1; }

# Get recent entries from CHANGELOG.md
DOC=$(sed -n "/^## \[Unreleased\]/I,/^## /p" CHANGELOG.md | grep -v '^## ')
# Abort if changes have only empty lines.
echo "$DOC" | grep -qv '^ *$'  || abort "CHANGELOG.md has no new entries"

# Check git
[ "$(git branch --show-current)" = "master" ] || abort "Not on master branch"
[ -z "$(git status --porcelain)" ] || abort "Uncommitted changes"
rev1=$(git rev-parse HEAD)
rev2=$(git ls-remote origin master | cut -f1)
[ $rev1 == $rev2 ] || abort "Need git pull/push"

# Build binaries and execute tests
export VERSION="$(date +%F-%H%M)"
go/build.sh $VERSION

# Check again for changed files, since build.sh may update IPv6 tests.
[ -z "$(git status --porcelain)" ] || abort "Uncommitted changes"

# Update version
sed -i "/^## \[Unreleased\]/Ia \\\n## [$VERSION]" CHANGELOG.md
git add CHANGELOG.md
git commit -m$VERSION
git push
git tag $VERSION
git push --tags

# Build packages; nfpm.yaml uses $VERSION
rm -rf released
mkdir released
nfpm package -p deb -t released/
nfpm package -p rpm -t released/

# Create release on GitHub.
echo "$DOC" |
    gh release create $VERSION --notes-file - --title $VERSION released/*
