#!/bin/bash
GIT_REF="09f249a06e7e3289930bf6d05f38fb562f748ebf"

set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# remove current files
rm -rf "$SCRIPT_DIR/other" "$SCRIPT_DIR/declarative"

# clone Apple repository to temporary folder
git clone -q https://github.com/apple/device-management /tmp/device-management

# set git clone as current directory
cd /tmp/device-management

# store current reference
git describe --tags --always "$GIT_REF" > "$SCRIPT_DIR/reference.txt"

# copy files
git archive --format=tar "$GIT_REF" LICENSE.txt declarative/declarations other/skipkeys.yaml | tar -C "$SCRIPT_DIR" -xf -

# cleanup temporary folder
rm -rf /tmp/device-management
