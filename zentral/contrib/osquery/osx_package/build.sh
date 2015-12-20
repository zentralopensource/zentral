#!/bin/bash
# usage: build.sh server.fqdn osquery_secret_secret

set -e

# find install dir
# http://stackoverflow.com/questions/59895/can-a-bash-script-tell-what-directory-its-stored-in 
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

# make temporary dir
TEMPDIR="$(mktemp -d)"

# cp pkg template in temporary dir
cp -r $DIR/build.tmpl/* "$TEMPDIR"

# replace hostname
sed -i -e "s/%TLS_HOSTNAME%/$1/" $TEMPDIR/root/Library/LaunchDaemons/com.facebook.osqueryd.plist

# build package Payload
(cd "$TEMPDIR/root" && find . | cpio -o --quiet --format odc --owner 0:80 | gzip -c) > "$TEMPDIR/base.pkg/Payload"

# replace osquery_secret_secret
sed -i -e "s/%OSQUERY_SECRET_SECRET%/$2/" $TEMPDIR/scripts/preinstall

# build package Scripts
(cd "$TEMPDIR/scripts" && find . | cpio -o --quiet --format odc --owner 0:80 | gzip -c) > "$TEMPDIR/base.pkg/Scripts"

# prepare PackageInfo
INSTALL_KB=$(du --apparent-size --block-size=1024 -s $TEMPDIR/root | awk '{print $1}')
sed -i -e "s/%INSTALL_KB%/$INSTALL_KB/" $TEMPDIR/base.pkg/PackageInfo

# build BOM
/usr/bin/mkbom -u 0 -g 80 $TEMPDIR/root $TEMPDIR/base.pkg/Bom

# build pkg
cd "$TEMPDIR/base.pkg" && xar --compression none -cf "$TEMPDIR/installer.pkg" *

rm -r $TEMPDIR/{root,scripts,base.pkg}

echo "$TEMPDIR/installer.pkg"
