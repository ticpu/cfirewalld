#!/bin/bash

set -e

# Set changelog username and email.
export DEBFULLNAME=${DEBFULLNAME-`git config user.name`}
export DEBEMAIL=${DEBEMAIL-`git config user.email`}

# Set package name for debuild. 
PACKAGENAME="cfirewalld"

# Set version according to tag, if tag has commits after, add
# the hash in version number.
FULL_PACKAGENAME="${PACKAGENAME}"
TAG_MATCH="${PACKAGENAME}-v"
SHORT_VERSION="`git describe --match ${TAG_MATCH}* --abbrev=0`"
SHORT_VERSION="${SHORT_VERSION#$TAG_MATCH}"
SHORT_TAG="`git describe --match ${TAG_MATCH}* --tags`"
SHORT_TAG="${SHORT_TAG#$TAG_MATCH}"
if [[ "$SHORT_VERSION" == "$SHORT_TAG" ]]; then
	VERSION="${SHORT_VERSION}-1"
else
	VERSION="${SHORT_VERSION}-`git rev-parse HEAD | cut -c1-8`"
fi

# Set package dir for tarball.
PACKAGE_DIR="${FULL_PACKAGENAME}-${SHORT_VERSION}"



./debian/git-archive-all.sh --prefix "$PACKAGE_DIR/" \
	-t HEAD "${FULL_PACKAGENAME}_${SHORT_VERSION}.orig.tar"
gzip "${FULL_PACKAGENAME}_${SHORT_VERSION}.orig.tar"
[ -d "${PACKAGE_DIR}" ] && rm -r "${PACKAGE_DIR}"
tar -xzf "${FULL_PACKAGENAME}_${SHORT_VERSION}.orig.tar.gz"
cd "${PACKAGE_DIR}"

CHANGES=`git tag -v $TAG_MATCH$SHORT_VERSION 2>/dev/null | sed -r -n -e 's/\* (.*)\.?$/\1./p'`
dch --create -v "${VERSION}" --package "${FULL_PACKAGENAME}" "$CHANGES"
debuild "$@"
