#!/bin/bash -e

# Set package name and version for debuild. 
PACKAGENAME="cfirewalld"

# Set changelog username and email.
[ -z "$DEBFULLNAME" ] && export DEBFULLNAME=`git config user.name`
[ -z "$DEBEMAIL" ] && export DEBEMAIL=`git config user.email`

git_describe () {
	git describe --match "${PACKAGENAME}-*" "$@"
}

TAG="`git_describe --abbrev=0`"
SHORT_TAG="`git_describe --tags`"
FULL_TAG="`git_describe`"
VERSION="${TAG#${PACKAGENAME}-}"
FULL_PACKAGENAME="${PACKAGENAME}"
if [[ "$TAG" == "$SHORT_TAG" ]]; then
	FULL_VERSION="${VERSION}-1"
else
	FULL_VERSION="${FULL_TAG#${PACKAGENAME}-${VERSION}-}"
	FULL_VERSION="${VERSION}-${FULL_VERSION/-/.}"
fi

# Set package dir for tarball.
PACKAGE_DIR="${FULL_PACKAGENAME}-${VERSION}"

git archive --prefix "$PACKAGE_DIR/" \
	-o "${FULL_PACKAGENAME}_${VERSION}.orig.tar.gz" HEAD .
[ -d "${PACKAGE_DIR}" ] && rm -r "${PACKAGE_DIR}"
tar -xzf "${FULL_PACKAGENAME}_${VERSION}.orig.tar.gz"
cd "${PACKAGE_DIR}"

CHANGES=`git tag -v ${TAG} 2>/dev/null | sed -r -n -e 's/\* (.*)\.?$/\1./p'`
dch --create -v "${FULL_VERSION}" --package "${FULL_PACKAGENAME}" "$CHANGES"
debuild "$@"
