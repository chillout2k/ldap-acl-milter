#!/bin/sh

BRANCH="$(/usr/bin/git branch|/bin/grep \*|/usr/bin/awk {'print $2'})"
VERSION="$(/bin/cat VERSION)"
BASEOS="$(/bin/cat BASEOS)"
GO=""

while getopts g opt
do
  case $opt in
    g) GO="go";;
  esac
done

if [ -z "${GO}" ] ; then
  echo "Building ldap-acl-milter@docker on '${BASEOS}' for version '${VERSION}' in branch '${BRANCH}'!"
  echo "GO serious with '-g'!"
  exit 1
fi

IMAGES="ldap-acl-milter"

for IMAGE in ${IMAGES}; do
  /usr/bin/docker build \
    -t "${IMAGE}:${BRANCH}" \
    -f "docker/${BASEOS}/Dockerfile" .
done
