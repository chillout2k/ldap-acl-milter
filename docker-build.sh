#!/bin/sh

BRANCH="$(/usr/bin/git branch|/bin/grep \*|/usr/bin/awk {'print $2'})"
VERSION="$(/bin/cat VERSION)"
BASEOS="$(/bin/cat BASEOS)"
#REGISTRY="some-registry.invalid"
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
#    --build-arg http_proxy=http://wprx-zdf.zwackl.local:3128 \
#    --build-arg https_proxy=http://wprx-zdf.zwackl.local:3128 \
  /usr/bin/docker build \
    -t "${IMAGE}/${BASEOS}:${VERSION}_${BRANCH}" \
    -f "docker/${BASEOS}/Dockerfile" .
#  /usr/bin/docker tag "${IMAGE}/${BASEOS}:${VERSION}_${BRANCH}" "${REGISTRY}/${IMAGE}/${BASEOS}:${VERSION}_${BRANCH}"
done

#/bin/echo "Push images to registry:"
#for IMAGE in ${IMAGES}; do
#  /bin/echo "/usr/bin/docker push ${REGISTRY}/${IMAGE}/${BASEOS}:${VERSION}_${BRANCH}"
#done
