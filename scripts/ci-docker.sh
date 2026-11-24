#!/bin/sh
# Builds the image and pushes it, the way .gitlab-ci.yml does. POSIX sh: the
# CI image (docker:cli) is Alpine and has no bash.
#
# Two modes, matching the two CI jobs:
#
#   ci-docker.sh nightly   sha-<hash> and nightly, Docker Hub only
#   ci-docker.sh release   <version>, <major.minor> and latest, both registries
#
# Everything it needs comes from the environment, so it runs locally as well:
#
#   DOCKERHUB_USER=me ./scripts/ci-docker.sh nightly
#
# Environment:
#   DOCKERHUB_USER          required; also the Docker Hub namespace
#   CONTAINER_IMAGE_NAME    default keycordon
#   CI_COMMIT_TAG           set for a release (vX.Y.Z)
#   CI_COMMIT_SHORT_SHA     set for a nightly
#   CI_COMMIT_BRANCH        must equal CI_DEFAULT_BRANCH for a nightly
#   CI_REGISTRY_IMAGE       set for a release; GitLab registry path
#   GOPROXY / GOSUMDB       passed to the build
#   DRY_RUN=1               print the commands instead of running them

set -eu

mode="${1:-}"
case "$mode" in
nightly | release) ;;
*)
	echo "usage: $0 {nightly|release}" >&2
	exit 2
	;;
esac

: "${DOCKERHUB_USER:?DOCKERHUB_USER is required}"
IMAGE="${CONTAINER_IMAGE_NAME:-keycordon}"
HUB="docker.io/${DOCKERHUB_USER}/${IMAGE}"
BUILD="${IMAGE}:build"

run() {
	if [ "${DRY_RUN:-}" = "1" ]; then
		printf '  %s\n' "$*"
		return 0
	fi
	"$@"
}

# ---- what this build is --------------------------------------------------
if [ "$mode" = release ]; then
	: "${CI_COMMIT_TAG:?release needs CI_COMMIT_TAG}"
	version="${CI_COMMIT_TAG#v}"
	minor="${version%.*}"
	tags="${version} ${minor} latest"
else
	# A nightly may only come from the default branch: "nightly" is a moving
	# tag, and a feature branch is not what users should get when they pull
	# it. The pipeline rules already exclude other branches; this is the
	# guard for a manual run or a rule change.
	: "${CI_COMMIT_BRANCH:?nightly needs CI_COMMIT_BRANCH}"
	: "${CI_DEFAULT_BRANCH:?nightly needs CI_DEFAULT_BRANCH}"
	if [ "$CI_COMMIT_BRANCH" != "$CI_DEFAULT_BRANCH" ]; then
		echo "nightly is built from ${CI_DEFAULT_BRANCH} only, not ${CI_COMMIT_BRANCH}" >&2
		exit 1
	fi
	sha="${CI_COMMIT_SHORT_SHA:?nightly needs CI_COMMIT_SHORT_SHA}"
	version="0.0.0-${sha}"
	tags="sha-${sha} nightly"
fi

echo "== ${mode}: version ${version}, tags ${tags}"

# ---- build ---------------------------------------------------------------
echo "-- build"
run docker build --pull --provenance=false --sbom=false \
	--build-arg "VERSION=${version}" \
	--build-arg "GOPROXY=${GOPROXY:-https://proxy.golang.org,direct}" \
	--build-arg "GOSUMDB=${GOSUMDB:-sum.golang.org}" \
	-t "$BUILD" .

# ---- smoke test ----------------------------------------------------------
# An image that cannot start its own binary must never be pushed.
echo "-- smoke test"
run docker run --rm "$BUILD" version
run docker run --rm "$BUILD" adapters >/dev/null

# ---- tag and push --------------------------------------------------------
# A release goes to both registries; a nightly only to Docker Hub, so the
# GitLab registry holds releases alone instead of every nightly.
registry=""
if [ "$mode" = release ]; then
	: "${CI_REGISTRY_IMAGE:?release needs CI_REGISTRY_IMAGE}"
	registry="$CI_REGISTRY_IMAGE"
fi

for tag in $tags; do
	run docker tag "$BUILD" "${HUB}:${tag}"
	if [ -n "$registry" ]; then
		run docker tag "$BUILD" "${registry}:${tag}"
	fi
done
for tag in $tags; do
	echo "-- push ${HUB}:${tag}"
	run docker push "${HUB}:${tag}"
	if [ -n "$registry" ]; then
		echo "-- push ${registry}:${tag}"
		run docker push "${registry}:${tag}"
	fi
done

echo "== done"
echo "   Docker Hub: ${HUB}"
if [ -n "$registry" ]; then
	echo "   GitLab    : ${registry}"
fi
echo "   tags      : ${tags}"
