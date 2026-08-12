#!/usr/bin/env bash
#
# Build the "Postgres Enterprise by AppsCode" image from this fork.
#
# The source is handed to the Dockerfile as a git archive of a branch/tag in
# this repository, so the image content is pinned to a git ref rather than to
# whatever happens to be in the working tree.
#
# Usage:
#   docker/build.sh [REF] [IMAGE]
#
#   REF     git ref to build from      (default: appscode/18)
#   IMAGE   image name:tag to produce  (default: ghcr.io/kubedb/postgres:18.6)

set -euo pipefail

REF="${1:-appscode/18}"
IMAGE="${2:-ghcr.io/kubedb/postgres:18.6}"

repo_root="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
cd "$repo_root"

if ! git rev-parse --verify --quiet "$REF^{commit}" >/dev/null; then
	echo "build.sh: no such git ref: $REF" >&2
	exit 1
fi

ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT

cp docker/Dockerfile docker/docker-entrypoint.sh docker/docker-ensure-initdb.sh "$ctx/"

echo "==> archiving $REF ($(git rev-parse --short "$REF"))"
git archive --format=tar.gz --output="$ctx/postgresql-src.tar.gz" "$REF"

echo "==> building $IMAGE"
docker build \
	--label "org.opencontainers.image.revision=$(git rev-parse "$REF")" \
	--label "org.opencontainers.image.source=$(git remote get-url origin 2>/dev/null || echo unknown)" \
	--label "org.opencontainers.image.title=Postgres Enterprise by AppsCode" \
	--label "org.opencontainers.image.version=18.6" \
	-t "$IMAGE" \
	"$ctx"

echo "==> built $IMAGE"
