#!/bin/bash
set -euo pipefail

IMAGE_NAME="tcp-syn-stop-builder"
VERSION_FILE="VERSION"

# Load builder-specific settings (bucket, maintainer) from env file.
if [[ -f release.env ]]; then
    # shellcheck source=release.env.example
    source release.env
else
    die "release.env not found — copy release.env.example and fill in your values"
fi
[[ -n "${GCS_BUCKET:-}" ]]      || die "GCS_BUCKET not set in release.env"
[[ -n "${DEB_MAINTAINER:-}" ]]  || die "DEB_MAINTAINER not set in release.env"

export DEB_MAINTAINER

die() { echo "error: $*" >&2; exit 1; }

# Advisory flock guard — prevents concurrent runs on the same local checkout.
# Relative path is intentional: the script already assumes CWD = repo root
# (VERSION_FILE="VERSION").  Advisory locks do not work over NFS; acceptable
# for a single-developer project.
LOCKFILE=".release.lock"
exec 9>"$LOCKFILE"
flock -n 9 || die "another release.sh is already running"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --bump       Bump version before building (default: debian revision)
  --minor      Bump minor version (implies --bump, e.g. 4.0-2 → 4.1-1)
  --major      Bump major version (implies --bump, e.g. 4.0-2 → 5.0-1)
  --publish    Upload repo to GCS (builds first unless artifacts already exist)
  -h, --help   Show this help message

Without --bump/--minor/--major, builds at the current version.
--publish alone uploads existing artifacts without rebuilding.
EOF
    exit 0
}

bump_version() {
    local current="$1" mode="$2"
    local upstream="${current%%-*}"   # e.g. 4.0
    local revision="${current##*-}"   # e.g. 2
    local major="${upstream%%.*}"     # e.g. 4
    local minor="${upstream#*.}"      # e.g. 0

    case "$mode" in
        revision)
            echo "${upstream}-$(( revision + 1 ))"
            ;;
        minor)
            echo "${major}.$(( minor + 1 ))-1"
            ;;
        major)
            echo "$(( major + 1 )).0-1"
            ;;
        *)
            die "unknown bump mode: $mode"
            ;;
    esac
}

# --- Parse arguments ---
do_bump=false
bump_mode="revision"
do_publish=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bump)    do_bump=true ;;
        --minor)   do_bump=true; bump_mode="minor" ;;
        --major)   do_bump=true; bump_mode="major" ;;
        --publish) do_publish=true ;;
        -h|--help) usage ;;
        *)         die "unknown option: $1" ;;
    esac
    shift
done

# --- Version bump ---
[[ -f "$VERSION_FILE" ]] || die "$VERSION_FILE not found"
current_version="$(cat "$VERSION_FILE" | tr -d '[:space:]')"

if $do_bump; then
    head_msg="$(git log -1 --format=%s)"
    if [[ "$head_msg" == "Bump version to $current_version" ]] \
       && ! git tag -l "v${current_version}" | grep -q .; then
        echo "Resuming interrupted release: HEAD already bumped to $current_version (untagged)"
    else
        new_version="$(bump_version "$current_version" "$bump_mode")"
        echo "$new_version" > "$VERSION_FILE"

        # Sync Cargo.toml version (translate debian X.Y-Z → semver X.Y.Z)
        cargo_version="${new_version//-/.}"
        sed -i "s/^version = \".*\"/version = \"${cargo_version}\"/" syn-sight/Cargo.toml

        echo "Version: $current_version → $new_version"

        git add "$VERSION_FILE" syn-sight/Cargo.toml
        git commit --no-gpg-sign -m "Bump version to $new_version"

        current_version="$new_version"
    fi
else
    echo "Building version: $current_version (no bump)"
fi

# --- Build (skip if --publish only and artifacts exist) ---
deb_path="repo/amd64/tcp-syn-stop_${current_version}_amd64.deb"
do_build=true

if $do_publish && ! $do_bump && [[ -f "$deb_path" ]]; then
    echo "Artifacts exist: $deb_path — skipping build"
    do_build=false
fi

if $do_build; then
    echo "Building build environment image: $IMAGE_NAME..."
    docker build -t "$IMAGE_NAME" -f release.Dockerfile .

    echo "Running build, tests and packaging..."
    # Integration tests require root + network namespaces and must be run
    # separately (sudo make integration-test).  The Docker build container
    # runs as the host user, so only unit/release tests are viable here.
    docker run --privileged --rm --user "$(id -u):$(id -g)" \
        -v "$(pwd)":/build/workspace -w /build/workspace \
        "$IMAGE_NAME" /bin/bash -c "make clean && make test-debug && make test-release && make deb"
fi

# --- Generate SHA256SUMS on the host (survives make clean) ---
[[ -f "$deb_path" ]] || die "expected artifact not found: $deb_path"
mkdir -p build
sha256sum "$deb_path" > build/SHA256SUMS

# --- Tag (only after successful build, skip if tag exists) ---
if $do_bump && ! git tag -l "v${current_version}" | grep -q .; then
    git tag "v${current_version}"
    echo "Tagged v${current_version}"
fi

# --- Publish ---
if $do_publish; then
    echo "Publishing to GCS: $GCS_BUCKET..."
    gcloud storage cp -r repo/amd64 "$GCS_BUCKET/"
    gcloud storage cp build/SHA256SUMS "$GCS_BUCKET/amd64/"
    echo "Release published successfully."
fi

echo "Done. Version: $current_version"
