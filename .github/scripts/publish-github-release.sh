#!/usr/bin/env bash
# Complete an immutable release, including recovery after a partial publication.
set -euo pipefail
: "${TAG:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_RUN_ID:?}"
notes="docs/release-${TAG#v}.md"
test -s "$notes"
if gh release view "$TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  echo "Release $TAG already exists; preserving it."
  exit 0
fi

tagged_sha="$(git rev-parse "$TAG^{commit}")"
run_id=""
# Only artifacts from a run on the immutable version tag's commit are eligible.
# The current docs/repair commit must never replace already-published packages.
candidates="$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/pypi.yml/runs?head_sha=$tagged_sha&event=push&per_page=100" --jq '.workflow_runs[].id')"
for candidate in $candidates; do
  actual_sha="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$candidate" --jq '.head_sha')"
  test "$actual_sha" = "$tagged_sha" || continue
  published="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$candidate/jobs?per_page=100" --jq '[.jobs[] | select(.name == "publish" and .conclusion == "success")] | length')"
  if [[ "$published" != 0 ]]; then
    run_id="$candidate"
    break
  fi
done
if [[ -z "$run_id" ]]; then
  echo 'No validated PyPI publication found for the immutable tag; refusing release.' >&2
  exit 1
fi
artifacts="$(mktemp -d)"
trap 'rm -rf "$artifacts"' EXIT
gh run download "$run_id" --repo "$GITHUB_REPOSITORY" --name python-distributions --dir "$artifacts"
shopt -s nullglob
wheels=("$artifacts"/*.whl)
sources=("$artifacts"/*.tar.gz)
[[ ${#wheels[@]} == 1 && ${#sources[@]} == 1 ]]
gh release create "$TAG" "${wheels[0]}" "${sources[0]}" --verify-tag \
  --repo "$GITHUB_REPOSITORY" --title "HTTPdis $TAG" --notes-file "$notes"
