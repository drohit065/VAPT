#!/usr/bin/env bash
# VAPT Scanner CI client: start a scan, wait for it, enforce a quality gate.
#
# Required environment:
#   VAPT_URL       e.g. https://vapt.example.com           (the dashboard address)
#   VAPT_API_KEY   an API key with the analyst role (Settings -> API keys & CI/CD)
# Source (one of):
#   VAPT_SOURCE=zip      (default) zip the current directory (git-tracked files if inside a repo)
#   VAPT_SOURCE=git      scan VAPT_REPO_URL (https) at VAPT_BRANCH; VAPT_GIT_TOKEN for private repos
#   VAPT_SOURCE=url      scan the live URL(s) in VAPT_TARGETS (newline or comma separated)
#   VAPT_SOURCE=image    scan the container image VAPT_IMAGE (e.g. ghcr.io/org/app:sha)
# Optional:
#   VAPT_CHECKS     JSON of checks, e.g. '{"code":true,"deps":true,"secrets":true,"iac":true}'
#   VAPT_FAIL_ON    Critical | High (default) | Medium | Low | none
#   VAPT_NEW_ONLY   true = only fail on findings that are new since the previous scan
#   VAPT_SARIF      path to write a SARIF file (for GitHub code scanning upload)
#   VAPT_TIMEOUT    seconds to wait for the scan (default 3600)
#
# Needs: curl, jq, zip (for zip mode). Exit codes: 0 passed, 1 gate failed, 2 error.
set -euo pipefail

: "${VAPT_URL:?set VAPT_URL}"
: "${VAPT_API_KEY:?set VAPT_API_KEY}"
SOURCE="${VAPT_SOURCE:-zip}"
FAIL_ON="${VAPT_FAIL_ON:-High}"
NEW_ONLY="${VAPT_NEW_ONLY:-false}"
TIMEOUT="${VAPT_TIMEOUT:-3600}"
API="${VAPT_URL%/}/api"
AUTH=(-H "Authorization: Bearer ${VAPT_API_KEY}")
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

die() { echo "vapt: $*" >&2; exit 2; }
command -v jq >/dev/null || die "jq is required"

form=(-F "source_type=${SOURCE}")
[ -n "${VAPT_CHECKS:-}" ] && form+=(-F "checks=${VAPT_CHECKS}")
case "$SOURCE" in
  zip)
    name="$(basename "$PWD").zip"
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      # committed files of the current directory (and below) only
      git archive --format=zip -o "$WORK/$name" HEAD -- .
    else
      command -v zip >/dev/null || die "zip is required outside a git checkout"
      zip -qr "$WORK/$name" . -x '.git/*' 'node_modules/*'
    fi
    form+=(-F "file=@$WORK/$name;type=application/zip") ;;
  git)
    : "${VAPT_REPO_URL:?set VAPT_REPO_URL}"
    form+=(-F "repo_url=${VAPT_REPO_URL}")
    [ -n "${VAPT_BRANCH:-}" ] && form+=(-F "branch=${VAPT_BRANCH}")
    [ -n "${VAPT_GIT_TOKEN:-}" ] && form+=(-F "token=${VAPT_GIT_TOKEN}") ;;
  url)
    : "${VAPT_TARGETS:?set VAPT_TARGETS}"
    form+=(-F "target_urls=${VAPT_TARGETS}" -F "authorized=true") ;;
  image)
    : "${VAPT_IMAGE:?set VAPT_IMAGE}"
    form+=(-F "image_ref=${VAPT_IMAGE}") ;;
  *) die "unknown VAPT_SOURCE=$SOURCE" ;;
esac

resp="$(curl -sS --fail-with-body "${AUTH[@]}" "${form[@]}" "$API/scans")" || die "could not start the scan: $resp"
scan_id="$(jq -r .id <<<"$resp")"
echo "vapt: scan #$scan_id started (${SOURCE})"

deadline=$(( $(date +%s) + TIMEOUT ))
while :; do
  gate="$(curl -sS --fail-with-body "${AUTH[@]}" "$API/scans/$scan_id/gate?fail_on=$FAIL_ON&new_only=$NEW_ONLY")" \
    || die "gate request failed: $gate"
  [ "$(jq -r .done <<<"$gate")" = "true" ] && break
  [ "$(date +%s)" -gt "$deadline" ] && die "timed out after ${TIMEOUT}s waiting for scan #$scan_id"
  echo "vapt: $(jq -r .status <<<"$gate")..."
  sleep 15
done

if [ -n "${VAPT_SARIF:-}" ] && [ "$(jq -r .status <<<"$gate")" = "completed" ]; then
  curl -sS --fail "${AUTH[@]}" -o "$VAPT_SARIF" "$API/scans/$scan_id/export.sarif" && echo "vapt: SARIF written to $VAPT_SARIF"
fi

echo "vapt: open findings $(jq -c .counts <<<"$gate")"
[ "$(jq -r '.report_url // empty' <<<"$gate")" ] && echo "vapt: report $(jq -r .report_url <<<"$gate")"
if [ "$(jq -r .status <<<"$gate")" = "failed" ]; then
  die "scan failed: $(jq -r .error <<<"$gate")"
fi
if [ "$(jq -r .passed <<<"$gate")" = "true" ]; then
  echo "vapt: PASSED (no open findings at or above ${FAIL_ON}$([ "$NEW_ONLY" = true ] && echo ', new only'))"
  exit 0
fi
echo "vapt: FAILED: $(jq -r .blocking <<<"$gate") blocking finding(s) at or above ${FAIL_ON}:"
jq -r '.blocking_findings[] | "  [\(.severity)] \(.title)  \(.location)"' <<<"$gate"
exit 1
