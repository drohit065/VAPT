#!/bin/sh
# GIT_ASKPASS helper: supplies the access token from the environment so it never appears
# in the clone URL, the process list, or .git/config.
case "$1" in
  Username*) printf '%s\n' "${VAPT_GIT_USERNAME:-x-access-token}" ;;
  *) printf '%s\n' "${VAPT_GIT_TOKEN:-}" ;;
esac
