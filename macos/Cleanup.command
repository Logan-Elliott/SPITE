#!/bin/zsh
set -eu
if (( $# == 0 )); then
  print -n "Prepared workspace: "
  IFS= read -r workspace
  if [[ -z "$workspace" ]]; then
    print -u2 "Workspace path is required"
    exit 2
  fi
  set -- "$workspace"
fi
exec /bin/zsh "$(dirname -- "$0")/launch.sh" done "$@"
