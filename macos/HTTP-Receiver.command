#!/bin/zsh
exec /bin/zsh "$(dirname -- "$0")/launch.sh" receiver "$@"
