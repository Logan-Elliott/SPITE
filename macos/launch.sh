#!/bin/zsh
set -eu
package_root="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
phase="$1"
shift
exercise_python=""
for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if [[ -x "$candidate" ]] && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)' 2>/dev/null; then
    exercise_python="$candidate"
    break
  fi
done
if [[ -z "$exercise_python" ]]; then
  print -u2 'Python 3.9+ is required. Install it using your approved software channel, then retry.'
  exit 1
fi
if [[ "$phase" == capture ]]; then
  for argument in "$@"; do
    if [[ "$argument" == -h || "$argument" == --help ]]; then
      exec "$exercise_python" "$package_root/tools/exercise_ops.py" "$phase" "$@"
    fi
  done
  exec sudo "$exercise_python" "$package_root/tools/exercise_ops.py" "$phase" "$@"
fi
exec "$exercise_python" "$package_root/tools/exercise_ops.py" "$phase" "$@"
