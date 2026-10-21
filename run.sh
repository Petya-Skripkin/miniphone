#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$(id -u)" ]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi
# Diagnostics do not claim the phone's single-instance lock.
case " $* " in
    *" --check "*|*" --devices "*) exec python3 phone.py "$@" ;;
esac
exec 9>"${XDG_RUNTIME_DIR:-/tmp}/miniphone-$(id -u).lock"
if ! flock -n 9; then
    printf '%s\n' 'MiniPhone is already running. Use its existing terminal window.' >&2
    exit 1
fi
exec python3 phone.py "$@"
