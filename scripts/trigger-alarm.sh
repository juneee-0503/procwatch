#!/bin/sh
# Trigger test alarms in a running procwatch, through the real alarm path:
# lamp, sound, record and notifications. Titles always start with [TEST].
# The session must have the alarm module loaded, and run as the same user.
#
#   scripts/trigger-alarm.sh high            one alarm: high, medium or low
#   scripts/trigger-alarm.sh all             one of each
#   scripts/trigger-alarm.sh sequence        low, then medium, then high
#   scripts/trigger-alarm.sh storm [N]       N alarms at once, default 20
#   scripts/trigger-alarm.sh clear           end all test alarms
#
# PROCWATCH=path/to/binary picks the program.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
find_binary() {
    if [ -n "${PROCWATCH:-}" ]; then
        printf '%s\n' "$PROCWATCH"
        return
    fi
    for candidate in "$here/target/release/procwatch" "$here/target/debug/procwatch"; do
        if [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    command -v procwatch || {
        echo "procwatch not found: build it, or set PROCWATCH" >&2
        exit 2
    }
}
pw=$(find_binary)

case "${1:-}" in
high | medium | low)
    "$pw" --alarm-trigger "$1"
    ;;
all)
    for level in low medium high; do
        "$pw" --alarm-trigger "$level"
    done
    ;;
sequence)
    "$pw" --alarm-trigger low
    sleep 5
    "$pw" --alarm-trigger medium
    sleep 5
    "$pw" --alarm-trigger high
    ;;
storm)
    "$pw" --alarm-trigger medium --count "${2:-20}"
    ;;
clear)
    "$pw" --alarm-clear
    ;;
*)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
