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
# The most recently built one: that is the one likely to be running.
find_binary() {
    if [ -n "${PROCWATCH:-}" ]; then
        printf '%s\n' "$PROCWATCH"
        return
    fi
    release=$here/target/release/procwatch
    debug=$here/target/debug/procwatch
    if [ -x "$release" ] && [ -x "$debug" ]; then
        if [ "$release" -nt "$debug" ]; then printf '%s\n' "$release"; else printf '%s\n' "$debug"; fi
    elif [ -x "$release" ]; then
        printf '%s\n' "$release"
    elif [ -x "$debug" ]; then
        printf '%s\n' "$debug"
    else
        command -v procwatch || {
            echo "procwatch not found: run cargo build, or set PROCWATCH" >&2
            exit 2
        }
    fi
}
pw=$(find_binary)

if ! "$pw" --help 2>&1 | grep -q -e --alarm-trigger; then
    echo "$pw is older than this script. Run cargo build, then restart procwatch." >&2
    exit 2
fi

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
