#!/bin/sh
# Upgrade in place, keeping data and settings, and go back if it won't run.
# Usage: deploy/linux/upgrade.sh path/to/new/procwatch
set -eu
binary=${1:?usage: upgrade.sh path/to/new/procwatch}
as_service() { runuser -u procwatch -- env XDG_CONFIG_HOME=/etc XDG_DATA_HOME=/var/lib "$@"; }

# Otherwise the protection takes the upgrade for an attack.
as_service /usr/local/bin/procwatch --maintenance 15 "upgrade"
cp -p /usr/local/bin/procwatch /usr/local/bin/procwatch.previous
install -o root -g root -m 0755 "$binary" /usr/local/bin/procwatch
as_service /usr/local/bin/procwatch --accept-program
systemctl restart procwatch
sleep 5
if ! systemctl is-active --quiet procwatch; then
    echo "The new version didn't start: going back." >&2
    install -o root -g root -m 0755 /usr/local/bin/procwatch.previous /usr/local/bin/procwatch
    as_service /usr/local/bin/procwatch --accept-program
    systemctl restart procwatch
    exit 1
fi
as_service /usr/local/bin/procwatch --maintenance 0
echo "Upgraded."
