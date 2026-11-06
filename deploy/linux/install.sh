#!/bin/sh
# Install procwatch as a service, run as root from the project folder.
# Usage: deploy/linux/install.sh path/to/procwatch
set -eu
binary=${1:?usage: install.sh path/to/procwatch}

id procwatch >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin procwatch
# Reading authentication logs.
getent group adm >/dev/null && usermod -aG adm procwatch
getent group systemd-journal >/dev/null && usermod -aG systemd-journal procwatch

install -o root -g root -m 0755 "$binary" /usr/local/bin/procwatch
install -d -o root -g procwatch -m 0750 /etc/procwatch
install -d -o procwatch -g procwatch -m 0750 /var/lib/procwatch /var/lib/procwatch/events

[ -e /etc/procwatch/agent.yml ] || install -o root -g procwatch -m 0640 rules/policy/agent-example.yml /etc/procwatch/agent.yml
[ -e /etc/procwatch/defense.yml ] || { echo "version: 1" >/etc/procwatch/defense.yml; chown root:procwatch /etc/procwatch/defense.yml; chmod 0640 /etc/procwatch/defense.yml; }

install -o root -g root -m 0644 deploy/linux/procwatch.service /etc/systemd/system/procwatch.service
as_service() { runuser -u procwatch -- env XDG_CONFIG_HOME=/etc XDG_DATA_HOME=/var/lib /usr/local/bin/procwatch "$@"; }
as_service --accept-program
as_service --config-accept /etc/procwatch/defense.yml
systemctl daemon-reload
systemctl enable --now procwatch
systemctl --no-pager status procwatch | head -5
