#!/bin/bash
# Security acceptance tests T-01 to T-13 from docs/security.md, against a
# real installed service. Needs root and systemd: a throwaway machine only.
# Usage: tests/acceptance.sh path/to/release/procwatch
set -u
binary=${1:?usage: acceptance.sh path/to/procwatch}
run=$(mktemp -d)
chmod 755 "$run"
key=$run/key
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$key"
chmod 600 "$key"
pass=0
fail=0
result() { # id, ok?, what
    if [ "$2" = 0 ]; then echo "PASS $1: $3"; pass=$((pass + 1)); else echo "FAIL $1: $3"; fail=$((fail + 1)); fi
}
wait_for() { # seconds, command
    local until=$((SECONDS + $1)); shift
    while [ $SECONDS -lt $until ]; do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
    return 1
}
pid() { systemctl show -p MainPID --value procwatch; }
heard() { grep -q "$1" "$run/receiver.log"; }
as_service() { runuser -u procwatch -- env XDG_CONFIG_HOME=/etc XDG_DATA_HOME=/var/lib "$@"; }

deploy/linux/install.sh "$binary" >/dev/null
systemctl stop procwatch
cp "$key" /etc/procwatch/heartbeat.key; chown procwatch /etc/procwatch/heartbeat.key; chmod 600 /etc/procwatch/heartbeat.key
cat >/etc/procwatch/defense.yml <<YML
version: 1
heartbeat: { url: "http://127.0.0.1:19190/beat", key_file: /etc/procwatch/heartbeat.key, interval_seconds: 2 }
sync: { url: "http://127.0.0.1:19190/logs" }
YML
as_service /usr/local/bin/procwatch --config-accept /etc/procwatch/defense.yml >/dev/null
mkdir -p /etc/systemd/system/procwatch.service.d
printf '[Service]\nWatchdogSec=12\n[Unit]\nStartLimitBurst=100\n' >/etc/systemd/system/procwatch.service.d/test.conf
systemctl daemon-reload

# A copy: the running receiver mustn't hold the file T-07 replaces.
cp /usr/local/bin/procwatch "$run/receiver"
XDG_DATA_HOME=$run/rx XDG_CONFIG_HOME=$run/rx "$run/receiver" --heartbeat-receiver 127.0.0.1:19190 --key "$key" --period 2 --store "$run/store" >"$run/receiver.log" 2>&1 &
receiver=$!
trap 'kill $receiver 2>/dev/null; systemctl stop procwatch; rm -rf /etc/systemd/system/procwatch.service.d; systemctl daemon-reload' EXIT
systemctl start procwatch
wait_for 30 heard '"first contact"' || echo "no first contact: $(journalctl -u procwatch -n 20 --no-pager)"

before=$(pid)
runuser -u nobody -- kill -9 "$before" 2>/dev/null
[ $? -ne 0 ] && [ "$(pid)" = "$before" ]; result T-01 $? "an ordinary user can't kill the service"

kill -9 "$before"
wait_for 15 sh -c "[ \"\$(systemctl show -p MainPID --value procwatch)\" != 0 ] && [ \"\$(systemctl show -p MainPID --value procwatch)\" != $before ]"; result T-02 $? "killed by root, it is back within seconds"
wait_for 15 heard '"restarted"'; result T-02b $? "the receiver saw the restart"

before=$(pid); sleep 3
kill -TERM "$before"
wait_for 15 heard 'signal 15'; result T-03 $? "SIGTERM leaves last words"
wait_for 15 sh -c "[ \"\$(systemctl show -p MainPID --value procwatch)\" != 0 ] && [ \"\$(systemctl show -p MainPID --value procwatch)\" != $before ]"; result T-03b $? "and the service restarts"

sleep 3; before=$(pid)
kill -STOP "$before"
wait_for 40 sh -c "[ \"\$(systemctl show -p MainPID --value procwatch)\" != $before ]"; result T-04 $? "a stopped process is replaced by the watchdog"

# T-05: a deadlocked main loop feeds nothing, which is the same to systemd;
# the rule that only the loop feeds it is tested in cli::service.
result T-05 0 "covered by T-04 and the unit test the_watchdog_needs_real_work"

sleep 3
cp /etc/procwatch/defense.yml "$run/good.yml"
echo "quiet_seconds: 1" >>/etc/procwatch/defense.yml
systemctl restart procwatch
wait_for 20 grep -q 'configuration refused' /var/lib/procwatch/events/audit.jsonl; result T-06 $? "a tampered configuration is refused and recorded"
cp "$run/good.yml" /etc/procwatch/defense.yml

systemctl stop procwatch
cp /usr/local/bin/procwatch "$run/procwatch.good"
cp "$run/procwatch.good" "$run/tampered"
printf 'x' >>"$run/tampered"
install -m 0755 "$run/tampered" /usr/local/bin/procwatch
systemctl start procwatch
wait_for 20 heard 'program changed'; result T-07 $? "a replaced program refuses to run, and the receiver sees the hash change"
systemctl stop procwatch
install -m 0755 "$run/procwatch.good" /usr/local/bin/procwatch
as_service /usr/local/bin/procwatch --accept-program >/dev/null
systemctl reset-failed procwatch; systemctl start procwatch
sleep 4

log=/var/lib/procwatch/agent.jsonl
systemctl stop procwatch
chattr -a "$log" 2>/dev/null
cp "$log" "$run/log.good"
sed -i '2s/"event":"{/"event":"{ /' "$log"
as_service /usr/local/bin/procwatch --agent-verify "$log" 2>&1 | grep -q 'line 2'; result T-08 $? "an edited line is located exactly"
cp "$run/log.good" "$log"; chown procwatch "$log"

python3 - "$log" <<'PY'
import hashlib, json, sys
path = sys.argv[1]
prev = "0" * 64
out = []
for line in open(path):
    e = json.loads(line)
    e["event"] = e["event"].replace("agent", "AGENT")
    e["prev"] = prev
    h = hashlib.sha256()
    for part in (prev, str(e["seq"]), e["time"], e["event"]):
        h.update(part.encode()); h.update(b"\0")
    e["hash"] = prev = h.hexdigest()
    out.append(json.dumps(e, separators=(",", ":")))
open(path, "w").write("\n".join(out) + "\n")
PY
as_service /usr/local/bin/procwatch --agent-verify "$log" >/dev/null; verified=$?
systemctl start procwatch
wait_for 15 heard 'log rewritten'; rewritten=$?
[ $verified = 0 ] && [ $rewritten = 0 ]; result T-09 $? "a rebuilt chain passes locally but disagrees with the anchors"

kill $receiver; wait $receiver 2>/dev/null
sleep 6
XDG_DATA_HOME=$run/rx XDG_CONFIG_HOME=$run/rx "$run/receiver" --heartbeat-receiver 127.0.0.1:19190 --key "$key" --period 2 --store "$run/store" >>"$run/receiver.log" 2>&1 &
receiver=$!
stored=$(cat "$run"/store/*.jsonl 2>/dev/null | wc -l)
wait_for 30 sh -c "[ \$(cat $run/store/*.jsonl 2>/dev/null | wc -l) -gt $stored ]"; result T-10 $? "log lines held during an outage arrive afterwards"
systemctl stop procwatch
wait_for 15 heard 'lost contact'; result T-10b $? "silence is reported"
heard 'stop requested\|signal 15'; result T-11 $? "systemctl stop leaves last words"
systemctl start procwatch; sleep 5

before=$(pid)
python3 - <<'PY'
import socket
for payload in (b"\0" * 5000 + b"\n", b"\xff\xfe garbage\n", b"health" * 1000 + b"\n", b""):
    s = socket.socket(socket.AF_UNIX)
    s.connect("/var/lib/procwatch/events/query.sock")
    s.sendall(payload)
    s.close()
PY
sleep 2
[ "$(pid)" = "$before" ]; result T-12 $? "malformed input doesn't hurt the service"

as_service /usr/local/bin/procwatch --maintenance 1 "test" >/dev/null
sleep 3
marks=$(grep -c 'lost contact' "$run/receiver.log")
systemctl stop procwatch
sleep 10
[ "$(grep -c 'lost contact' "$run/receiver.log")" = "$marks" ]; quiet=$?
wait_for 70 sh -c "[ \$(grep -c 'lost contact' $run/receiver.log) -gt $marks ]"; ended=$?
[ $quiet = 0 ] && [ $ended = 0 ]; result T-13 $? "silence is excused during maintenance, and protection returns by itself"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
