#!/usr/bin/env bash
# A real sshd on a throwaway port, real keys, then the files are compared on disk.
set -uo pipefail
cd "$(dirname "$0")/.."
./build.sh >/dev/null || { echo "build failed" >&2; exit 1; }
. tools/smoke-lib.sh

sshd_dir="$(mktemp -d)"; port=2222; user="$(whoami)"
cleanup() { [ -f "$sshd_dir/sshd.pid" ] && kill "$(cat "$sshd_dir/sshd.pid")" 2>/dev/null; }
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$sshd_dir/host_key"
ssh-keygen -q -t ed25519 -N '' -f "$sshd_dir/user_key"
cp "$sshd_dir/user_key.pub" "$sshd_dir/authorized_keys"; chmod 600 "$sshd_dir/authorized_keys"
cat >"$sshd_dir/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $sshd_dir/host_key
PidFile $sshd_dir/sshd.pid
AuthorizedKeysFile $sshd_dir/authorized_keys
PasswordAuthentication no
UsePAM no
StrictModes no
EOF
/usr/sbin/sshd -f "$sshd_dir/sshd_config" -E "$sshd_dir/sshd.log" || fail "could not start the throwaway sshd"
ok=""
for _ in $(seq 1 40); do
  if ssh -p $port -i "$sshd_dir/user_key" -o BatchMode=yes -o StrictHostKeyChecking=no \
     -o UserKnownHostsFile=/dev/null "$user@127.0.0.1" true 2>/dev/null; then ok=1; break; fi
  sleep 0.2
done
[ -n "$ok" ] || fail "the throwaway sshd never accepted the key"

root="$sshd_dir/remote"

# --- the workspace: nested paths, a space in a name, a UTF-8 name, and something outside the pattern
ws="$(mktemp -d)"
mkdir -p "$ws/dist/nested" "$ws/secret"
printf 'jar-bytes\n' >"$ws/dist/app.jar"
printf 'deep\n' >"$ws/dist/nested/deep.txt"
printf 'spaced\n' >"$ws/dist/a file with spaces.txt"
printf 'zh\n' >"$ws/dist/报告.txt"
printf 'nope\n' >"$ws/secret/password.txt"
cp "$sshd_dir/user_key" "$ws/deploy_key"; chmod 600 "$ws/deploy_key"

write_input() { printf '%s' "$1" >"$ws/input.json"; }

write_input "{\"host\": \"127.0.0.1\", \"port\": \"$port\", \"user\": \"$user\", \"remoteDir\": \"$root\", \"sourceFiles\": \"dist/**/*\", \"exclude\": \"**/*.log\", \"keyFile\": \"deploy_key\", \"knownHostsFile\": \"known_hosts\"}"
run "$ws" >"$ws/atom.log" 2>&1 || fail "upload failed: $(cat "$ws/output.json") $(tail -3 "$ws/atom.log")"
[ "$(output "$ws" filesUploaded)" = "4" ] || fail "file count: $(cat "$ws/output.json")"

# --- compare what actually landed, byte for byte, with paths intact
cmp -s "$ws/dist/app.jar" "$root/dist/app.jar" || fail "app.jar did not arrive intact"
cmp -s "$ws/dist/nested/deep.txt" "$root/dist/nested/deep.txt" || fail "the nested path was flattened"
cmp -s "$ws/dist/a file with spaces.txt" "$root/dist/a file with spaces.txt" || fail "a name with spaces broke the transfer"
cmp -s "$ws/dist/报告.txt" "$root/dist/报告.txt" || fail "a UTF-8 name broke the transfer"
[ ! -e "$root/secret/password.txt" ] || fail "a file outside the pattern must not be sent"
grep -q "127.0.0.1" "$ws/known_hosts" || fail "knownHostsFile should have recorded the host key"

# the runner's own scratch must never be uploaded, whatever the pattern says
mkdir -p "$ws/.atoms/run1" "$ws/dist/sub"
printf '{"token": "super-secret"}' >"$ws/.atoms/run1/.secrets.json"
printf '{"a": 1}' >"$ws/.atoms/run1/input.json"
printf 'ship\n' >"$ws/dist/sub/keep.txt"
write_input "{\"host\": \"127.0.0.1\", \"port\": \"$port\", \"user\": \"$user\", \"remoteDir\": \"$root/scratch\", \"sourceFiles\": \"**/*\", \"keyFile\": \"deploy_key\", \"knownHostsFile\": \"known_hosts\"}"
run "$ws" >"$ws/atom.log" 2>&1 || fail "upload with an all-files pattern failed: $(cat "$ws/output.json")"
[ ! -e "$root/scratch/.atoms/run1/.secrets.json" ] || fail "the runner's secrets were uploaded"
[ ! -e "$root/scratch/.atoms" ] || fail "the runner's scratch directory was uploaded"
[ -f "$root/scratch/dist/sub/keep.txt" ] || fail "a real file was skipped along with the scratch"

# --- deleteRemote clears what is no longer produced
printf 'stale\n' >"$root/dist/old.txt"
rm -f "$ws/dist/app.jar"
write_input "{\"host\": \"127.0.0.1\", \"port\": \"$port\", \"user\": \"$user\", \"remoteDir\": \"$root\", \"sourceFiles\": \"dist/**/*\", \"keyFile\": \"deploy_key\", \"knownHostsFile\": \"known_hosts\", \"deleteRemote\": \"true\"}"
run "$ws" >"$ws/atom.log" 2>&1 || fail "second upload failed: $(cat "$ws/output.json")"
[ ! -e "$root/dist/old.txt" ] || fail "deleteRemote should have removed the stale file"
[ ! -e "$root/dist/app.jar" ] || fail "a deleted source must not survive remotely"
[ -f "$root/dist/nested/deep.txt" ] || fail "the remaining files must still be there"

# --- a repeat against the same known_hosts is a plain hit
printf 'again\n' >"$ws/dist/app.jar"
write_input "{\"host\": \"127.0.0.1\", \"port\": \"$port\", \"user\": \"$user\", \"remoteDir\": \"$root\", \"sourceFiles\": \"dist/**/*\", \"keyFile\": \"deploy_key\", \"knownHostsFile\": \"known_hosts\"}"
run "$ws" >"$ws/atom.log" 2>&1 || fail "a repeat upload failed: $(cat "$ws/output.json")"
cmp -s "$ws/dist/app.jar" "$root/dist/app.jar" || fail "the repeat upload did not land"

# --- the key as a secret instead of a path
ws2="$(mktemp -d)"; mkdir -p "$ws2/out"; printf 'x\n' >"$ws2/out/x.txt"
cat >"$ws2/input.json" <<EOF
{"host": "127.0.0.1", "port": "$port", "user": "$user", "remoteDir": "$root/secretkey", "sourceFiles": "out/**/*", "knownHostsFile": "known_hosts"}
EOF
cp "$ws/known_hosts" "$ws2/known_hosts"
python3 -c "
import json,sys
json.dump({'key': open(sys.argv[1]).read()}, open(sys.argv[2], 'w'))
" "$sshd_dir/user_key" "$ws2/.secrets.json"
run "$ws2" >"$ws2/atom.log" 2>&1 || fail "upload with a key secret failed: $(cat "$ws2/output.json")"
[ -f "$root/secretkey/out/x.txt" ] || fail "the file sent with a key secret is not there"

# --- failures that must be reported, not swallowed
write_input "{\"host\": \"127.0.0.1\", \"port\": \"1\", \"user\": \"$user\", \"remoteDir\": \"/tmp/x\", \"sourceFiles\": \"dist/**/*\", \"keyFile\": \"deploy_key\"}"
run "$ws" >"$ws/atom.log" 2>&1 && fail "a port with nothing listening must fail"
grep -q "ssh failed" "$ws/output.json" || fail "the ssh failure must be reported: $(cat "$ws/output.json")"

write_input "{\"host\": \"127.0.0.1\", \"port\": \"$port\", \"user\": \"$user\", \"remoteDir\": \"/\", \"sourceFiles\": \"dist/**/*\", \"keyFile\": \"deploy_key\"}"
run "$ws" >"$ws/atom.log" 2>&1 && fail "remoteDir / must be refused"
grep -q "must be a real directory" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"

write_input "{\"host\": \"127.0.0.1\", \"port\": \"$port\", \"user\": \"$user\", \"remoteDir\": \"$root\", \"sourceFiles\": \"nothing-here/**/*.jar\", \"keyFile\": \"deploy_key\"}"
run "$ws" >"$ws/atom.log" 2>&1 && fail "matching nothing must fail"
grep -q "no file matched" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"

# --- a host key that changed under us is refused, and says why.
# The entry has to be a well-formed key: ssh silently ignores a line it cannot parse, and then accept-new
# would happily add the real key, which is not the case being tested.
ssh-keygen -q -t ed25519 -N '' -f "$sshd_dir/other_key"
printf '[127.0.0.1]:%s %s\n' "$port" "$(cat "$sshd_dir/other_key.pub")" >"$ws/known_hosts"
write_input "{\"host\": \"127.0.0.1\", \"port\": \"$port\", \"user\": \"$user\", \"remoteDir\": \"$root\", \"sourceFiles\": \"dist/**/*\", \"keyFile\": \"deploy_key\", \"knownHostsFile\": \"known_hosts\"}"
run "$ws" >"$ws/atom.log" 2>&1 && fail "a bogus known_hosts entry must stop the upload"
grep -q "IDENTIFICATION HAS CHANGED" "$ws/output.json" || fail "the host-key warning must surface: $(cat "$ws/output.json")"

echo "smoke ok: real sshd transfer, nested paths, spaces and UTF-8 names, exclude, deleteRemote, key secret, host-key refusal, failures"
