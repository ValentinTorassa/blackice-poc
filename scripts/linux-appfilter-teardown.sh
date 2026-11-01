#!/bin/bash
set -euo pipefail
[[ $EUID == 0 && $# == 0 ]] || { echo 'Usage: linux-appfilter-teardown.sh (as root, after review)' >&2; exit 1; }
# Check unknown configuration entries before removing anything. Keep the installation marker until the
# runtime cleanup and account deletion have completed, so an interrupted teardown can be resumed.
/usr/bin/python3 -I - <<'PREFLIGHT'
from pathlib import Path
directory = Path('/etc/blackice-appfilter')
if directory.is_symlink():
    raise SystemExit('Refusing symlink: /etc/blackice-appfilter')
if directory.exists():
    unknown = sorted(str(p) for p in directory.iterdir() if p.name != 'owner.json')
    if unknown:
        raise SystemExit('Unexpected configuration entries; retained for owner review: ' + ', '.join(unknown))
PREFLIGHT
# Never delete an account this installer did not record.
if /usr/bin/getent passwd blackice-appfilter >/dev/null; then
    [[ -f /etc/blackice-appfilter/owner.json && ! -L /etc/blackice-appfilter/owner.json ]]
    [[ $(/usr/bin/stat -c '%u:%g:%a' /etc/blackice-appfilter/owner.json) == 0:0:644 ]]
    /usr/bin/python3 -I - <<'CHECK'
import json, pwd
with open('/etc/blackice-appfilter/owner.json') as f:
    config = json.load(f)
account = pwd.getpwnam('blackice-appfilter')
assert config['version'] == 1 and config['service_uid'] == account.pw_uid != 0
CHECK
fi
PS4='+ blackice teardown: '
set -x
if [[ -f /etc/systemd/system/blackice-appfilter.socket ]]; then /usr/bin/systemctl disable --now blackice-appfilter.socket; fi
if [[ -f /etc/systemd/system/blackice-appfilter.service ]]; then /usr/bin/systemctl stop blackice-appfilter.service; fi
# Exact pins only. Missing pins plus attached programs fail and require root/security diagnosis.
if [[ -x /usr/local/libexec/blackice-linux-appfilter ]]; then
    /usr/local/libexec/blackice-linux-appfilter --teardown
elif [[ -e /run/blackice-appfilter/bpf/state ]]; then
    echo 'Pins exist but the reviewed teardown binary is missing; refusing removal.' >&2
    exit 1
fi
if [[ -f /etc/systemd/system/blackice-appfilter-bpffs.service ]]; then /usr/bin/systemctl stop blackice-appfilter-bpffs.service; fi
if /usr/bin/mountpoint -q /run/blackice-appfilter/bpf; then /usr/bin/umount /run/blackice-appfilter/bpf; fi
/usr/bin/rm -f /usr/local/libexec/blackice-linux-appfilter /usr/local/libexec/blackice-appfilter-bpffs /etc/systemd/system/blackice-appfilter.service /etc/systemd/system/blackice-appfilter.socket /etc/systemd/system/blackice-appfilter-bpffs.service /usr/share/polkit-1/actions/org.blackice.appfilter.policy
/usr/bin/systemctl daemon-reload
for directory in /run/blackice-appfilter/bpf /run/blackice-appfilter; do
    if [[ -d $directory ]]; then /usr/bin/rmdir -- "$directory"; fi
done
# Preserve receipts and policies as root-owned evidence; never recursively delete user data.
if [[ -d /var/lib/blackice-appfilter ]]; then
    /usr/bin/chown root:root /var/lib/blackice-appfilter
    /usr/bin/chmod 00700 /var/lib/blackice-appfilter
    /usr/bin/python3 -I - <<'ARCHIVE'
import os
fd = os.open('/var/lib/blackice-appfilter', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    for name in os.listdir(fd):
        # No recursion and no symlink following. Retain every entry, including unexpected evidence.
        os.chown(name, 0, 0, dir_fd=fd, follow_symlinks=False)
finally:
    os.close(fd)
ARCHIVE
fi
if /usr/bin/getent passwd blackice-appfilter >/dev/null; then /usr/sbin/userdel blackice-appfilter; fi
if /usr/bin/getent group blackice-appfilter >/dev/null; then /usr/sbin/groupdel blackice-appfilter; fi
/usr/bin/rm -f /etc/blackice-appfilter/owner.json
if [[ -d /etc/blackice-appfilter ]]; then /usr/bin/rmdir /etc/blackice-appfilter; fi

# Remove only named staging leftovers, including an installer killed before its EXIT trap.
/usr/bin/rm -f /usr/local/libexec/blackice-appfilter-stage/bundle.tar /usr/local/libexec/blackice-appfilter-stage/blackice-linux-appfilter /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter.service /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter.socket /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter-bpffs.service /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter-bpffs /usr/local/libexec/blackice-appfilter-stage/org.blackice.appfilter.policy
if [[ -d /usr/local/libexec/blackice-appfilter-stage ]]; then /usr/bin/rmdir /usr/local/libexec/blackice-appfilter-stage; fi
