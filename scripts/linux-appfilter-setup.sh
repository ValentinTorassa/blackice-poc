#!/bin/bash
# Future owner-operated installation. Not authorized until the separate app-filter security gate clears.
set -euo pipefail
[[ $EUID == 0 && $# == 3 ]] || { echo 'Usage: linux-appfilter-setup.sh USER BUNDLE_SHA256 BINARY_SHA256 (as root, after review)' >&2; exit 1; }
owner=$1
bundle_sha=$2
binary_sha=$3
[[ $owner =~ ^[a-z_][a-z0-9_-]*$ && $bundle_sha =~ ^[0-9a-f]{64}$ && $binary_sha =~ ^[0-9a-f]{64}$ ]] || exit 1
src=$(/usr/bin/dirname -- "$(/usr/bin/readlink -f -- "$0")")/../zig-out/blackice-linux-appfilter-install.tar
[[ -f $src ]]
if [[ -d /var/lib/blackice-appfilter && ! -f /etc/blackice-appfilter/owner.json ]]; then
    echo 'Preserved state exists without an installation marker. Archive it as the owner before reinstalling; this script will not adopt or erase it.' >&2
    exit 1
fi
[[ ! -e /run/blackice-appfilter/bpf/state ]] || { echo 'Existing pinned policy: owner teardown is required before an upgrade.' >&2; exit 1; }
if /usr/bin/systemctl is-active --quiet blackice-appfilter.service; then echo 'Stop through authorized app off first.' >&2; exit 1; fi
for program in /usr/sbin/bpftool /usr/sbin/nft /usr/sbin/useradd /usr/sbin/userdel /usr/sbin/groupadd /usr/sbin/groupdel /usr/sbin/getcap /usr/bin/ss; do
    [[ -x $program ]] || { echo "Required reviewed system tool is missing: $program (no packages installed by this script)" >&2; exit 1; }
done
owner_uid=$(/usr/bin/id -u "$owner")
owner_gid=$(/usr/bin/id -g "$owner")
owner_group=$(/usr/bin/id -gn "$owner")
[[ $owner_uid != 0 && $owner_group =~ ^[a-z_][a-z0-9_-]*$ ]]
[[ $(/usr/bin/uname -r) == 6.12.113+deb13-amd64 ]]
[[ $(/usr/sbin/sysctl -n net.ipv4.ip_unprivileged_port_start) -gt 774 ]]
[[ $(/usr/sbin/sysctl -n kernel.yama.ptrace_scope) -ge 1 ]]
[[ $(/usr/sbin/sysctl -n kernel.unprivileged_bpf_disabled) == 2 ]]
PS4='+ blackice setup: '
set -x
# Required read-only preflight record; the owner retains this terminal output for security.
/usr/sbin/bpftool cgroup tree
/usr/sbin/bpftool prog list
/usr/sbin/nft list ruleset
/usr/bin/ls -ld /sys/fs/bpf
/usr/sbin/sysctl fs.protected_hardlinks kernel.unprivileged_bpf_disabled kernel.yama.ptrace_scope net.ipv4.ip_unprivileged_port_start
/usr/bin/ss -ltn 'sport >= :760 and sport <= :774'
/usr/bin/id "$owner"
# Stage and hash the root-owned COPY before extracting it or using any content.
/usr/bin/install -d -o root -g root -m 0700 /usr/local/libexec/blackice-appfilter-stage
trap '/usr/bin/rm -f /usr/local/libexec/blackice-appfilter-stage/bundle.tar /usr/local/libexec/blackice-appfilter-stage/blackice-linux-appfilter /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter.service /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter.socket /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter-bpffs.service /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter-bpffs /usr/local/libexec/blackice-appfilter-stage/org.blackice.appfilter.policy; /usr/bin/rmdir /usr/local/libexec/blackice-appfilter-stage' EXIT
/usr/bin/install -o root -g root -m 0600 "$src" /usr/local/libexec/blackice-appfilter-stage/bundle.tar
[[ $(/usr/bin/sha256sum /usr/local/libexec/blackice-appfilter-stage/bundle.tar | /usr/bin/cut -d' ' -f1) == "$bundle_sha" ]]
/usr/bin/tar --extract --file=/usr/local/libexec/blackice-appfilter-stage/bundle.tar --directory=/usr/local/libexec/blackice-appfilter-stage --no-same-owner --no-same-permissions -- blackice-linux-appfilter blackice-appfilter.service blackice-appfilter.socket blackice-appfilter-bpffs.service blackice-appfilter-bpffs org.blackice.appfilter.policy
[[ $(/usr/bin/sha256sum /usr/local/libexec/blackice-appfilter-stage/blackice-linux-appfilter | /usr/bin/cut -d' ' -f1) == "$binary_sha" ]]
if /usr/bin/getent passwd blackice-appfilter >/dev/null; then
    [[ -f /etc/blackice-appfilter/owner.json ]] || { echo 'Refusing to adopt an existing account.' >&2; exit 1; }
else
    /usr/sbin/groupadd --system blackice-appfilter
    /usr/sbin/useradd --system --gid blackice-appfilter --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin blackice-appfilter
fi
service_uid=$(/usr/bin/id -u blackice-appfilter)
service_gid=$(/usr/bin/id -g blackice-appfilter)
[[ $service_uid != 0 && $service_uid != "$owner_uid" ]]
/usr/bin/install -d -o root -g root -m 0755 /etc/blackice-appfilter
/usr/bin/install -d -o blackice-appfilter -g "$owner_group" -m 2750 /var/lib/blackice-appfilter
/usr/bin/printf '{"version":1,"owner_uid":%s,"owner_gid":%s,"service_uid":%s,"service_gid":%s}\n' "$owner_uid" "$owner_gid" "$service_uid" "$service_gid" > /etc/blackice-appfilter/owner.json
/usr/bin/chown root:root /etc/blackice-appfilter/owner.json
/usr/bin/chmod 0644 /etc/blackice-appfilter/owner.json
/usr/bin/install -o root -g root -m 0755 /usr/local/libexec/blackice-appfilter-stage/blackice-linux-appfilter /usr/local/libexec/blackice-linux-appfilter
[[ -z $(/usr/sbin/getcap /usr/local/libexec/blackice-linux-appfilter) ]]
[[ $(/usr/bin/stat -c '%u:%g:%a' /usr/local/libexec/blackice-linux-appfilter) == 0:0:755 ]]
/usr/bin/install -o root -g root -m 0700 /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter-bpffs /usr/local/libexec/blackice-appfilter-bpffs
/usr/bin/install -o root -g root -m 0644 /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter.service /etc/systemd/system/blackice-appfilter.service
/usr/bin/install -o root -g root -m 0644 /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter-bpffs.service /etc/systemd/system/blackice-appfilter-bpffs.service
/usr/bin/sed -i "s/@OWNER_GROUP@/$owner_group/" /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter.socket
/usr/bin/install -o root -g root -m 0644 /usr/local/libexec/blackice-appfilter-stage/blackice-appfilter.socket /etc/systemd/system/blackice-appfilter.socket
/usr/bin/install -o root -g root -m 0644 /usr/local/libexec/blackice-appfilter-stage/org.blackice.appfilter.policy /usr/share/polkit-1/actions/org.blackice.appfilter.policy
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable --now blackice-appfilter.socket
/usr/bin/sha256sum /usr/local/libexec/blackice-linux-appfilter
/usr/bin/printf 'Installed. Setup did not load BPF. Security must authorize the first on/evidence run separately.\n'
