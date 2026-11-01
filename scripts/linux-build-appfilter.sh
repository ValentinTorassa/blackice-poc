#!/bin/bash
set -euo pipefail
[[ $EUID -ne 0 ]] || { echo 'Build as the normal user; do not compile as root.' >&2; exit 1; }
cd -- "$(/usr/bin/dirname -- "$(/usr/bin/readlink -f -- "$0")")/.."
zig=${ZIG:-"$HOME/.local/bin/zig"}
[[ $zig == /* && -x $zig ]] || { echo 'ZIG must name an absolute executable path.' >&2; exit 1; }
"$zig" build linux-appfilter
/usr/bin/python3 -I - <<'PY'
from pathlib import Path
import hashlib, tarfile
root = Path.cwd()
files = {'blackice-linux-appfilter': root / 'zig-out/bin/blackice-linux-appfilter'}
for path in sorted((root / 'packaging/linux-appfilter').iterdir()):
    if path.is_file():
        files[path.name] = path
out = root / 'zig-out/blackice-linux-appfilter-install.tar'
with tarfile.open(out, 'w', format=tarfile.USTAR_FORMAT) as tar:
    for name, path in sorted(files.items()):
        data = path.read_bytes()
        info = tarfile.TarInfo(name)
        info.size, info.mtime, info.uid, info.gid = len(data), 0, 0, 0
        info.mode = 0o755 if name in ('blackice-linux-appfilter', 'blackice-appfilter-bpffs') else 0o644
        import io
        tar.addfile(info, io.BytesIO(data))
for path in (files['blackice-linux-appfilter'], out):
    print(hashlib.sha256(path.read_bytes()).hexdigest(), path)
print('Build only. No host installation or BPF operation performed.')
PY
