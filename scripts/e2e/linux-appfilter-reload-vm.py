#!/usr/bin/env python3
"""VM-only acceptance driver for three real policy reloads.

Run inside VM3 as its unprivileged owner in a tty. Requires four policy fixtures
with generation 1..4, a reviewed installed CLI/service, bpftool read access via
sudo -n, a root-owned listed copy of env, and a controlled off-VM TCP receiver.
No setup/install/teardown, polkit bypass, password handling or BPF mutation here.
"""
import argparse
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

PIN = '/run/blackice-appfilter/bpf'
STATE = Path('/var/lib/blackice-appfilter')
PROBE = r'''
import errno,json,os,signal,socket,sys,time
host,port,token=sys.argv[1:]
state={'stop':False}
signal.signal(signal.SIGTERM,lambda *_:state.update(stop=True))
print(json.dumps({'event':'probe_started','pid':os.getpid()}),flush=True)
while not state['stop']:
 start=time.monotonic_ns()
 code=None
 try:
  with socket.create_connection((host,int(port)),timeout=0.25) as s:
   s.sendall((token+'\n').encode())
 except OSError as e: code=e.errno
 print(json.dumps({'event':'direct_attempt','pid':os.getpid(),'monotonic_ns':start,'errno':code}),flush=True)
 time.sleep(0.05)
'''


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def command(args, timeout=20):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    require(p.returncode == 0, f'{args[0]} failed ({p.returncode}): {p.stderr[:500]}')
    return p.stdout


def decode_bytes(value):
    require(isinstance(value, list) and all(isinstance(x, str) and re.fullmatch('(?:0x)?[a-fA-F0-9]{2}', x) for x in value),
            'unexpected bpftool byte format')
    return bytes(int(x, 16) for x in value)


def lookup(name, key=0):
    encoded = [f'{b:02x}' for b in struct.pack('<I', key)]
    return json.loads(command(['sudo', '-n', 'bpftool', '-j', 'map', 'lookup', 'pinned', f'{PIN}/{name}', 'key', 'hex', *encoded]))


def state_hash(record):
    data = decode_bytes(record['value'])
    require(len(data) >= 48, 'unexpected pinned state ABI')
    return data[16:48].hex()


def tag(pid):
    return int.from_bytes(decode_bytes(lookup('tags', pid)['value']), 'little')


def snapshot(output, generation, pid):
    state = lookup('state')
    files = json.loads(command(['sudo', '-n', 'bpftool', '-j', 'map', 'dump', 'pinned', PIN + '/files']))
    ports = json.loads(command(['sudo', '-n', 'bpftool', '-j', 'map', 'dump', 'pinned', PIN + '/ports']))
    programs = json.loads(command(['sudo', '-n', 'bpftool', '-j', 'cgroup', 'show', '/sys/fs/cgroup/user.slice']))
    root_programs = json.loads(command(['sudo', '-n', 'bpftool', '-j', 'cgroup', 'show', '/sys/fs/cgroup']))
    raw = decode_bytes(state['value'])
    require(len(raw) == 56 and int.from_bytes(raw[12:16], 'little') == 2, 'generation ABI 2 required')
    require(int.from_bytes(raw[48:52], 'little') == generation and int.from_bytes(raw[52:56], 'little') == 0,
            'kernel generation mismatch or admission still fenced')
    stable_ports = {}
    for row in ports:
        key, value = decode_bytes(row['key']), decode_bytes(row['value'])
        require(len(key) == 8 and len(value) == 12, 'unexpected ports map ABI')
        if int.from_bytes(key[4:8], 'little') == generation:
            stable_ports[str(int.from_bytes(key[:4], 'little'))] = value[:8].hex()
    require(stable_ports, 'no port bindings for active generation')
    data = {'gen': generation, 'state': state, 'files': files, 'ports': ports, 'stable_ports': stable_ports,
            'tag': tag(pid), 'programs': programs, 'root_programs': root_programs}
    (output / f'maps-gen-{generation}.json').write_text(json.dumps(data, indent=2) + '\n')
    return data


def receipts(sizes):
    records = []
    for path in sorted(STATE.glob('receipt-*.jsonl')):
        with path.open('rb') as stream:
            stream.seek(sizes.get(str(path), 0))
            for line in stream:
                require(line.endswith(b'\n'), 'partial receipt line')
                records.append(json.loads(line))
    return records


def validate_activations(records, hashes):
    require(not any(r.get('dropped', 0) or r.get('event') == 'receipt_loss' for r in records), 'receipt loss invalidates the run')
    for generation in range(2, 5):
        candidates = [r for r in records if r.get('event') == 'policy_activated' and r.get('gen') == generation]
        require(len(candidates) == 1, f'expected one activation for generation {generation}')
        row = candidates[0]
        old, new = hashes[generation - 2:generation]
        detail = row.get('detail', '')
        require(row.get('old_policy') == old or f'old_policy={old}' in detail, 'activation omits old policy hash')
        require(row.get('new_policy') == new or f'new_policy={new}' in detail, 'activation omits new policy hash')
        require(row.get('policy') == new, 'activation policy does not match the new configuration')
    for row in records:
        if row.get('event') in ('kernel_drop', 'connect', 'http'):
            require(row.get('gen') in (1, 2, 3, 4), 'decision lacks a valid generation')
    require(any(r.get('event') == 'kernel_drop' for r in records), 'no kernel refusal receipts recorded')


def validate_windows(records, windows, pid, attempts):
    matched = []
    for row in records:
        if row.get('event') != 'kernel_drop': continue
        detail = row.get('detail', '')
        process = re.search(r'\btgid=(\d+)\b', detail)
        instant = re.search(r'\bkernel_monotonic_ns=(\d+)\b', detail)
        if not process or int(process[1]) != pid: continue
        require(instant is not None, 'kernel receipt lacks event-time timestamp')
        matched.append((int(instant[1]), row['gen']))
    require(len(matched) == attempts, 'kernel receipt count differs from completed direct attempts')
    for generation, start, end in windows:
        inside = [gen for instant, gen in matched if start <= instant < end]
        require(inside, f'no steady-generation observations for {generation}')
        require(all(gen == generation for gen in inside), 'kernel receipt labeled with a different generation')


def validate_web(records, attempts, pid, app_id, configs, launcher):
    flows = [r for r in records if r.get('event') == 'connect' and r.get('app_id') == app_id]
    kernels = [r for r in records if r.get('event') == 'kernel_drop' and re.search(rf'\btgid={pid}\b', r.get('detail', ''))]
    require(len(flows) + len(kernels) == len(attempts), 'HTTPS attempts do not have exactly one initial decision each')
    policies = [next(a['policy'] for a in cfg['applications'] if a['executable'] == launcher) for cfg in configs]
    digests = [hashlib.sha256(json.dumps(pol, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest() for pol in policies]
    for row in flows:
        gen = row.get('gen')
        require(gen in (1, 2, 3, 4) and row['policy'] == digests[gen - 1], 'HTTPS receipt mixes policy and generation')
        host = row.get('host')
        if host is None:
            require(row.get('verdict') == 'deny' and row.get('reason') == 'policy_change_in_progress', 'unexplained nameless HTTPS decision')
            continue
        require(host in ('example.com', 'github.com'), 'unexpected HTTPS host')
        # A ClientHello that arrives while a change is published is refused by name, whatever either policy says.
        if row.get('reason') == 'policy_change_in_progress':
            require(row.get('verdict') == 'deny', 'policy_change_in_progress must refuse')
            continue
        network = policies[gen - 1]['network']
        require(network['mode'] == 'allowlist', 'web-loop fixtures must use exact-name allowlists')
        allowed = host in network['allow']
        require(row.get('verdict') == ('allow' if allowed else 'deny'), 'HTTPS verdict contradicts its recorded generation')
        if not allowed:
            require(row.get('reason') == 'no_matching_rule', 'refused host has an unexpected reason')
    for gen in range(1, 5):
        for host in ('example.com', 'github.com'):
            require(any(r.get('gen') == gen and r.get('host') == host for r in flows), f'no HTTPS observation for gen{gen} {host}')
    successes = sum(r.get('http_status') is not None for r in attempts)
    allowed = sum(r.get('verdict') == 'allow' for r in flows)
    narrowed = sum(r.get('event') == 'policy_changed' and r.get('reason') == 'policy_narrowed' and r.get('app_id') == app_id for r in records)
    require(successes <= allowed and allowed - successes <= narrowed, 'allowed HTTPS failures lack a narrowing reset explanation')
    return {'attempts': len(attempts), 'proxy_decisions': len(flows), 'kernel_decisions': len(kernels),
            'http_responses': successes, 'narrowing_resets': narrowed}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cli', required=True, type=Path)
    p.add_argument('--cli-sha256', required=True)
    p.add_argument('--launcher', required=True, type=Path)
    p.add_argument('--policy', action='append', required=True, type=Path, help='supply four times, generations 1..4')
    p.add_argument('--receiver', required=True, help='controlled off-VM IPv4 receiver')
    p.add_argument('--receiver-port', required=True, type=int)
    p.add_argument('--token', required=True, help='unique public test marker, never a credential')
    p.add_argument('--output', required=True, type=Path, help='new directory')
    p.add_argument('--web-loop', action='store_true', help='also send 20 Hz HTTPS requests alternating example.com/github.com')
    args = p.parse_args()
    require(os.geteuid() != 0, 'run as the unprivileged configured VM owner')
    require(command(['systemd-detect-virt']).strip() in ('kvm', 'qemu'), 'disposable KVM/QEMU VM required')
    require(re.fullmatch('[0-9a-f]{64}', args.cli_sha256) is not None, 'invalid expected CLI hash')
    require(hashlib.sha256(args.cli.read_bytes()).hexdigest() == args.cli_sha256, 'CLI hash mismatch')
    help_result = subprocess.run([str(args.cli), 'app', 'reload', '--help'], capture_output=True, text=True)
    if help_result.returncode != 0 or 'availability=experimental_vm_only' not in help_result.stdout.splitlines():
        print('NOT RUN: candidate CLI does not advertise experimental VM reload support; no arm/reload/off attempted.')
        return 77
    require(os.isatty(0), 'owner tty needed for real polkit authentication; no auth bypass is installed')
    require(shutil.which('bpftool') is not None or Path('/usr/sbin/bpftool').is_file(), 'bpftool required')
    require(len(args.policy) == 4, 'provide generations 1, 2, 3 and 4')
    receiver = ipaddress.IPv4Address(args.receiver)
    require(not receiver.is_loopback and not receiver.is_unspecified and not receiver.is_multicast, 'off-VM unicast receiver required')
    require(1024 <= args.receiver_port <= 65535, 'use a dedicated unprivileged receiver port')
    require(re.fullmatch('[A-Za-z0-9_-]{1,80}', args.token) is not None, 'invalid public test token')
    configs = [json.loads(path.read_bytes()) for path in args.policy]
    hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in args.policy]
    for gen, cfg in enumerate(configs, 1):
        require(cfg.get('generation') == gen, 'wrong fixture generation')
        require(str(args.launcher) in [a['executable'] for a in cfg['applications']], 'launcher must remain listed in all four fixtures')
        require({a['executable'] for a in cfg['applications']} == {a['executable'] for a in configs[0]['applications']},
                'this script covers fixed membership; add/remove race tests are a separate required gate')
    before = command([str(args.cli), 'app', 'status'])
    require(before.strip().startswith('OK off'), 'refuse to take over an already armed instance')
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    sizes = {str(path): path.stat().st_size for path in STATE.glob('receipt-*.jsonl')}
    # Off-VM receiver must log this untagged control before it checks for forbidden payloads.
    import socket
    with socket.create_connection((str(receiver), args.receiver_port), timeout=3) as control:
        control.sendall((args.token + ':outside-before\n').encode())
    probe = None
    web = None
    web_file = None
    armed = False
    report = {'result': 'NOT RUN', 'cli_sha256': args.cli_sha256, 'configuration_sha256': hashes}
    try:
        # Inherit the tty for polkit; never capture or supply a password.
        def action(verb, policy):
            result = subprocess.run([str(args.cli), 'app', verb, '--policy', str(policy)], timeout=130)
            require(result.returncode == 0, f'{verb} failed; see terminal/polkit output')
        action('on', args.policy[0])
        armed = True
        with (args.output / 'direct-probe.jsonl').open('w') as stream:
            probe = subprocess.Popen([str(args.launcher), sys.executable, '-u', '-c', PROBE,
                                      str(receiver), str(args.receiver_port), args.token + ':listed'], stdout=stream, stderr=subprocess.STDOUT)
            time.sleep(1)
            first = snapshot(args.output, 1, probe.pid)
            require(first['tag'] != 0, 'probe is untagged')
            require(state_hash(first['state']) == hashes[0], 'initial kernel policy hash mismatch')
            if args.web_loop:
                web_file = (args.output / 'web-probe.jsonl').open('w')
                web = subprocess.Popen([str(args.launcher), sys.executable, '-u', '-B',
                                        str(Path(__file__).with_name('linux-appfilter-reload-web-probe.py'))], stdout=web_file, stderr=subprocess.STDOUT)
                time.sleep(0.3)
                require(web.poll() is None and tag(web.pid) == first['tag'], 'web probe is not live with the expected tag')
            windows = []
            window_start = time.monotonic_ns()
            time.sleep(0.5)
            for generation in range(2, 5):
                windows.append((generation - 1, window_start, time.monotonic_ns()))
                action('reload', args.policy[generation - 1])
                window_start = time.monotonic_ns()
                time.sleep(1)
                require(probe.poll() is None, 'listed process was restarted or died')
                current = snapshot(args.output, generation, probe.pid)
                require(current['tag'] == first['tag'], 'reload changed the process tag')
                require(current['stable_ports'] == first['stable_ports'], 'stable app listener ports changed')
                require(current['programs'] == first['programs'] and current['root_programs'] == first['root_programs'], 'BPF attachments changed')
                require(state_hash(current['state']) == hashes[generation - 1], 'kernel state does not name the committed policy')
            windows.append((4, window_start, time.monotonic_ns()))
        probe_pid = probe.pid
        probe.terminate()
        probe.wait(timeout=5)
        probe = None
        web_pid = None
        if web is not None:
            web_pid = web.pid
            web.terminate()
            require(web.wait(timeout=15) == 0, 'web probe failed')
            web = None
            web_file.close()
            web_file = None
        attempts = [json.loads(line) for line in (args.output / 'direct-probe.jsonl').read_text().splitlines()]
        attempts = [r for r in attempts if r.get('event') == 'direct_attempt']
        require(len(attempts) >= 40, 'too few continuous kernel probes')
        require(all(r['errno'] in (errno.EPERM, errno.EACCES) for r in attempts), 'observed unfiltered or ambiguous direct-connect attempt')
        time.sleep(0.3)  # Allow the bounded service drain to append the final kernel records.
        rows = receipts(sizes)
        (args.output / 'receipts.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
        validate_activations(rows, hashes)
        validate_windows(rows, windows, probe_pid, len(attempts))
        if web_pid is not None:
            web_rows = [json.loads(line) for line in (args.output / 'web-probe.jsonl').read_text().splitlines()]
            require(web_rows[-1].get('event') == 'web_finished', 'web probe did not finish its bounded requests')
            require(web_rows[-1]['backpressure_skipped'] == 0, 'web loop could not sustain the scheduled 20 Hz rate')
            web_attempts = [r for r in web_rows if r.get('event') == 'web_attempt']
            report['web'] = validate_web(rows, web_attempts, web_pid, first['tag'], configs, str(args.launcher))
        with socket.create_connection((str(receiver), args.receiver_port), timeout=3) as control:
            control.sendall((args.token + ':outside-after\n').encode())
        report.update(result='LOCAL CHECKS PASS; RECEIVER CORROBORATION REQUIRED', attempts=len(attempts),
                      receiver_rule=f'both {args.token}:outside-* controls and ZERO {args.token}:listed lines')
    except Exception as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        if web is not None:
            web.terminate()
            try: web.wait(timeout=15)
            except subprocess.TimeoutExpired: web.kill(); web.wait()
        if web_file is not None:
            web_file.close()
        if probe is not None:
            probe.terminate()
            try: probe.wait(timeout=5)
            except subprocess.TimeoutExpired: probe.kill(); probe.wait()
        cleanup_error = None
        if armed:
            # Refusal leaves pins for operator recovery and must reach result.json.
            try:
                off = subprocess.run([str(args.cli), 'app', 'off'], timeout=130)
                require(off.returncode == 0, 'authorized off failed; pins may remain, do not claim cleanup')
                report['cleanup'] = 'authorized off completed'
            except (RuntimeError, OSError, subprocess.SubprocessError) as error:
                cleanup_error = str(error)
                report.update(result='FAIL', cleanup_error=cleanup_error)
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        if cleanup_error:
            raise RuntimeError(cleanup_error)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        raise SystemExit(1)
