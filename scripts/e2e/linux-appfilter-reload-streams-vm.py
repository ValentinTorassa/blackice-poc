#!/usr/bin/env python3
"""VM3 real slow-HTTPS widening/narrowing evidence; fresh owner polkit required.

Uses two public drip endpoints with 80-byte, eight-second bodies. HTTP errors or
stalled controls fail the run instead of being counted as enforcement evidence.
The configured root-owned env copy launches the same two live TLS/TCP streams.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('reload_vm', Path(__file__).with_name('linux-appfilter-reload-vm.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
AGENT = r'''
import concurrent.futures,http.client,json,signal,socket,ssl,threading,time
stop=threading.Event(); lock=threading.Lock(); ctx=ssl.create_default_context()
signal.signal(signal.SIGTERM,lambda *_:stop.set())
def emit(**row):
 row.update(wall_ns=time.time_ns(),monotonic_ns=time.monotonic_ns())
 with lock: print(json.dumps(row),flush=True)
def stream(host):
 total=0; error=None
 try:
  with socket.create_connection(('1.1.1.1',443),4) as raw:
   with ctx.wrap_socket(raw,server_hostname=host,suppress_ragged_eofs=False) as tls:
    tls.settimeout(4)
    tls.sendall(('GET /drip?duration=8&numbytes=80&code=200 HTTP/1.1\r\nHost: '+host+'\r\nUser-Agent: blackice-reload-vm-test/0.1\r\nConnection: close\r\n\r\n').encode())
    response=http.client.HTTPResponse(tls); response.begin()
    if response.status!=200: raise ValueError('HTTP status '+str(response.status)+': '+response.read(1024).decode('utf-8','replace'))
    emit(event='stream_started',host=host,status=response.status)
    while not stop.is_set():
     data=response.read(1)
     if not data: break
     total+=len(data); emit(event='stream_progress',host=host,total=total)
 except Exception as exc: error=type(exc).__name__+': '+str(exc)
 emit(event='stream_ended',host=host,total=total,error=error,cancelled=stop.is_set())
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 jobs=[pool.submit(stream,h) for h in ('httpbin.org','httpbingo.org')]
 for job in jobs: job.result()
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cli', type=Path, required=True)
    p.add_argument('--cli-sha256', required=True)
    p.add_argument('--service-sha256', required=True)
    p.add_argument('--launcher', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--websocket', action='store_true', help='two real TLS WebSocket echo streams instead of HTTPS drips')
    a = p.parse_args()
    vm.require(os.geteuid() == 1000 and os.isatty(0) and socket.gethostname() == 'test3-vm', 'VM3 owner tty required')
    vm.require(vm.command(['systemd-detect-virt']).strip() in ('qemu', 'kvm'), 'QEMU/KVM only')
    vm.require(hashlib.sha256(a.cli.read_bytes()).hexdigest() == a.cli_sha256, 'CLI hash mismatch')
    vm.require(hashlib.sha256(Path('/usr/local/libexec/blackice-linux-appfilter').read_bytes()).hexdigest() == a.service_sha256, 'service hash mismatch')
    vm.require(vm.command([str(a.cli), 'app', 'status']).startswith('OK off'), 'service must start off')
    a.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    removed = 'httpbingo.org'
    kept = 'ws.postman-echo.com' if a.websocket else 'httpbin.org'
    hosts_in_test = (kept, removed)
    paths = []
    for gen, hosts in enumerate([[kept, removed], [kept, removed, 'example.com'], [kept, 'example.com']], 1):
        cfg = {'version': 'blackice.apps/v0', 'generation': gen, 'applications': [{'executable': a.launcher,
               'policy': {'version': 'blackice.policy/v0', 'network': {'mode': 'allowlist', 'allow': hosts}}}]}
        path = a.output / f'policy-{gen}.json'
        path.write_text(json.dumps(cfg, indent=2) + '\n'); paths.append(path)
    sizes = {str(x): x.stat().st_size for x in vm.STATE.glob('receipt-*.jsonl')}
    report = {'result': 'FAIL', 'service_sha256': a.service_sha256,
              'transport': 'websocket_tls' if a.websocket else 'https_drip'}
    armed = False
    agent = None
    stream_file = None

    def action(verb, policy=None):
        cmd = [str(a.cli), 'app', verb]
        if policy: cmd += ['--policy', str(policy)]
        vm.require(subprocess.run(cmd, timeout=35).returncode == 0, f'{verb} failed')

    def progress():
        data = (a.output / 'streams.jsonl').read_bytes()
        return [json.loads(line) for line in data.splitlines(keepends=True) if line.endswith(b'\n')]

    def count(rows, host):
        return max([r.get('total', 0) for r in rows if r.get('host') == host] or [0])

    def ended(rows, host):
        return [r for r in rows if r.get('event') == 'stream_ended' and r.get('host') == host]

    try:
        action('on', paths[0]); armed = True
        stream_file = (a.output / 'streams.jsonl').open('w')
        agent_args = ([str(Path(__file__).with_name('linux-appfilter-websocket-client.py'))] if a.websocket else ['-c', AGENT])
        agent = subprocess.Popen([a.launcher, sys.executable, '-u', *agent_args], stdout=stream_file, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 15
        while True:
            rows = progress()
            vm.require(not any(ended(rows, host) for host in hosts_in_test), 'a stream endpoint failed before the policy change')
            if all(count(rows, host) >= 3 for host in hosts_in_test): break
            vm.require(time.monotonic() < deadline, 'both real stream controls did not start')
            time.sleep(0.05)
        vm.require(vm.tag(agent.pid) == 1, 'stream agent not tagged')
        before = {host: count(rows, host) for host in hosts_in_test}
        action('reload', paths[1])
        time.sleep(1)
        rows = progress()
        for host in before:
            vm.require(not ended(rows, host) and count(rows, host) >= before[host] + 3, 'widening interrupted a permitted stream')
        vm.require(not any(r.get('reason') == 'policy_narrowed' for r in vm.receipts(sizes)), 'widening emitted a narrowing reset')
        report['widening'] = 'both streams remained live and transferred more body bytes'
        action('reload', paths[2])
        deadline = time.monotonic() + 3
        while True:
            rows = progress()
            if ended(rows, removed): break
            vm.require(time.monotonic() < deadline, 'narrowed stream did not stop')
            time.sleep(0.02)
        cut = ended(rows, removed)
        vm.require(len(cut) == 1 and not cut[0]['cancelled'] and
                   (not cut[0]['deadline_reached'] if a.websocket else cut[0]['total'] < 80),
                   'narrowed stream completed or was stopped by the harness')
        keep_before = count(rows, kept)
        time.sleep(1)
        rows = progress()
        vm.require(not ended(rows, kept) and count(rows, kept) >= keep_before + 3, 'still-allowed stream stopped at narrowing')
        records = vm.receipts(sizes)
        resets = [r for r in records if r.get('reason') == 'policy_narrowed']
        vm.require(len(resets) == 1 and resets[0].get('event') == 'policy_changed' and
                   resets[0].get('host') == removed and resets[0].get('gen') == 3,
                   'expected exactly one policy_changed reset of the removed host at gen3')
        activations = [r for r in records if r.get('event') == 'policy_activated' and r.get('gen') == 3]
        vm.require(len(activations) == 1, 'missing generation3 activation')
        activated = datetime.datetime.fromisoformat(activations[0]['ts'].replace('Z', '+00:00')).timestamp()
        latency_ms = cut[0]['wall_ns'] / 1_000_000 - activated * 1000
        vm.require(-2 <= latency_ms <= 201, f'narrowed stream stopped outside one watchdog period: {latency_ms:.3f}ms')
        vm.require(vm.tag(agent.pid) == 1, 'stream process tag changed')
        vm.require(not any(r.get('event') == 'receipt_loss' or r.get('dropped', 0) for r in records), 'receipt loss')
        (a.output / 'receipts.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records))
        report.update(result='PASS', narrowing_cut_ms=latency_ms, removed_stream=cut[0],
                      kept_host=kept, kept_bytes_after_narrowing=count(rows, kept) - keep_before,
                      kept_reset_count=sum(r.get('host') == kept for r in resets))
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if agent is not None and agent.poll() is None:
            agent.terminate()
            try: agent.wait(timeout=6)
            except subprocess.TimeoutExpired: agent.kill(); agent.wait()
        if stream_file is not None: stream_file.close()
        if armed:
            try:
                action('off'); report['cleanup'] = 'authorized off completed'
            except Exception as error: report.update(result='FAIL', cleanup_error=str(error))
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    vm.require(report['result'] == 'PASS', 'stream evidence/cleanup failed')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        raise SystemExit(1)
