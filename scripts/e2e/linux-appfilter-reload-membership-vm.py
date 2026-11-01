#!/usr/bin/env python3
"""VM3 add/remove/retirement evidence with real owner polkit authorization.

Requires an off, installed service and an initial generation-1 policy listing
root-owned copies of env and curl (not /usr/bin/env or /usr/bin/curl themselves).
No setup, credential handling or authorization rule. A controlled loader crash
checks retired-slot recovery; the final off is freshly authorized through polkit.
"""
import argparse
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('reload_vm', Path(__file__).with_name('linux-appfilter-reload-vm.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
AGENT = r'''
import json,os,socket,ssl,sys,time
host,port=sys.argv[1:]
ctx=ssl.create_default_context()
print(json.dumps({'pid':os.getpid()}),flush=True)
for command in sys.stdin:
 row={'command':command.strip(),'pid':os.getpid(),'monotonic_ns':time.monotonic_ns(),'error':None,'errno':None}
 try:
  target=(host,int(port)) if row['command']=='direct' else ('1.1.1.1',443)
  with socket.create_connection(target,timeout=4) as s:
   if row['command']=='tls':
    with ctx.wrap_socket(s,server_hostname='example.com'): pass
 except OSError as e: row.update(error=type(e).__name__,errno=e.errno)
 print(json.dumps(row),flush=True)
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cli', type=Path, required=True)
    p.add_argument('--cli-sha256', required=True)
    p.add_argument('--service-sha256', required=True)
    p.add_argument('--launcher', required=True)
    p.add_argument('--initial-policy', type=Path, required=True)
    p.add_argument('--receiver', required=True)
    p.add_argument('--receiver-port', type=int, required=True)
    p.add_argument('--token', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    vm.require(os.geteuid() == 1000 and os.isatty(0) and socket.gethostname() == 'test3-vm', 'VM3 owner tty required')
    vm.require(vm.command(['systemd-detect-virt']).strip() in ('qemu', 'kvm'), 'QEMU/KVM only')
    vm.require(hashlib.sha256(a.cli.read_bytes()).hexdigest() == a.cli_sha256, 'CLI hash mismatch')
    vm.require(hashlib.sha256(Path('/usr/local/libexec/blackice-linux-appfilter').read_bytes()).hexdigest() == a.service_sha256, 'service hash mismatch')
    initial = json.loads(a.initial_policy.read_bytes())
    names = [x['executable'] for x in initial['applications']]
    vm.require(initial['generation'] == 1 and len(names) == 2 and names[0] == a.launcher, 'initial policy must list launcher first and two copied apps')
    vm.require('/usr/bin/curl' not in names and '/usr/bin/env' not in names, 'original curl/env must start unlisted')
    vm.require(vm.command([str(a.cli), 'app', 'status']).startswith('OK off'), 'service must start off')
    a.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    configs = [initial]
    second = copy.deepcopy(initial)
    second['generation'] = 2
    second['applications'].append({'executable': '/usr/bin/curl', 'policy': copy.deepcopy(initial['applications'][0]['policy'])})
    configs.append(second)
    third = copy.deepcopy(second)
    third['generation'] = 3
    third['applications'] = [x for x in third['applications'] if x['executable'] != a.launcher]
    configs.append(third)
    fourth = copy.deepcopy(third)
    fourth['generation'] = 4
    fourth['applications'].append({'executable': '/usr/bin/env', 'policy': {'version': 'blackice.policy/v0', 'network': {'mode': 'deny-all'}}})
    configs.append(fourth)
    paths = []
    for n, cfg in enumerate(configs, 1):
        path = a.output / f'policy-{n}.json'
        path.write_text(json.dumps(cfg, indent=2) + '\n')
        paths.append(path)
    sizes = {str(x): x.stat().st_size for x in vm.STATE.glob('receipt-*.jsonl')}
    children = []
    armed = False
    report = {'result': 'FAIL', 'service_sha256': a.service_sha256, 'cases': {}}

    def action(verb, policy=None, success=True):
        cmd = [str(a.cli), 'app', verb]
        if policy: cmd += ['--policy', str(policy)]
        rc = subprocess.run(cmd, timeout=35).returncode
        vm.require((rc == 0) == success, f'unexpected {verb} exit {rc}')

    def read_line(proc):
        vm.require(select.select([proc.stdout], [], [], 6)[0], 'agent reply timeout')
        return json.loads(proc.stdout.readline())

    def agent(executable):
        proc = subprocess.Popen([executable, sys.executable, '-u', '-c', AGENT, a.receiver, str(a.receiver_port)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        children.append(proc)
        vm.require(read_line(proc)['pid'] == proc.pid, 'wrong agent PID')
        return proc

    def probe(proc, command, allowed):
        proc.stdin.write(command + '\n')
        proc.stdin.flush()
        row = read_line(proc)
        if command == 'direct' and not allowed:
            vm.require(row['errno'] in (errno.EPERM, errno.EACCES), f'direct attempt was not refused: {row}')
        else:
            vm.require((row['error'] is None) == allowed, f'unexpected TLS decision: {row}')
        return row

    try:
        action('on', paths[0])
        armed = True
        original = agent(a.launcher)
        vm.require(vm.tag(original.pid) == 1, 'original launcher not in slot1')
        probes = [probe(original, 'direct', False)]
        held = subprocess.Popen(['/usr/bin/curl', '--silent', '--show-error', '--noproxy', '*', '--limit-rate', '1', '--max-time', '30', '-o', '/dev/null', 'https://example.com/'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(held)
        time.sleep(0.3)
        vm.require(held.poll() is None and vm.tag(held.pid) == 0, 'candidate must already be running untagged')
        before = vm.lookup('state')
        action('reload', paths[1], success=False)
        vm.require(vm.lookup('state') == before, 'already-running addition changed the epoch')
        vm.require(any(r.get('reason') == 'CloseAddedAppsFirst' for r in vm.receipts(sizes)), 'missing already-running refusal receipt')
        report['cases']['already_running_addition'] = 'CloseAddedAppsFirst; unchanged epoch'
        held.terminate(); held.wait(timeout=5)
        action('reload', paths[1])
        vm.require(vm.tag(original.pid) == 1, 'original tag moved after addition')
        probes.append(probe(original, 'direct', False))
        for host, yes in [('example.com', True), ('github.com', False)]:
            result = subprocess.run(['/usr/bin/curl', '--silent', '--show-error', '--noproxy', '*', '--max-time', '10', '-o', '/dev/null', '-w', '%{http_code}', 'https://' + host + '/'], capture_output=True, text=True, timeout=12)
            vm.require((result.returncode == 0 and result.stdout == '200') if yes else result.returncode == 35, f'newly listed curl {host}: {result.returncode} {result.stdout} {result.stderr}')
        rows = vm.receipts(sizes)
        for host, verdict in [('example.com', 'allow'), ('github.com', 'deny')]:
            vm.require(any(r.get('event') == 'connect' and r.get('app_id') == 3 and r.get('gen') == 2 and r.get('host') == host and r.get('verdict') == verdict for r in rows), 'new slot decision receipt missing')
        report['cases']['newly_listed_app'] = 'slot3; example.com allowed, github.com denied; gen2 receipts'
        action('reload', paths[2])
        vm.require(vm.tag(original.pid) == 1, 'retirement changed an existing tag')
        probes.append(probe(original, 'direct', False))
        probe(original, 'tls', True)
        code = 'import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),3); s.sendall((sys.argv[3]+"\\n").encode()); s.close()'
        vm.command([a.launcher, sys.executable, '-c', code, a.receiver, str(a.receiver_port), a.token + ':removed-new-launch'])
        report['cases']['removed_running_app'] = 'old slot1 still denied direct network and allowed its previous example.com TLS; new launch reached receiver'
        action('reload', paths[3])
        added = agent('/usr/bin/env')
        vm.require(vm.tag(added.pid) == 4 and vm.tag(original.pid) == 1, 'retired slot was reused or original tag changed')
        probe(added, 'direct', False)
        probes.append(probe(original, 'direct', False))
        report['cases']['retired_slot_not_reused'] = 'new app slot4; retired process remains slot1'
        old_pid = vm.command(['systemctl', 'show', 'blackice-appfilter.service', '-p', 'MainPID', '--value']).strip()
        kill_code = 'import os,signal,socket,subprocess,sys; assert socket.gethostname()=="test3-vm"; fd=os.pidfd_open(int(sys.argv[1])); assert subprocess.check_output(["systemctl","show","blackice-appfilter.service","-p","MainPID","--value"],text=True).strip()==sys.argv[1]; signal.pidfd_send_signal(fd,signal.SIGKILL); os.close(fd)'
        vm.command(['sudo', '-n', '/usr/bin/python3', '-c', kill_code, old_pid])
        recovery_started = time.monotonic()
        end = recovery_started + 75  # reviewed unit: restart backoff up to 60s
        while True:
            vm.require(time.monotonic() < end, 'retirement recovery exceeded the restart-backoff budget')
            answer = subprocess.run([str(a.cli), 'app', 'status'], capture_output=True, text=True, timeout=max(0.1, end - time.monotonic()))
            if answer.returncode == 0 and answer.stdout.startswith('OK armed gen=4 '): break
            vm.require(time.monotonic() < end, 'retirement recovery did not complete')
            time.sleep(0.2)
        report['recovery_wait_seconds'] = time.monotonic() - recovery_started
        vm.require(vm.tag(original.pid) == 1, 'restart lost the retired process tag')
        probe(original, 'tls', False)
        time.sleep(0.3)
        records = vm.receipts(sizes)
        vm.require(any(r.get('reason') == 'retired_app_after_restart' and r.get('app_id') == 1 and r.get('gen') == 2 for r in records), 'retired restart refusal receipt missing')
        for row, expected in zip(probes, (1, 2, 2, 2)):
            matching = [r for r in records if r.get('event') == 'kernel_drop' and f'tgid={original.pid} ' in r.get('detail', '') and int(r.get('detail', '').split('kernel_monotonic_ns=')[-1]) >= row['monotonic_ns']]
            vm.require(matching and matching[0]['gen'] == expected, 'retired decisions were relabeled with the active generation')
        vm.require(not any(r.get('event') == 'receipt_loss' or r.get('dropped', 0) for r in records), 'receipt loss')
        report['cases']['retired_after_restart'] = 'same tag, old gen2 refusal; no retired listener service'
        (a.output / 'receipts.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records))
        report.update(result='LOCAL PASS; RECEIVER CORROBORATION REQUIRED', receiver_rule=a.token + ':removed-new-launch must be present', probes=probes)
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for proc in children:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        if armed:
            try:
                action('off')
                report['cleanup'] = 'authorized off completed'
            except Exception as error:
                report.update(result='FAIL', cleanup_error=str(error))
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    vm.require(report['result'].startswith('LOCAL PASS'), 'membership evidence/cleanup failed')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        raise SystemExit(1)
