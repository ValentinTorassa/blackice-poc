#!/usr/bin/env python3
"""VM3-only reload crash/child-fault evidence; real fresh polkit auth is required.

Run as the configured owner in a tty against an explicitly installed fault build.
This script never handles a password or installs an authorization rule. It writes
one root-owned PID-scoped fault selector and, for a paused case, kills that exact
loader through a pidfd. It leaves the recovered policy armed and records its gen.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time

spec = importlib.util.spec_from_file_location('reload_vm', Path(__file__).with_name('linux-appfilter-reload-vm.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
UNIT = 'blackice-appfilter.service'
ROOT_CONTROL = r'''
import os,signal,socket,stat,subprocess,sys
assert os.geteuid()==0 and socket.gethostname()=='test3-vm'
assert subprocess.check_output(['systemd-detect-virt'],text=True).strip() in ('qemu','kvm')
op,pid,mode=sys.argv[1:]
assert pid.isdecimal() and int(pid)>1
assert mode in ('after_validation','after_prepare','after_stage','after_intent','stop_child','kill_child','invalid_policy','off_stopping')
path='/etc/blackice-appfilter/vm-reload-fault'
expected=(pid+' '+mode+'\n').encode()
if op=='create':
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
 try: os.write(fd,expected); os.fchmod(fd,0o644); os.fsync(fd)
 finally: os.close(fd)
elif op=='remove':
 try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError: sys.exit(0)
 try:
  st=os.fstat(fd)
  assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
  assert os.read(fd,128)==expected
 finally: os.close(fd)
 os.unlink(path)
elif op=='kill':
 fd=os.pidfd_open(int(pid))
 try:
  assert subprocess.check_output(['systemctl','show','blackice-appfilter.service','-p','MainPID','--value'],text=True).strip()==pid
  signal.pidfd_send_signal(fd,signal.SIGKILL)
 finally: os.close(fd)
else: raise AssertionError('invalid operation')
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cli', type=Path, required=True)
    p.add_argument('--cli-sha256', required=True)
    p.add_argument('--fault-build-sha256', required=True)
    p.add_argument('--mode', required=True, choices=('after_validation', 'after_prepare', 'after_stage', 'after_intent', 'stop_child', 'kill_child', 'invalid_policy'))
    p.add_argument('--current-policy', type=Path, required=True)
    p.add_argument('--next-policy', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    vm.require(os.geteuid() != 0 and os.isatty(0), 'unprivileged owner tty required for real polkit')
    vm.require(socket.gethostname() == 'test3-vm', 'only the designated VM3 guest')
    vm.require(vm.command(['systemd-detect-virt']).strip() in ('qemu', 'kvm'), 'QEMU/KVM only')
    vm.require(hashlib.sha256(a.cli.read_bytes()).hexdigest() == a.cli_sha256, 'CLI hash mismatch')
    binary = Path('/usr/local/libexec/blackice-linux-appfilter').read_bytes()
    vm.require(hashlib.sha256(binary).hexdigest() == a.fault_build_sha256, 'fault build hash mismatch')
    vm.require(b'VM-ONLY RELOAD FAULT BUILD' in binary, 'test build required; never substitute the normal binary')
    current, candidate = a.current_policy.read_bytes(), a.next_policy.read_bytes()
    generation = json.loads(current).get('generation', 1)
    vm.require(json.loads(candidate)['generation'] == generation + 1, 'next generation required')
    if a.mode == 'after_validation':
        vm.require('/usr/bin/sleep' not in [x['executable'] for x in json.loads(current)['applications']], 'sleep must initially be unlisted')
        vm.require('/usr/bin/sleep' in [x['executable'] for x in json.loads(candidate)['applications']], 'candidate must add /usr/bin/sleep')
    before = vm.lookup('state')
    old_hash, new_hash = (hashlib.sha256(b).hexdigest() for b in (current, candidate))
    vm.require(vm.state_hash(before) == old_hash, 'wrong current policy')
    pid = vm.command(['systemctl', 'show', UNIT, '-p', 'MainPID', '--value']).strip()
    vm.require(int(pid) > 0, 'service must already be armed')
    a.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    sizes = {str(x): x.stat().st_size for x in vm.STATE.glob('receipt-*.jsonl')}
    tail = vm.command(['sudo', '-n', 'journalctl', '--no-pager', '-n', '1', '-o', 'json', f'_PID={pid}'], timeout=3)
    vm.require(tail.strip(), 'fault build must have a startup journal record')
    cursor = json.loads(tail.splitlines()[-1])['__CURSOR']
    report = {'result': 'FAIL', 'mode': a.mode, 'service_sha256': a.fault_build_sha256, 'loader_before': pid,
              'old_policy': old_hash, 'new_policy': new_hash, 'state_before': before}
    stop = threading.Event()
    monitor_error = []
    observed = []
    selector_created = False
    race_processes = []

    def root(operation):
        return vm.command(['sudo', '-n', '/usr/bin/python3', '-c', ROOT_CONTROL, operation, pid, a.mode])

    def journal():
        return vm.command(['sudo', '-n', 'journalctl', '--no-pager', '--after-cursor', cursor, '-o', 'cat', f'_PID={pid}'], timeout=3)

    def monitor():
        paused = a.mode in ('after_validation', 'after_prepare', 'after_stage', 'after_intent')
        marker = f'VM_RELOAD_PAUSE pid={pid} point={a.mode}' if paused else f'VM_RELOAD_FAULT pid={pid} mode={a.mode}'
        try:
            end = time.monotonic() + 65
            while not stop.wait(0.05):
                found = marker in journal()
                if stop.is_set():
                    return
                if found:
                    observed.append(time.monotonic())
                    if paused:
                        # Verify the separate control acceptor remains responsive
                        # while the transaction thread is deliberately paused.
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                            s.settimeout(2)
                            s.connect('/run/blackice-appfilter/control.sock')
                            s.sendall(b'BA1\x04' + struct.pack('<I', len(candidate)) + candidate)
                            response = s.recv(4096).decode()
                        vm.require('ChangeInProgress' in response, f'concurrent reload not refused: {response}')
                        report['concurrent_refusal'] = response.strip()
                        if a.mode == 'after_stage':
                            staged_maps = {}
                            for name in ('files', 'ports'):
                                entries = json.loads(vm.command(['sudo', '-n', 'bpftool', '-j', 'map', 'dump', 'pinned', vm.PIN + '/' + name]))
                                vm.require(any(int.from_bytes(vm.decode_bytes(x['key'])[4:8], 'little') == generation + 1 for x in entries), 'fault did not leave real next-generation rows staged')
                                staged_maps[name] = entries
                            report['staged_maps_before_crash'] = staged_maps
                        if a.mode == 'after_validation':
                            app = subprocess.Popen(['/usr/bin/sleep', '60'])
                            race_processes.append(app)
                            time.sleep(0.1)
                            vm.require(app.poll() is None and vm.tag(app.pid) == 0, 'race process was not started untagged')
                            report['race_pid'] = app.pid
                            root('remove')  # Resume only the paused transaction thread.
                        else:
                            root('kill')
                    return
                vm.require(time.monotonic() < end, 'fault boundary was not reached')
        except Exception as error:
            monitor_error.append(str(error))
            if paused and observed:
                try:
                    root('kill')
                except Exception as recovery:
                    monitor_error.append('kill failed: ' + str(recovery))

    thread = threading.Thread(target=monitor, daemon=True)
    try:
        root('create')
        selector_created = True
        thread.start()
        # Deliberately inherit the owner's terminal. No password capture/input.
        rc = subprocess.run([str(a.cli), 'app', 'reload', '--policy', str(a.next_policy)], timeout=85).returncode
        finished = time.monotonic()
        report['cli_returncode'] = rc
        vm.require((rc == 0) == (a.mode == 'after_validation'), 'unexpected reload exit status')
        thread.join(timeout=5)
        vm.require(not monitor_error, '; '.join(monitor_error))
        vm.require(observed, 'no fault marker observed; authentication may have failed')
        report['seconds_after_fault_observed'] = finished - observed[0]
        if a.mode == 'stop_child':
            vm.require(4.5 <= finished - observed[0] <= 8, 'child timeout outside the five-second budget tolerance')
        committed = a.mode in ('after_validation', 'after_intent')
        expected_generation = generation + committed
        expected_hash = new_hash if committed else old_hash
        recovery_started = time.monotonic()
        # The reviewed unit backs off failed restarts up to 60 seconds. This
        # separate recovery budget never extends the five-second child exchange.
        end = recovery_started + 75
        while True:
            vm.require(time.monotonic() < end, 'recovery exceeded the restart-backoff budget')
            answer = subprocess.run([str(a.cli), 'app', 'status'], capture_output=True, text=True, timeout=max(0.1, end - time.monotonic()))
            if answer.returncode == 0 and answer.stdout.startswith(f'OK armed gen={expected_generation} '):
                report['status'] = answer.stdout.strip()
                break
            vm.require(time.monotonic() < end, f'recovery failed: {answer.stdout} {answer.stderr}')
            time.sleep(0.2)
        report['recovery_wait_seconds'] = time.monotonic() - recovery_started
        state = vm.lookup('state')
        vm.require(vm.state_hash(state) == expected_hash, 'kernel does not follow committed intent')
        raw = vm.decode_bytes(state['value'])
        vm.require(int.from_bytes(raw[48:52], 'little') == expected_generation and raw[52:56] == bytes(4), 'wrong epoch or fence remains closed')
        recovered_maps = {}
        for name in ('files', 'ports'):
            entries = json.loads(vm.command(['sudo', '-n', 'bpftool', '-j', 'map', 'dump', 'pinned', vm.PIN + '/' + name]))
            vm.require(all(int.from_bytes(vm.decode_bytes(x['key'])[4:8], 'little') <= expected_generation for x in entries), 'uncommitted future rows survived recovery')
            recovered_maps[name] = entries
        report['maps_after_recovery'] = recovered_maps
        after = vm.command(['systemctl', 'show', UNIT, '-p', 'MainPID', '--value']).strip()
        vm.require((after == pid) == (a.mode in ('after_validation', 'invalid_policy')), 'unexpected restart behavior')
        time.sleep(0.2)
        records = vm.receipts(sizes)
        event = 'policy_activated' if a.mode == 'after_validation' else 'policy_change_completed_after_restart' if a.mode == 'after_intent' else 'policy_change_failed'
        reason = 'completed_after_restart' if a.mode == 'after_intent' else 'proxy_refused' if a.mode == 'invalid_policy' else 'interrupted'
        matching = [r for r in records if r.get('event') == event and (a.mode == 'after_validation' or r.get('reason') == reason) and r.get('old_policy') == old_hash and r.get('new_policy') == new_hash]
        vm.require(len(matching) == 1, 'missing/duplicate recovery receipt or wrong hashes')
        if a.mode == 'after_validation':
            import re
            app = race_processes[0]
            vm.require(app.poll() is None and vm.tag(app.pid) == 0, 'running race process was silently retagged')
            flag = re.search(r'added_app_running_untagged=(\d+)', report['status'])
            vm.require(flag and int(flag[1]) != 0, 'added-app status warning missing')
            warnings = [r for r in records if r.get('reason') == 'added_app_running_untagged' and r.get('executable') == '/usr/bin/sleep' and f'tgid={app.pid};' in r.get('detail', '')]
            vm.require(warnings, 'added-app receipt does not name the untagged process')
            fresh = subprocess.Popen(['/usr/bin/sleep', '60'])
            race_processes.append(fresh)
            time.sleep(0.1)
            vm.require(fresh.poll() is None and vm.tag(fresh.pid) != 0, 'new launch after publication was not tagged')
            report['fresh_pid'] = fresh.pid
            report['fresh_tag'] = vm.tag(fresh.pid)
            app.terminate()
            app.wait(timeout=3)
            end = time.monotonic() + 3
            while True:
                status = vm.command([str(a.cli), 'app', 'status'])
                if 'added_app_running_untagged=0' in status:
                    report['warning_cleared_after_exit'] = True
                    break
                vm.require(time.monotonic() < end, 'warning remained after the race process exited')
                time.sleep(0.1)
        vm.require(not any(r.get('event') == 'receipt_loss' or r.get('dropped', 0) for r in records), 'receipt loss')
        (a.output / 'receipts.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records))
        report.update(result='PASS; SUBSEQUENT AUTHENTICATED RETRY STILL REQUIRED', loader_after=after,
                      generation_after=expected_generation, state_after=state)
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        stop.set()
        if thread.ident:
            thread.join(timeout=6)
        for app in race_processes:
            if app.poll() is None:
                app.terminate()
                try:
                    app.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    app.kill()
                    app.wait()
        if selector_created:
            try:
                root('remove')
                report['selector_cleanup'] = 'removed only the matching root-owned PID selector'
            except Exception as error:
                report['selector_cleanup_error'] = str(error)
                report['result'] = 'FAIL'
        try:
            (a.output / 'loader-journal.txt').write_text(journal())
        except Exception as error:
            report['journal_error'] = str(error)
            report['result'] = 'FAIL'
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    vm.require(report['result'].startswith('PASS'), 'evidence or selector cleanup failed')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        raise SystemExit(1)
