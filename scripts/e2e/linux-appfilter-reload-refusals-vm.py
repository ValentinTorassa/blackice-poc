#!/usr/bin/env python3
"""VM-only negative reload tests. No password, policy installation, or auth rule.

Requires an already armed generation with /usr/bin/curl listed, its exact policy,
and a valid next policy. The root-peer case uses sudo -n only to send a refused
control request. A private PTY cancels the real polkit prompt without entering
credentials. All cases must leave the pinned epoch and service PID unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import struct
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('reload_vm', Path(__file__).with_name('linux-appfilter-reload-vm.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
CONTROL = '/run/blackice-appfilter/control.sock'
UNIT = 'blackice-appfilter.service'


def exchange(body, op=4):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(20)
        sock.connect(CONTROL)
        try:
            sock.sendall(b'BA1' + bytes([op]) + struct.pack('<I', len(body)) + body)
        except BrokenPipeError:
            pass  # The service refuses non-owner/tagged peers before reading.
        return sock.recv(4096).decode('utf-8', 'replace').strip()


def cancelled_prompt(cli, policy):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(str(cli), [str(cli), 'app', 'reload', '--policy', str(policy)])
    text = bytearray()
    cancelled = False
    status = None
    try:
        end = time.monotonic() + 22
        while time.monotonic() < end:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    data = b''
                if not data:
                    break
                text.extend(data)
                vm.require(len(text) <= 32768, 'unexpected oversized terminal output')
                if b'AUTHENTICATING FOR org.blackice.appfilter.reload' in text and not cancelled:
                    os.write(fd, b'\x03')
                    cancelled = True
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            status = None
        vm.require(cancelled, 'no real reload authentication prompt observed')
    finally:
        if status is None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status = os.waitpid(pid, 0)
        os.close(fd)
    vm.require(status != 0, 'cancelled CLI unexpectedly succeeded')
    return text.decode('utf-8', 'replace')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hostname', required=True)
    p.add_argument('--cli', type=Path, required=True)
    p.add_argument('--cli-sha256', required=True)
    p.add_argument('--service-sha256', required=True)
    p.add_argument('--current-policy', type=Path, required=True)
    p.add_argument('--next-policy', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--off-stopping', action='store_true', help='VM fault build only: interrupt an authorized off, refuse reload while stopping, finish off and check NotArmed')
    a = p.parse_args()
    vm.require(os.geteuid() != 0, 'unprivileged owner required')
    vm.require(socket.gethostname() == a.hostname, 'wrong guest name')
    vm.require(vm.command(['systemd-detect-virt']).strip() in ('kvm', 'qemu'), 'QEMU/KVM only')
    vm.require(hashlib.sha256(a.cli.read_bytes()).hexdigest() == a.cli_sha256, 'CLI hash mismatch')
    vm.require(hashlib.sha256(Path('/usr/local/libexec/blackice-linux-appfilter').read_bytes()).hexdigest() == a.service_sha256,
               'installed service hash mismatch')
    current = a.current_policy.read_bytes()
    candidate = a.next_policy.read_bytes()
    config = json.loads(current)
    generation = config.get('generation', 1)
    vm.require(json.loads(candidate)['generation'] == generation + 1, 'next generation required')
    vm.require('/usr/bin/curl' in [x['executable'] for x in config['applications']], 'curl must be listed')
    before = vm.lookup('state')
    vm.require(vm.state_hash(before) == hashlib.sha256(current).hexdigest(), 'wrong armed configuration')
    service_pid = vm.command(['systemctl', 'show', UNIT, '-p', 'MainPID', '--value']).strip()
    vm.require(int(service_pid) > 0, 'service not active')
    if a.off_stopping:
        vm.require(os.isatty(0), 'owner tty required for the two real off authorizations')
        vm.require(b'VM-ONLY RELOAD FAULT BUILD' in Path('/usr/local/libexec/blackice-linux-appfilter').read_bytes(), 'opt-in VM fault build required')
    a.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    sizes = {str(path): path.stat().st_size for path in vm.STATE.glob('receipt-*.jsonl')}
    report = {'result': 'FAIL', 'generation': generation, 'cases': {}, 'service_sha256': a.service_sha256}

    def unchanged():
        # Auth cancellation can leave the service in its bounded D-Bus wait.
        deadline = time.monotonic() + 20
        while True:
            response = subprocess.run([str(a.cli), 'app', 'status'], capture_output=True, text=True, timeout=20)
            state = response.stdout + response.stderr
            if 'ChangeInProgress' not in state:
                vm.require(response.returncode == 0, f'status failed: {state}')
                vm.require(state.startswith(f'OK armed gen={generation} '), 'armed generation changed')
                break
            vm.require(time.monotonic() < deadline, 'request did not finish')
            time.sleep(0.1)
        vm.require(vm.lookup('state') == before, 'pinned epoch changed on a refusal')
        vm.require(vm.command(['systemctl', 'show', UNIT, '-p', 'MainPID', '--value']).strip() == service_pid,
                   'service restarted during a negative test')

    try:
        for name, body, expected in [
            ('stale_generation', current, 'ExpectedNextGeneration'),
            ('invalid_policy', b'{', None),
            ('owner_without_agent', candidate, 'OwnerAuthorizationRequired'),
        ]:
            answer = exchange(body)
            vm.require(answer.startswith('ERROR '), f'{name} unexpectedly accepted: {answer}')
            if expected:
                vm.require(expected in answer, f'{name}: {answer}')
            report['cases'][name] = answer
            unchanged()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as slow:
            slow.settimeout(5)
            slow.connect(CONTROL)
            slow.sendall(b'BA1\x04' + struct.pack('<I', len(candidate)))
            time.sleep(0.2)
            answer = exchange(candidate)
            vm.require('ChangeInProgress' in answer, f'concurrent request not refused: {answer}')
            report['cases']['concurrent_request'] = answer
        time.sleep(0.2)
        unchanged()
        root_code = 'import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect("' + CONTROL + '"); print(s.recv(4096).decode().strip())'
        answer = vm.command(['sudo', '-n', '/usr/bin/python3', '-c', root_code]).strip()
        vm.require(answer == 'ERROR NotOwner', f'root peer unexpectedly accepted: {answer}')
        report['cases']['non_owner_root'] = answer
        unchanged()
        tagged = subprocess.run(['/usr/bin/curl', '--http0.9', '--noproxy', '*', '--max-time', '5', '--silent', '--show-error',
                                 '--unix-socket', CONTROL, 'http://localhost/'], capture_output=True, text=True, timeout=10)
        # Early refusal closes without consuming curl's HTTP bytes, which can
        # yield ECONNRESET. The matching TaggedCaller receipt is required below.
        vm.require(tagged.stdout.strip() == 'ERROR TaggedCaller' or tagged.returncode == 56,
                   f'tagged caller unexpectedly accepted: {tagged.stdout} {tagged.stderr}')
        report['cases']['tagged_caller'] = {'stdout': tagged.stdout, 'stderr': tagged.stderr, 'returncode': tagged.returncode}
        unchanged()
        prompt = cancelled_prompt(a.cli, a.next_policy)
        (a.output / 'cancelled-prompt.txt').write_text(prompt)
        time.sleep(0.2)
        unchanged()
        report['cases']['cancelled_prompt'] = 'real org.blackice.appfilter.reload prompt; Ctrl-C; no credential entered'
        if a.off_stopping:
            fault_spec = importlib.util.spec_from_file_location('fault_controller', Path(__file__).with_name('linux-appfilter-reload-faults-vm.py'))
            faults = importlib.util.module_from_spec(fault_spec)
            fault_spec.loader.exec_module(faults)
            def selector(operation):
                return vm.command(['sudo', '-n', '/usr/bin/python3', '-c', faults.ROOT_CONTROL, operation, service_pid, 'off_stopping'])
            selector('create')
            try:
                off = subprocess.run([str(a.cli), 'app', 'off'], timeout=35)
                vm.require(off.returncode != 0, 'test interruption unexpectedly completed off')
                stopping = vm.lookup('state')
                vm.require(int.from_bytes(vm.decode_bytes(stopping['value'])[:4], 'little') == 6, 'test did not reach stopping state')
                response = exchange(candidate)
                vm.require(response == 'ERROR Stopping', f'reload while stopping: {response}')
                vm.require(vm.lookup('state') == stopping, 'refused reload modified stopping epoch')
                report['cases']['stopping'] = response
                report['stopping_state'] = stopping
            finally:
                selector('remove')
                off = subprocess.run([str(a.cli), 'app', 'off'], timeout=35)
                vm.require(off.returncode == 0, 'authorized off retry failed')
            response = exchange(candidate)
            vm.require(response == 'ERROR NotArmed', f'reload while unarmed: {response}')
            report['cases']['unarmed'] = response
            vm.require(vm.command([str(a.cli), 'app', 'status']).startswith('OK off'), 'off status missing')
            vm.command(['sudo', '-n', 'test', '!', '-e', vm.PIN + '/state'])
            report['cleanup'] = 'fresh authorized off retry completed; pins absent'
        time.sleep(0.2)
        records = vm.receipts(sizes)
        (a.output / 'receipts.jsonl').write_text(''.join(json.dumps(x) + '\n' for x in records))
        vm.require(not any(x.get('event') in ('policy_activated', 'policy_changed', 'receipt_loss') for x in records),
                   'unexpected activation/policy change/loss')
        reasons = {x.get('reason') for x in records}
        for reason in ('ExpectedNextGeneration', 'OwnerAuthorizationRequired', 'ChangeInProgress', 'NotOwner', 'TaggedCaller'):
            vm.require(reason in reasons, f'missing refusal record: {reason}')
        if a.off_stopping:
            for reason in ('Stopping', 'NotArmed'):
                vm.require(reason in reasons, f'missing state refusal receipt: {reason}')
        report.update(result='PASS', receipt_count=len(records), state=before, service_pid=service_pid)
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        raise SystemExit(1)
