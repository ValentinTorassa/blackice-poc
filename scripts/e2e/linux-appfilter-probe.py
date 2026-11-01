#!/usr/bin/python3
"""Disposable-QEMU-VM runtime fixture. No BPF/control/setup calls; never run by builds."""
import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import selectors
import socket
import sys
import time


PROTOCOL_CASES = (
    ("icmp4", socket.AF_INET, socket.SOCK_DGRAM, 1),
    ("icmp6", socket.AF_INET6, socket.SOCK_DGRAM, 58),
    ("sctp4", socket.AF_INET, socket.SOCK_STREAM, 132),
    ("udplite4", socket.AF_INET, socket.SOCK_DGRAM, 136),
    ("mptcp4", socket.AF_INET, socket.SOCK_STREAM, 262),
    ("raw4", socket.AF_INET, socket.SOCK_RAW, 1),
)
PERMISSION_ERRORS = (errno.EPERM, errno.EACCES)
CONTROL_LIMITS = (*PERMISSION_ERRORS, errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT,
                  errno.ESOCKTNOSUPPORT, errno.ENOPROTOOPT)


def emit(event, **fields):
    print(json.dumps({"event": event, "monotonic_ns": time.monotonic_ns(), **fields}), flush=True)


def address(value, version):
    parsed = ipaddress.ip_address(value)
    if parsed.version != version or parsed.is_unspecified or parsed.is_multicast:
        raise ValueError("expected a specific unicast address of the requested family")
    return str(parsed)


def cases(v4, v6):
    return [
        ("tcp4", socket.AF_INET, socket.SOCK_STREAM, (v4, 47121)),
        ("tcp6", socket.AF_INET6, socket.SOCK_STREAM, (v6, 47122)),
        ("udp4", socket.AF_INET, socket.SOCK_DGRAM, (v4, 47123)),
        ("udp6", socket.AF_INET6, socket.SOCK_DGRAM, (v6, 47124)),
        ("tcp_mapped", socket.AF_INET6, socket.SOCK_STREAM, ("::ffff:" + v4, 47121)),
        ("udp_mapped", socket.AF_INET6, socket.SOCK_DGRAM, ("::ffff:" + v4, 47123)),
    ]


def send(args):
    ok = True
    for name, family, kind, destination in cases(args.v4, args.v6):
        payload = f"{args.token}:{args.phase}:{name}".encode("ascii")
        failure = None
        try:
            with socket.socket(family, kind) as client:
                client.settimeout(2)
                if kind == socket.SOCK_STREAM:
                    client.connect(destination)
                    client.sendall(payload)
                else:
                    client.sendto(payload, destination)
        except OSError as error:
            failure = error.errno if error.errno is not None else -1
        passed = (failure in (errno.EPERM, errno.EACCES)) if args.expect == "deny" else failure is None
        emit("attempt", case=name, phase=args.phase, expected=args.expect,
             errno=failure, passed=passed, pid=os.getpid())
        ok = ok and passed
    return 0 if ok else 1


def protocol_control(path):
    """Accept one complete untagged observation, not a deny log or a partial run."""
    if not path:
        raise ValueError("protocols --expect deny requires --control-log from an untagged run")
    with Path(path).open("rb") as source:
        data = source.read(65537)
    if len(data) > 65536:
        raise ValueError("protocol control log is too large")
    cases_by_name = {row[0]: row[1:] for row in PROTOCOL_CASES}
    rows = {}
    for line in data.decode("utf-8").splitlines():
        row = json.loads(line)
        if not isinstance(row, dict) or row.get("expected") != "control":
            raise ValueError("not an untagged protocol control log")
        if row.get("event") == "protocol_summary":
            continue
        name = row.get("case")
        failure = row.get("errno")
        if (row.get("event") != "socket_attempt" or name not in cases_by_name or name in rows
                or "errno" not in row or (failure is not None and type(failure) is not int)
                or tuple(row.get(key) for key in ("family", "kind", "protocol")) != cases_by_name[name]):
            raise ValueError("invalid or duplicate protocol control case")
        rows[name] = failure
    if rows.keys() != cases_by_name.keys():
        raise ValueError("incomplete protocol control log")
    return rows


def protocol_result(expected, failure, control_errno=None):
    if expected == "control":
        if failure is None:
            return "CONTROL_AVAILABLE", True, "socket_created"
        if failure in CONTROL_LIMITS:
            return "LIMIT", None, "untagged_socket_unavailable"
        return "FAIL", False, "control_error"
    if failure is None:
        return "FAIL", False, "tagged_socket_created"
    if control_errno is not None:
        if control_errno in CONTROL_LIMITS:
            return "LIMIT", None, "untagged_socket_unavailable"
        return "FAIL", False, "control_error"
    if failure in PERMISSION_ERRORS:
        return "PASS", True, "refused_after_available_control"
    return "FAIL", False, "not_a_permission_refusal"


def protocols(args):
    controls = protocol_control(args.control_log) if args.expect == "deny" else {}
    counts = {"passed": 0, "limited": 0, "failed": 0}
    for name, family, kind, protocol in PROTOCOL_CASES:
        failure = None
        try:
            with socket.socket(family, kind, protocol):
                pass
        except OSError as error:
            failure = error.errno if error.errno is not None else -1
        control_errno = controls.get(name)
        verdict, passed, reason = protocol_result(args.expect, failure, control_errno)
        emit("socket_attempt", case=name, phase=args.phase, expected=args.expect,
             family=family, kind=kind, protocol=protocol, errno=failure,
             control_errno=control_errno, verdict=verdict, reason=reason, passed=passed, pid=os.getpid())
        counts["limited" if passed is None else "passed" if passed else "failed"] += 1
    emit("protocol_summary", expected=args.expect, **counts)
    # Exit 2 means there was no usable control; it is not a passing denial run.
    return 1 if counts["failed"] else 0 if counts["passed"] else 2


def require_vm(hostname):
    # Catch accidental host execution before socket creation, barriers or forks.
    # This is an operator guard, not a security boundary against a malicious caller.
    if (not hostname or socket.gethostname() != hostname
            or Path("/sys/class/dmi/id/sys_vendor").read_text().strip() != "QEMU"):
        raise ValueError("runtime probe requires the named disposable QEMU VM")
    if os.geteuid() == 0:
        raise ValueError("run the probe as the unprivileged VM owner, never as root")


def receiver(args):
    selector = selectors.DefaultSelector()
    opened = []
    streams = {}
    ready = False
    try:
        for name, family, kind, endpoint in cases(args.v4, args.v6)[:4]:
            listener = socket.socket(family, kind)
            opened.append(listener)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(endpoint)
            if kind == socket.SOCK_STREAM:
                listener.listen(16)
            listener.setblocking(False)
            selector.register(listener, selectors.EVENT_READ, (name, kind))
        emit("ready", ports=[47121, 47122, 47123, 47124])
        ready = True
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                current = key.fileobj
                name, kind = key.data
                if kind == "stream":
                    data = current.recv(4096)
                    streams[current] += data
                    if len(streams[current]) > 4096:
                        raise ValueError("unexpected oversized receiver payload")
                    if not data:
                        emit("payload", case=name, payload=streams.pop(current).decode("ascii", "replace"))
                        selector.unregister(current)
                        current.close()
                elif kind == socket.SOCK_STREAM:
                    peer, _ = current.accept()
                    if len(streams) >= 32:
                        peer.close()
                        raise ValueError("unexpected receiver connection flood")
                    peer.setblocking(False)
                    streams[peer] = b""
                    selector.register(peer, selectors.EVENT_READ, (name, "stream"))
                else:
                    data, _ = current.recvfrom(4096)
                    emit("payload", case=name, payload=data.decode("ascii", "replace"))
        if streams:
            raise ValueError("receiver stopped with incomplete TCP payloads")
        return 0
    finally:
        for stream in streams:
            stream.close()
        for listener in opened:
            listener.close()
        selector.close()
        if ready:
            emit("stopped")


def wait_barrier(args):
    if not args.wait_for:
        return
    release = Path(args.wait_for)
    if release.exists():
        raise ValueError("release marker already exists")
    if not args.ready_file:
        raise ValueError("wait-for requires a ready-file")
    with Path(args.ready_file).open("x") as out:
        json.dump({"pid": os.getpid(), "monotonic_ns": time.monotonic_ns()}, out)
    deadline = time.monotonic() + 120
    while not release.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("operator did not release the prepared probe within 120 seconds")
        time.sleep(0.01)


def double_fork(args, operation):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        os.setsid()
        if os.fork() != 0:
            os._exit(0)
        try:
            status = operation(args)
        except BaseException as error:
            emit("probe_error", reason=type(error).__name__)
            status = 1
        os.write(write_fd, bytes([status]))
        os.close(write_fd)
        os._exit(status)
    os.close(write_fd)
    os.waitpid(child, 0)
    try:
        if not select.select([read_fd], [], [], 40)[0]:
            raise TimeoutError("detached probe did not report completion")
        result = os.read(read_fd, 1)
        return result[0] if result else 1
    finally:
        os.close(read_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("receiver", "send", "protocols"))
    parser.add_argument("--authorized-network-test", action="store_true", required=True)
    parser.add_argument("--vm-hostname", required=True, help="exact disposable QEMU guest hostname")
    parser.add_argument("--v4")
    parser.add_argument("--v6")
    parser.add_argument("--seconds", type=int, default=90)
    parser.add_argument("--expect", choices=("control", "deny"), default="deny")
    parser.add_argument("--control-log", help="complete untagged protocols JSONL; required for protocol deny")
    parser.add_argument("--token", default="blackice-appfilter")
    parser.add_argument("--phase", default="denied")
    parser.add_argument("--double-fork", action="store_true")
    parser.add_argument("--wait-for")
    parser.add_argument("--ready-file")
    args = parser.parse_args()
    if args.control_log and (args.mode != "protocols" or args.expect != "deny"):
        parser.error("--control-log is only for protocols --expect deny")
    if args.mode == "protocols" and args.expect == "deny" and not args.control_log:
        parser.error("protocol deny requires an untagged --control-log")
    if args.mode != "protocols":
        args.v4, args.v6 = address(args.v4, 4), address(args.v6, 6)
    if not 1 <= args.seconds <= 1800:
        parser.error("seconds must be 1..1800")
    if any(not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value) for value in (args.token, args.phase)):
        parser.error("token and phase must be short ASCII identifiers")
    require_vm(args.vm_hostname)
    if args.mode == "receiver":
        if args.double_fork or args.wait_for or args.ready_file:
            parser.error("receiver has no fork or barrier options")
        return receiver(args)
    wait_barrier(args)
    operation = send if args.mode == "send" else protocols
    return double_fork(args, operation) if args.double_fork else operation(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        emit("fixture_error", reason=type(error).__name__, detail=str(error))
        sys.exit(1)
