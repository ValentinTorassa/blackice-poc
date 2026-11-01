#!/usr/bin/env python3
"""VM3-only WebSocket evidence client: two verified TLS echo connections.

No proxy environment or third-party packages. Default numeric dialing exercises
the app filter's SNI route; --direct is the off-state endpoint control. Only
synthetic test messages are sent. This is a bounded test client, not a library.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import signal
import socket
import ssl
import threading
import time

ENDPOINTS = {'httpbingo.org': '/websocket/echo', 'ws.postman-echo.com': '/raw'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--direct', action='store_true')
    p.add_argument('--seconds', type=float, default=30)
    args = p.parse_args()
    if socket.gethostname() != 'test3-vm' or not 1 <= args.seconds <= 60:
        raise SystemExit('VM3 only, duration 1..60 seconds')
    stop = threading.Event()
    lock = threading.Lock()
    ctx = ssl.create_default_context()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    def emit(**row):
        row.update(wall_ns=time.time_ns(), monotonic_ns=time.monotonic_ns())
        with lock:
            print(json.dumps(row), flush=True)

    def stream(host, path):
        total = messages = 0
        error = None
        sender = None
        done = threading.Event()
        deadline = 0
        try:
            with socket.create_connection((host if args.direct else '1.1.1.1', 443), 5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host, suppress_ragged_eofs=False) as tls:
                    tls.settimeout(5)
                    key = base64.b64encode(os.urandom(16)).decode()
                    head = (f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n'
                            f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
                            'Sec-WebSocket-Version: 13\r\nUser-Agent: blackice-a3-vm-test/0.1\r\n\r\n')
                    tls.sendall(head.encode())
                    with tls.makefile('rb') as reader:
                        # Bounded head parsing, preserving any following frames.
                        status = reader.readline(8193)
                        if len(status) > 8192 or not status.startswith(b'HTTP/1.1 101 '):
                            raise ValueError('WebSocket upgrade failed: ' + repr(status[:200]))
                        headers = {}
                        for _ in range(64):
                            line = reader.readline(8193)
                            if line == b'\r\n':
                                break
                            if not line or len(line) > 8192 or b':' not in line:
                                raise ValueError('invalid upgrade header')
                            name, value = line.decode('ascii').split(':', 1)
                            name = name.lower()
                            if name in headers:
                                raise ValueError('duplicate upgrade header')
                            headers[name] = value.strip()
                        else:
                            raise ValueError('too many upgrade headers')
                        expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                        if (headers.get('sec-websocket-accept') != expected
                                or headers.get('upgrade', '').lower() != 'websocket'
                                or 'upgrade' not in headers.get('connection', '').lower().split(', ')):
                            raise ValueError('unverified WebSocket upgrade')
                        emit(event='stream_started', host=host, status=101, protocol='websocket_tls')
                        deadline = time.monotonic() + args.seconds

                        def payload(seq):
                            return f'blackice-a3-{host}-{seq}'.encode()

                        send_lock = threading.Lock()

                        def frame(opcode, body):
                            if len(body) > 125:
                                raise ValueError('fixture payload too long')
                            mask = os.urandom(4)
                            data = bytes((0x80 | opcode, 0x80 | len(body))) + mask
                            data += bytes(b ^ mask[i % 4] for i, b in enumerate(body))
                            with send_lock:
                                tls.sendall(data)

                        def send():
                            seq = 0
                            try:
                                while not done.is_set() and not stop.is_set() and time.monotonic() < deadline:
                                    frame(1, payload(seq))
                                    seq += 1
                                    done.wait(0.05)
                            except OSError:
                                pass  # The receiver records the connection's terminal result.
                            finally:
                                if not done.is_set():
                                    try:
                                        tls.shutdown(socket.SHUT_RDWR)
                                    except OSError:
                                        pass

                        def exact(size):
                            data = reader.read(size)
                            if len(data) != size:
                                raise EOFError('WebSocket connection ended')
                            return data

                        sender = threading.Thread(target=send, daemon=True)
                        sender.start()
                        try:
                            while not stop.is_set() and time.monotonic() < deadline:
                                first, second = exact(2)
                                if first & 0x70 or not first & 0x80 or second & 0x80:
                                    raise ValueError('unexpected fragmented, compressed or masked server frame')
                                size = second & 0x7f
                                if size == 126:
                                    size = int.from_bytes(exact(2), 'big')
                                elif size == 127:
                                    size = int.from_bytes(exact(8), 'big')
                                if size > 65536:
                                    raise ValueError('oversized server frame')
                                body = exact(size)
                                opcode = first & 0x0f
                                if opcode == 9:
                                    frame(10, body)
                                elif opcode == 1 and body == payload(messages):
                                    messages += 1
                                    total += len(body)
                                    emit(event='stream_progress', host=host, total=total, messages=messages)
                                else:
                                    raise ValueError('unexpected WebSocket response')
                        finally:
                            done.set()
                            sender.join(timeout=6)
        except Exception as exc:
            error = type(exc).__name__ + ': ' + str(exc)
        timed_out = deadline != 0 and time.monotonic() >= deadline
        emit(event='stream_ended', host=host, total=total, messages=messages,
             error=error, cancelled=stop.is_set(), deadline_reached=timed_out)
        return args.direct and timed_out and messages >= 3 and not stop.is_set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(stream, host, path) for host, path in ENDPOINTS.items()]
        results = [job.result() for job in jobs]
    if args.direct and not all(results):
        raise SystemExit('FAIL: both direct WebSocket controls must echo at least three messages')


if __name__ == '__main__':
    main()
