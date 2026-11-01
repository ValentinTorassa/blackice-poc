#!/usr/bin/env python3
"""Bounded HTTPS probe; invoke through the VM's listed executable launcher.

The numeric connect target is intentionally redirected by the app filter. TLS
still validates the named public host's certificate. No DNS or proxy environment
is used by this client. At most eight requests are in flight, scheduled at 20 Hz.
"""
import concurrent.futures
import json
import os
import signal
import socket
import ssl
import threading
import time

stop = threading.Event()
lock = threading.Lock()
context = ssl.create_default_context()
signal.signal(signal.SIGTERM, lambda *_: stop.set())


def emit(row):
    with lock:
        print(json.dumps(row), flush=True)


def request(sequence):
    host = ('example.com', 'github.com')[sequence % 2]
    row = {'event': 'web_attempt', 'sequence': sequence, 'pid': os.getpid(), 'host': host,
           'start_ns': time.monotonic_ns(), 'http_status': None, 'error': None}
    try:
        with socket.create_connection(('1.1.1.1', 443), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=host) as stream:
                stream.settimeout(3)
                stream.sendall(f'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
                line = bytearray()
                while b'\n' not in line and len(line) < 512:
                    chunk = stream.recv(1)
                    if not chunk:
                        break
                    line.extend(chunk)
                parts = bytes(line).split()
                if len(parts) < 2 or not parts[0].startswith(b'HTTP/'):
                    raise ValueError('no HTTP status line')
                row['http_status'] = int(parts[1])
    except (OSError, ValueError) as error:
        row['error'] = type(error).__name__
        row['errno'] = getattr(error, 'errno', None)
    row['end_ns'] = time.monotonic_ns()
    emit(row)


def main():
    emit({'event': 'web_started', 'pid': os.getpid()})
    sequence = 0
    skipped = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        pending = set()
        due = time.monotonic()
        while not stop.is_set():
            pending = {job for job in pending if not job.done()}
            if len(pending) < 8:
                pending.add(pool.submit(request, sequence))
                sequence += 1
            else:
                skipped += 1
            due += 0.05
            stop.wait(max(0, due - time.monotonic()))
    emit({'event': 'web_finished', 'attempts': sequence, 'backpressure_skipped': skipped})


if __name__ == '__main__':
    main()
