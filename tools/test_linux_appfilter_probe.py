#!/usr/bin/python3
"""Offline fixture checks. Every socket constructor is replaced; no network or fork runs."""
import errno
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.dont_write_bytecode = True
path = Path(__file__).resolve().parents[1] / "scripts/e2e/linux-appfilter-probe.py"
spec = importlib.util.spec_from_file_location("appfilter_probe", path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeResultTests(unittest.TestCase):
    def run_send(self, expected, exception):
        args = SimpleNamespace(v4="192.0.2.1", v6="2001:db8::1", token="unit", phase="test", expect=expected)
        rows = []
        with patch.object(probe.socket, "socket", side_effect=exception), patch.object(probe, "emit", side_effect=lambda _event, **row: rows.append(row)):
            result = probe.send(args)
        self.assertEqual(len(rows), 6)
        return result, rows

    def test_permission_error_is_a_refusal_but_not_a_control(self):
        result, rows = self.run_send("deny", PermissionError(errno.EPERM, "test"))
        self.assertEqual(result, 0)
        self.assertTrue(all(row["passed"] for row in rows))
        self.assertEqual(self.run_send("control", PermissionError(errno.EPERM, "test"))[0], 1)

    def test_timeout_without_errno_never_counts_as_delivery_or_filtering(self):
        for expected in ("control", "deny"):
            result, rows = self.run_send(expected, TimeoutError("test"))
            self.assertEqual(result, 1)
            self.assertTrue(all(not row["passed"] for row in rows))

    def test_missing_route_never_counts_as_filtering(self):
        self.assertEqual(self.run_send("deny", OSError(errno.ENETUNREACH, "test"))[0], 1)

    def test_explicit_unicast_families_and_mapped_cases(self):
        self.assertEqual(probe.address("192.0.2.1", 4), "192.0.2.1")
        for value, family in (("0.0.0.0", 4), ("224.0.0.1", 4), ("::", 6), ("::1", 4)):
            with self.assertRaises(ValueError):
                probe.address(value, family)
        entries = probe.cases("192.0.2.1", "2001:db8::1")
        self.assertEqual(len({row[0] for row in entries}), 6)
        self.assertEqual(entries[4][3], ("::ffff:192.0.2.1", 47121))


class ProtocolControlTests(unittest.TestCase):
    def run_protocols(self, expected, failures, control_rows=None):
        args = SimpleNamespace(expect=expected, phase="unit", control_log="unit.jsonl")
        rows = []
        names = {entry[1:]: entry[0] for entry in probe.PROTOCOL_CASES}

        def socket_stub(family, kind, protocol):
            failure = failures.get(names[(family, kind, protocol)])
            if failure is not None:
                raise failure
            return MagicMock()

        data = b"" if control_rows is None else b"\n".join(json.dumps(row).encode() for row in control_rows)
        with patch.object(probe.socket, "socket", side_effect=socket_stub), \
                patch.object(probe.Path, "open", return_value=io.BytesIO(data)), \
                patch.object(probe, "emit", side_effect=lambda event, **row: rows.append({"event": event, **row})):
            result = probe.protocols(args)
        self.assertEqual(len(rows), len(probe.PROTOCOL_CASES) + 1)
        return result, rows

    def test_raw_permission_error_stays_a_limit_with_untagged_control(self):
        permission = PermissionError(errno.EPERM, "mock")
        status, control = self.run_protocols("control", {"raw4": permission})
        self.assertEqual(status, 0)
        self.assertEqual(control[-2]["verdict"], "LIMIT")
        self.assertIsNone(control[-2]["passed"])
        status, tagged = self.run_protocols("deny", {entry[0]: permission for entry in probe.PROTOCOL_CASES}, control)
        self.assertEqual(status, 0)
        self.assertEqual(tagged[-1], {"event": "protocol_summary", "expected": "deny", "passed": 5, "limited": 1, "failed": 0})
        self.assertEqual(tagged[-2]["case"], "raw4")
        self.assertIsNone(tagged[-2]["passed"])
        self.assertTrue(all(row["passed"] for row in tagged[:-2]))

    def test_all_unavailable_controls_are_not_a_passing_run(self):
        failures = {entry[0]: PermissionError(errno.EPERM, "mock") for entry in probe.PROTOCOL_CASES}
        status, control = self.run_protocols("control", failures)
        self.assertEqual(status, 2)
        status, tagged = self.run_protocols("deny", failures, control)
        self.assertEqual(status, 2)
        self.assertEqual(tagged[-1]["passed"], 0)
        self.assertEqual(tagged[-1]["limited"], 6)

    def test_unsupported_control_is_a_limit_and_cannot_prove_filtering(self):
        _, control = self.run_protocols("control", {"sctp4": OSError(errno.EPROTONOSUPPORT, "mock")})
        failures = {entry[0]: PermissionError(errno.EPERM, "mock") for entry in probe.PROTOCOL_CASES}
        _, tagged = self.run_protocols("deny", failures, control)
        row = next(row for row in tagged if row.get("case") == "sctp4")
        self.assertEqual(row["verdict"], "LIMIT")
        self.assertEqual(row["control_errno"], errno.EPROTONOSUPPORT)

    def test_unrelated_errors_do_not_count_as_refusals(self):
        for error in (TimeoutError("mock"), OSError(errno.ENETUNREACH, "mock")):
            with self.subTest(error=type(error).__name__):
                _, control = self.run_protocols("control", {})
                status, rows = self.run_protocols("deny", {entry[0]: error for entry in probe.PROTOCOL_CASES}, control)
                self.assertEqual(status, 1)
                self.assertEqual(rows[-1]["failed"], 6)
                control_status, control = self.run_protocols("control", {entry[0]: error for entry in probe.PROTOCOL_CASES})
                self.assertEqual(control_status, 1)
                status, rows = self.run_protocols("deny", {entry[0]: PermissionError(errno.EPERM, "mock") for entry in probe.PROTOCOL_CASES}, control)
                self.assertEqual(status, 1)
                self.assertEqual(rows[-1]["limited"], 0)

    def test_open_tagged_socket_is_a_failure_even_if_control_failed(self):
        failures = {entry[0]: PermissionError(errno.EPERM, "mock") for entry in probe.PROTOCOL_CASES}
        _, control = self.run_protocols("control", failures)
        status, rows = self.run_protocols("deny", {}, control)
        self.assertEqual(status, 1)
        self.assertEqual(rows[-1]["failed"], 6)

    def test_missing_control_refuses_before_socket_creation(self):
        args = SimpleNamespace(expect="deny", phase="unit", control_log=None)
        with patch.object(probe.socket, "socket") as opened:
            with self.assertRaises(ValueError):
                probe.protocols(args)
        opened.assert_not_called()

    def test_incomplete_duplicate_or_wrong_control_is_rejected(self):
        _, control = self.run_protocols("control", {})
        bad_logs = [control[1:], control + [control[0]],
                    [{**row, "expected": "deny"} for row in control],
                    [{**control[0], "protocol": 999}, *control[1:]],
                    [{**control[0], "errno": True}, *control[1:]],
                    [{k: v for k, v in control[0].items() if k != "errno"}, *control[1:]]]
        for rows in bad_logs:
            with self.subTest(rows=rows), patch.object(probe.Path, "open", return_value=io.BytesIO(b"\n".join(json.dumps(row).encode() for row in rows))):
                with self.assertRaises(ValueError):
                    probe.protocol_control("unit.jsonl")
        with patch.object(probe.Path, "open", return_value=io.BytesIO(b" " * 65537)):
            with self.assertRaises(ValueError):
                probe.protocol_control("unit.jsonl")


class VmGuardTests(unittest.TestCase):
    def test_wrong_host_non_vm_and_root_are_refused(self):
        for host, vendor, uid in (("host", "QEMU", 1000), ("test-vm", "Other", 1000), ("test-vm", "QEMU", 0)):
            with self.subTest(host=host, vendor=vendor, uid=uid), \
                    patch.object(probe.socket, "gethostname", return_value=host), \
                    patch.object(probe.Path, "read_text", return_value=vendor), \
                    patch.object(probe.os, "geteuid", return_value=uid):
                with self.assertRaises(ValueError):
                    probe.require_vm("test-vm")

    def test_named_unprivileged_qemu_guest_is_accepted(self):
        with patch.object(probe.socket, "gethostname", return_value="test-vm"), \
                patch.object(probe.Path, "read_text", return_value="QEMU\n"), \
                patch.object(probe.os, "geteuid", return_value=1000):
            probe.require_vm("test-vm")

    def test_runtime_guard_precedes_barriers_sockets_and_forks(self):
        argv = ["probe", "protocols", "--expect", "control", "--authorized-network-test", "--vm-hostname", "test-vm", "--double-fork"]
        with patch.object(sys, "argv", argv), \
                patch.object(probe, "require_vm", side_effect=ValueError("wrong VM")), \
                patch.object(probe, "wait_barrier") as barrier, \
                patch.object(probe.socket, "socket") as opened, \
                patch.object(probe.os, "fork") as fork:
            with self.assertRaises(ValueError):
                probe.main()
        barrier.assert_not_called()
        opened.assert_not_called()
        fork.assert_not_called()


if __name__ == "__main__":
    unittest.main()
