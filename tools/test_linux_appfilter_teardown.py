#!/usr/bin/python3
"""Exercise a redirected teardown copy as a normal user; every system command is mocked.

The production script is never executed. Only its EUID check and absolute paths are
rewritten. Bash control flow and the embedded preflight/archive Python stay intact.
No real account, service, mount, BPF object or installed file is accessed.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/linux-appfilter-teardown.sh"
TOOLS = {"python3", "getent", "stat", "systemctl", "mountpoint", "umount", "rm",
         "rmdir", "chown", "chmod", "userdel", "groupdel"}
PREFIXES = ("/etc/", "/run/", "/var/", "/usr/local/libexec/", "/usr/share/polkit-1/")

# Each mock subprocess persists its small account/mount model and command history.
# Python heredocs execute their actual code with fake pwd/chown, against redirected paths.
MOCK = r'''
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

base = Path(os.environ["BLACKICE_TEARDOWN_FIXTURE"])
assert base.name.startswith("blackice-teardown-unit-") and (base / "fixture-only").is_file()
root = base / "root"
state_path = base / "state.json"
state = json.loads(state_path.read_text())
command = Path(sys.argv[0]).name
args = sys.argv[1:]

def target(name):
    path = Path(name)
    assert path.is_absolute() and path.is_relative_to(root), name
    assert ".." not in path.parts, name
    return path

def record(action, **fields):
    with (base / "calls.jsonl").open("a") as log:
        log.write(json.dumps({"command": action, "args": args,
                             "marker": (root / "etc/blackice-appfilter/owner.json").exists(),
                             "account": state["account"], "group": state["group"], **fields}) + "\n")

def fail(when):
    failure = state.get("fail_once")
    if failure and failure["command"] == command and failure["when"] == when:
        if failure.get("contains", "") in " ".join(args):
            state["fail_once"] = None
            state_path.write_text(json.dumps(state))
            record("injected_failure", when=when)
            raise SystemExit(77)

record(command)
fail("before")
rc = 0
if command == "python3":
    assert args == ["-I", "-"]
    code = sys.stdin.read()
    def fake_chown(name, uid, gid, **kw):
        assert (uid, gid) == (0, 0) and kw.get("follow_symlinks") is False
        assert "/" not in name and "dir_fd" in kw
        record("archive_entry", name=name)
    with patch("pwd.getpwnam", return_value=SimpleNamespace(pw_uid=1001)), patch("os.chown", side_effect=fake_chown):
        exec(compile(code, "redirected-teardown-heredoc", "exec"), {"__name__": "__main__"})
elif command == "getent":
    assert args[0] in ("passwd", "group") and args[1] == "blackice-appfilter"
    exists = state["account" if args[0] == "passwd" else "group"]
    if exists:
        print("blackice-appfilter:x:1001:1001::/nonexistent:/usr/sbin/nologin")
    rc = 0 if exists else 2
elif command == "stat":
    assert args[:2] == ["-c", "%u:%g:%a"] and target(args[2]).is_file()
    print("0:0:644")
elif command == "systemctl":
    assert args in (["disable", "--now", "blackice-appfilter.socket"],
                    ["stop", "blackice-appfilter.service"],
                    ["stop", "blackice-appfilter-bpffs.service"], ["daemon-reload"])
elif command == "blackice-linux-appfilter":
    assert args == ["--teardown"]
    for name in ("state", "prog_conn4"):
        (root / "run/blackice-appfilter/bpf" / name).unlink(missing_ok=True)
    state["attached"] = False
elif command == "mountpoint":
    assert args[0] == "-q" and target(args[1]) == root / "run/blackice-appfilter/bpf"
    rc = 0 if state["mounted"] else 1
elif command == "umount":
    assert target(args[0]) == root / "run/blackice-appfilter/bpf"
    state["mounted"] = False
elif command == "rm":
    assert args[0] == "-f"
    for name in args[1:]:
        target(name).unlink(missing_ok=True)
elif command == "rmdir":
    for name in args:
        if name != "--":
            target(name).rmdir()
elif command == "chown":
    assert args[0] == "root:root" and target(args[1]) == root / "var/lib/blackice-appfilter"
elif command == "chmod":
    assert args[0] == "00700" and target(args[1]) == root / "var/lib/blackice-appfilter"
    target(args[1]).chmod(0o700)
elif command == "userdel":
    assert args == ["blackice-appfilter"] and state["account"]
    state["account"] = False
elif command == "groupdel":
    assert args == ["blackice-appfilter"] and state["group"]
    state["group"] = False
else:
    raise AssertionError("unmocked command: " + command)
state_path.write_text(json.dumps(state))
fail("after")
raise SystemExit(rc)
'''


@unittest.skipIf(os.geteuid() == 0, "offline teardown fixtures must run as an unprivileged user")
class TeardownTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="blackice-teardown-unit-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir()
        (self.base / "fixture-only").write_text("mock commands only\n")
        self.state_path = self.base / "state.json"
        self.state_path.write_text(json.dumps({"account": True, "group": True, "mounted": True, "attached": True}))
        self.marker = self.file("/etc/blackice-appfilter/owner.json", json.dumps({"version": 1, "service_uid": 1001}))
        self.receipt = self.file("/var/lib/blackice-appfilter/receipt-test.jsonl", '{"event":"fixture"}\n')
        for name in ("state", "prog_conn4"):
            self.file("/run/blackice-appfilter/bpf/" + name)
        for name in ("blackice-appfilter.service", "blackice-appfilter.socket", "blackice-appfilter-bpffs.service"):
            self.file("/etc/systemd/system/" + name)
        self.file("/usr/share/polkit-1/actions/org.blackice.appfilter.policy")
        self.file("/usr/local/libexec/blackice-appfilter-bpffs")
        self.file("/usr/local/libexec/blackice-appfilter-stage/bundle.tar")

        mock = self.base / "mock.py"
        mock.write_text(f"#!{sys.executable} -I\n" + MOCK)
        mock.chmod(0o700)
        commands = self.base / "commands"
        commands.mkdir()
        for name in TOOLS:
            (commands / name).symlink_to(mock)
        self.binary = self.root / "usr/local/libexec/blackice-linux-appfilter"
        self.binary.symlink_to(mock)

        source = SCRIPT.read_text()
        original_guard = "[[ $EUID == 0 && $# == 0 ]]"
        self.assertEqual(source.count(original_guard), 1)
        source = source.replace(original_guard, f"[[ $EUID == {os.geteuid()} && $# == 0 ]]")
        found = set(re.findall(r"/usr/(?:bin|sbin)/([A-Za-z0-9_.-]+)", source))
        self.assertEqual(found, TOOLS, "new teardown command requires an explicit safe mock")
        for prefix in PREFIXES:
            source = source.replace(prefix, str(self.root) + prefix)
        source = re.sub(r"/usr/(?:bin|sbin)/([A-Za-z0-9_.-]+)", lambda m: str(commands / m[1]), source)
        # Refuse a new unredirected host path or absolute command rather than run it.
        for path in re.findall(r"(?<![A-Za-z0-9_./-])/[A-Za-z0-9_./-]+", source):
            self.assertTrue(path in ("/bin/bash", "/dev/null") or path.startswith(str(self.base) + "/"), path)
        self.copy = self.base / "teardown-fixture.sh"
        self.copy.write_text(source)
        self.env = {"PATH": str(commands), "BLACKICE_TEARDOWN_FIXTURE": str(self.base), "LC_ALL": "C"}

    def file(self, name, data="fixture\n"):
        path = self.root / name.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        return path

    def run_copy(self):
        return subprocess.run(["/bin/bash", str(self.copy)], env=self.env, cwd=self.base,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)

    def state(self):
        return json.loads(self.state_path.read_text())

    def calls(self):
        return [json.loads(row) for row in (self.base / "calls.jsonl").read_text().splitlines()]

    def arm_failure(self, command, when, contains=""):
        state = self.state()
        state["fail_once"] = {"command": command, "when": when, "contains": contains}
        self.state_path.write_text(json.dumps(state))

    def assert_complete(self):
        self.assertFalse(self.marker.exists())
        self.assertFalse((self.root / "etc/blackice-appfilter").exists())
        self.assertFalse((self.root / "run/blackice-appfilter").exists())
        self.assertFalse((self.root / "usr/local/libexec/blackice-appfilter-stage").exists())
        self.assertFalse(any(self.state()[key] for key in ("account", "group", "mounted", "attached")))
        self.assertEqual(self.receipt.read_text(), '{"event":"fixture"}\n')
        self.assertEqual(self.receipt.parent.stat().st_mode & 0o7777, 0o700)

    def test_unknown_policy_refuses_before_any_cleanup(self):
        extra = self.file("/etc/blackice-appfilter/demo.json", "keep me\n")
        before = self.state()
        result = self.run_copy()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unexpected configuration entries", result.stderr)
        self.assertEqual(self.state(), before)
        self.assertTrue(self.marker.exists() and self.binary.exists())
        self.assertEqual(extra.read_text(), "keep me\n")
        self.assertEqual([row["command"] for row in self.calls()], ["python3"])

    def test_teardown_completes_and_second_run_is_idempotent(self):
        for _ in range(2):
            result = self.run_copy()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_complete()
        removal = next(row for row in self.calls() if row["command"] == "rm" and str(self.marker) in row["args"])
        self.assertFalse(removal["account"] or removal["group"])

    def test_interruptions_keep_marker_until_accounts_are_removed_and_resume(self):
        for command, when, contains in (("blackice-linux-appfilter", "before", ""),
                                       ("blackice-linux-appfilter", "after", ""),
                                       ("rm", "after", "blackice-linux-appfilter"),
                                       ("rmdir", "before", "/run/blackice-appfilter/bpf"),
                                       ("userdel", "before", ""), ("groupdel", "before", "")):
            with self.subTest(command=command, when=when):
                self.setUp()
                self.arm_failure(command, when, contains)
                failed = self.run_copy()
                self.assertEqual(failed.returncode, 77, failed.stderr)
                self.assertTrue(self.marker.exists())
                resumed = self.run_copy()
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                self.assert_complete()

    def test_interruption_after_marker_removal_still_finishes(self):
        self.arm_failure("rm", "after", "/etc/blackice-appfilter/owner.json")
        failed = self.run_copy()
        self.assertEqual(failed.returncode, 77, failed.stderr)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.state()["account"] or self.state()["group"])
        resumed = self.run_copy()
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assert_complete()

    def test_missing_binary_with_pins_retains_marker_and_accounts(self):
        self.binary.unlink()
        failed = self.run_copy()
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("reviewed teardown binary is missing", failed.stderr)
        self.assertTrue(self.marker.exists())
        self.assertTrue(self.state()["account"] and self.state()["attached"])

    def test_unrecorded_account_is_never_deleted(self):
        self.marker.unlink()
        failed = self.run_copy()
        self.assertNotEqual(failed.returncode, 0)
        self.assertTrue(self.state()["account"])
        self.assertFalse(any(row["command"] == "userdel" for row in self.calls()))


if __name__ == "__main__":
    unittest.main()
