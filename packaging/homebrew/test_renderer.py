#!/usr/bin/env python3
"""Offline checks of release checksum parsing and platform pin selection."""
import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RENDER = ROOT / "scripts/release/brew-formula.sh"


def assets(version):
    return [
        f"blackice-{version}-{target}"
        for target in ("aarch64-macos", "x86_64-macos", "aarch64-linux", "x86_64-linux")
    ]


def manifest(version="1.2.3"):
    return "".join(
        hashlib.sha256(("synthetic fixture: " + name).encode()).hexdigest()
        + "  " + name + "\n"
        for name in assets(version)
    ).encode()


class RendererTests(unittest.TestCase):
    def render(self, data=None, version="1.2.3"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SHA256SUMS"
            path.write_bytes(manifest(version) if data is None else data)
            return subprocess.run(
                [str(RENDER), version, str(path)], capture_output=True, text=True
            )

    def rejected(self, data, message, version="1.2.3"):
        result = self.render(data, version)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn(message, result.stderr)

    def test_each_release_url_has_its_own_manifest_checksum(self):
        data = manifest()
        result = self.render(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        pairs = dict(re.findall(
            r'url "https://github.com/ValentinTorassa/blackice/releases/download/v1\.2\.3/([^"]+)",'
            r'\s+using: :nounzip\s+sha256 "([0-9a-f]{64})"', result.stdout
        ))
        expected = {
            line.split()[1]: line.split()[0] for line in data.decode().splitlines()
        }
        self.assertEqual(pairs, expected)
        self.assertNotIn("@@", result.stdout)
        self.assertEqual(result.stdout, self.render(data).stdout)

    def test_crlf_manifest_selects_the_same_cli_bytes(self):
        data = manifest().replace(b"\n", b"\r\n")
        result = self.render(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.render(manifest()).stdout)

    def test_current_release_manifest_does_not_require_scripts(self):
        data = manifest() + b"a" * 64 + b"  blackice-linux-helper-1.2.3-x86_64-linux\n"
        result = self.render(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.render(manifest()).stdout)

    def test_binary_marker_uppercase_hash_and_extra_asset(self):
        rows = manifest().decode().splitlines()
        rows[0] = rows[0][:64].upper() + " *" + rows[0][66:]
        data = ("\n".join(rows) + "\n" + "a" * 64 + "  LICENSE\n").encode()
        result = self.render(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("/LICENSE", result.stdout)

    def test_prereleases_are_rejected(self):
        for version in ["1.2.3-rc.1", "1.2.3-alpha", "1.2.3-0"]:
            with self.subTest(version=version):
                self.rejected(manifest(version), "version must be X.Y.Z", version)

    def test_no_helper_or_setup_resource_is_selected(self):
        extra = b"".join(b"a" * 64 + b"  " + name + b"\n" for name in [
            b"blackice-linux-helper-1.2.3-aarch64-linux",
            b"blackice-linux-helper-1.2.3-x86_64-linux",
            b"linux-setup.sh", b"linux-teardown.sh",
        ])
        for data in [manifest(), manifest() + extra]:
            result = self.render(data)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotRegex(result.stdout, r"(?m)^\s*resource\b")
            self.assertEqual(result.stdout, self.render(manifest()).stdout)

    def test_caveats_bind_manifest_to_tag_and_checkout_without_sudo(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotRegex(result.stdout, r"\bsudo\b")
        commands = [line.strip() for line in result.stdout.splitlines()
                    if line.strip().startswith("gh attestation verify ")]
        self.assertEqual(commands, [
            "gh attestation verify SHA256SUMS --repo ValentinTorassa/blackice"
            " --signer-workflow ValentinTorassa/blackice/.github/workflows/release.yml"
            ' --source-ref refs/tags/v1.2.3 --source-digest "$(git rev-parse HEAD)"'
            " --deny-self-hosted-runners"
        ])
        self.assertIn("sha256sum -c SHA256SUMS", result.stdout)
        self.assertIn("zig build -Doptimize=ReleaseSafe", result.stdout)
        self.assertIn("blackice-linux-helper-1.2.3-x86_64-linux entry", result.stdout)

    def test_missing_each_required_asset(self):
        rows = manifest().splitlines(keepends=True)
        for i, name in enumerate(assets("1.2.3")):
            with self.subTest(name=name):
                self.rejected(b"".join(rows[:i] + rows[i + 1:]), "missing checksum entries")

    def test_duplicate_and_conflicting_entries(self):
        first = manifest().splitlines(keepends=True)[0]
        for row in [first, b"0" * 64 + first[64:]]:
            self.rejected(manifest() + row, "duplicate checksum entry")

    def test_invalid_versions_cannot_inject_ruby_or_shell(self):
        for version in [
            "v1.2.3", "01.2.3", "1.2", "1.2.3+meta", "1.2.3-01", "",
            '1.2.3"; system("id")', "1.2.3/../../main", "1.2.3\nnext", "1.2.3-$(id)",
        ]:
            with self.subTest(version=version):
                self.rejected(manifest(), "version", version)

    def test_malformed_or_unsafe_manifest_fails_closed(self):
        for line in [
            b"a" * 63 + b"  file",
            b"g" * 64 + b"  file",
            b"a" * 64 + b"  ../file",
            b"a" * 64 + b"  /tmp/file",
            b"a" * 64 + b'  file";system("id")',
            b"a" * 64 + b"  file with spaces",
            b"a" * 64 + b"  file\x00",
            b"a" * 64 + b"  file\x0b",
        ]:
            with self.subTest(line=line):
                self.rejected(manifest() + line + b"\n", "invalid SHA256SUMS line")
        self.rejected(manifest() + b"a" * 64 + b"  SHA256SUMS\n", "must not contain")

    def test_size_and_encoding_limits(self):
        self.rejected(b"x" * (1024 * 1024 + 1), "exceeds 1 MiB")
        self.rejected(b"\xff", "ascii")

    def test_argument_errors_do_not_print_a_formula(self):
        result = subprocess.run([str(RENDER)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("Usage:", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
