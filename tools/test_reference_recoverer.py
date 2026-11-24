#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


class RecovererTest:
    def __init__(self, cpcp):
        self.cpcp = Path(cpcp).resolve()
        self.script = Path(__file__).parent / "reference-recoverer" / "cpcp_recover.py"
        self.temp = tempfile.TemporaryDirectory(prefix="cpcp-reference-")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.source = self.root / "source"
        self.password = self.root / "password.txt"
        self.password.write_text("test password\n", encoding="utf-8")
        os.chmod(self.password, 0o600)
        (self.source / "sub").mkdir(parents=True)
        (self.source / "empty.txt").write_bytes(b"")
        (self.source / "a.txt").write_bytes(b"hello")
        (self.source / "duplicate.txt").write_bytes(b"hello")
        (self.source / "sub" / "b.txt").write_bytes(b"world")
        os.symlink("a.txt", self.source / "link.txt")
        self.run(self.cpcp, "repo", "init", str(self.repo),
                 "--password-file", str(self.password),
                 "--kdf-memory", "8MiB", "--kdf-iterations", "1",
                 "--chunk-size", "1MiB")
        self.run(self.cpcp, "backup", "add", str(self.source),
                 "--repo", str(self.repo), "--password-file", str(self.password))

    def run(self, *args, expected=0):
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != expected:
            raise AssertionError(
                f"command returned {result.returncode}, expected {expected}: "
                f"{' '.join(map(str, args))}\n{result.stderr}"
            )
        return result

    def recover(self, destination, password=None, expected=0):
        return self.run(
            sys.executable,
            str(self.script),
            "--repo", str(self.repo),
            "--to", str(destination),
            "--password-file", str(password or self.password),
            expected=expected,
        )

    def close(self):
        self.temp.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cpcp", required=True)
    args = parser.parse_args()
    test = RecovererTest(args.cpcp)
    try:
        restored = test.root / "restored"
        test.recover(restored)
        for relative in ("a.txt", "duplicate.txt", "empty.txt", "sub/b.txt"):
            assert (restored / "source" / relative).read_bytes() == (test.source / relative).read_bytes(), relative
        assert os.readlink(restored / "source" / "link.txt") == "a.txt"

        recovery_result = test.run(
            test.cpcp, "repo", "key", "add-recovery-key",
            "--repo", str(test.repo), "--password-file", str(test.password),
            "--show-key", "--json"
        )
        recovery = test.root / "recovery.txt"
        recovery.write_text(json.loads(recovery_result.stdout)["recovery_key"] + "\n", encoding="utf-8")
        os.chmod(recovery, 0o600)
        test.run(
            test.cpcp, "repo", "rotate-epoch",
            "--repo", str(test.repo), "--password-file", str(test.password)
        )
        multi_slot = test.root / "multi-slot-restored"
        test.recover(multi_slot, recovery)
        assert (multi_slot / "source" / "a.txt").read_bytes() == b"hello"

        wrong = test.root / "wrong-password.txt"
        wrong.write_text("wrong password\n", encoding="utf-8")
        os.chmod(wrong, 0o600)
        test.recover(test.root / "wrong", wrong, expected=5)

        chunk = next((test.repo / "chunks").glob("*/*/*"))
        with chunk.open("r+b") as stream:
            stream.seek(-1, os.SEEK_END)
            value = stream.read(1)
            stream.seek(-1, os.SEEK_END)
            stream.write(bytes([value[0] ^ 1]))
        test.recover(test.root / "tampered", expected=4)
        print("Independent reference recoverer tests passed")
    finally:
        test.close()


if __name__ == "__main__":
    main()
