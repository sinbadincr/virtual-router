"""Drives underlay_corpus.py inside mvr-inj as a long-lived process (one scapy-free sender)."""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "underlay_corpus.py"


def corpus(target="cn2"):
    """[{name, reason, what, bytes}]; runs the script without sending anything."""
    out = subprocess.run([sys.executable, str(SCRIPT), "list", "--target", target], capture_output=True,
                         text=True, check=True).stdout
    return json.loads(out)


class Injector:
    def __init__(self, target="cn2"):
        self.proc = subprocess.Popen(["ip", "netns", "exec", "mvr-inj", sys.executable, str(SCRIPT), "serve",
                                      "--target", target], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline().strip()
        assert line == "READY", f"injector: {line!r} {self.proc.stderr.read() if self.proc.poll() else ''}"

    def send(self, name):
        self.proc.stdin.write(name + "\n")
        self.proc.stdin.flush()
        assert self.proc.stdout.readline().strip() == "DONE " + name

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
