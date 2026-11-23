"""Background pingers for the failure tests: loss counted over a planned duration."""
import re
import subprocess
import threading

from conftest import VARIANT, run_lab


class Pinger:
    """ping src->dst every 100 ms for `seconds`; .join() returns the loss percentage."""

    def __init__(self, src, dst, seconds):
        self.src, self.dst, self.count = src, dst, int(seconds * 10)
        self.out = ""
        self.loss = None
        self.t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        sudo = "sudo " if VARIANT == "kvm" else ""
        cmd = f"{sudo}ping -c {self.count} -i 0.1 -W 1 {self.dst}"
        if VARIANT == "kvm":
            r = run_lab("ssh", self.src, cmd, timeout=self.count / 10 + 120)
        else:
            r = subprocess.run(["ip", "netns", "exec", f"mvr-{self.src}", "sh", "-c", cmd],
                               capture_output=True, text=True, timeout=self.count / 10 + 120)
        self.out = r.stdout
        m = re.search(r"(\d+(?:\.\d+)?)% packet loss", r.stdout)
        self.loss = float(m.group(1)) if m else 100.0

    def start(self):
        self.t.start()
        return self

    def join(self):
        self.t.join(timeout=self.count / 10 + 150)
        return self.loss
