from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess

from vod.models import Finding, HostSnapshot


@dataclass(slots=True)
class CommandResult:
    code: int
    stdout: str
    stderr: str


def run_command(command: list[str], timeout: int = 10) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(1, "", str(exc))
    return CommandResult(
        completed.returncode,
        completed.stdout.strip(),
        completed.stderr.strip(),
    )


class HostCollector:
    platform_name = "unknown"

    def available(self, command: str) -> bool:
        return shutil.which(command) is not None

    def collect_usb_devices(self) -> tuple[list[str], str]:
        return [], "coleta USB nao implementada para este sistema"

    def collect(self) -> HostSnapshot:
        raise NotImplementedError

    def read_text(self, path: str) -> str:
        file_path = Path(path)
        if not file_path.exists():
            return ""
        return file_path.read_text(encoding="utf-8", errors="ignore")


def make_finding(
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
    scope: str = "host",
) -> Finding:
    return Finding(
        scope=scope,
        severity=severity,
        title=title,
        evidence=evidence,
        recommendation=recommendation,
    )
