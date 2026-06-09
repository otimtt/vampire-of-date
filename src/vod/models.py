from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Finding:
    scope: str
    severity: str
    title: str
    evidence: str
    recommendation: str


@dataclass(slots=True)
class DeviceReport:
    name: str
    summary: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass(slots=True)
class HostSnapshot:
    platform: str
    summary: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    usb_devices: list[str] = field(default_factory=list)
    usb_note: str = ""


@dataclass(slots=True)
class ScanReport:
    host: HostSnapshot
    android_reports: list[DeviceReport] = field(default_factory=list)
    android_note: str = ""
