from __future__ import annotations

import platform

from vod.collectors import LinuxCollector, MacOSCollector, WindowsCollector, collect_android_reports
from vod.models import ScanReport

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_host_collector():
    system = platform.system().lower()
    if system == "linux":
        return LinuxCollector()
    if system == "darwin":
        return MacOSCollector()
    if system == "windows":
        return WindowsCollector()
    return LinuxCollector()


def build_report() -> ScanReport:
    collector = build_host_collector()
    host_snapshot = collector.collect()
    android_reports, android_note = collect_android_reports()

    host_snapshot.findings.sort(key=lambda item: SEVERITY_ORDER.get(item.severity, 99))
    for device in android_reports:
        device.findings.sort(key=lambda item: SEVERITY_ORDER.get(item.severity, 99))

    return ScanReport(
        host=host_snapshot,
        android_reports=android_reports,
        android_note=android_note,
    )
