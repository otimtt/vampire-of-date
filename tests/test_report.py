from __future__ import annotations

from vod.models import HostSnapshot
from vod.scanner import build_report


def test_build_report_returns_expected_shape() -> None:
    report = build_report()

    assert isinstance(report.host, HostSnapshot)
    assert isinstance(report.host.summary, list)
    assert isinstance(report.host.findings, list)
    assert isinstance(report.android_reports, list)
