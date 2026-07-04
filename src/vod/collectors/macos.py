from __future__ import annotations

import os
import platform

from vod.collectors.base import HostCollector, make_finding, run_command
from vod.models import Finding, HostSnapshot


class MacOSCollector(HostCollector):
    platform_name = "macOS"

    def collect(self) -> HostSnapshot:
        summary = [f"sistema: macOS {platform.mac_ver()[0] or 'desconhecido'}"]
        findings: list[Finding] = []

        for collector in (
            self.check_firewall,
            self.check_remote_login,
            self.check_listening_ports,
            self.check_path_permissions,
        ):
            line, collector_findings = collector()
            summary.append(line)
            findings.extend(collector_findings)

        usb_devices, usb_note = self.collect_usb_devices()
        return HostSnapshot(
            platform=self.platform_name,
            summary=summary,
            findings=findings,
            usb_devices=usb_devices,
            usb_note=usb_note,
        )

    def collect_usb_devices(self) -> tuple[list[str], str]:
        if not self.available("system_profiler"):
            return [], "system_profiler nao encontrado"
        result = run_command(["system_profiler", "SPUSBDataType"], timeout=20)
        if result.code == 0 and result.stdout:
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            return lines[:20], ""
        return [], result.stderr or "coleta USB indisponivel"

    def check_firewall(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        if not self.available("defaults"):
            return "firewall: defaults nao encontrado", findings

        result = run_command(
            [
                "defaults",
                "read",
                "/Library/Preferences/com.apple.alf",
                "globalstate",
            ]
        )
        if result.code != 0:
            return "firewall: estado indisponivel", findings
        if result.stdout != "1":
            findings.append(
                make_finding(
                    "medium",
                    "Firewall do macOS aparenta inativo",
                    f"globalstate={result.stdout or 'vazio'}",
                    "Ative o Application Firewall para reduzir exposicao local.",
                    fix_key="macos_firewall_enable",
                )
            )
        return f"firewall: estado {result.stdout or 'desconhecido'}", findings

    def check_remote_login(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        if not self.available("systemsetup"):
            return "remote login: systemsetup nao encontrado", findings
        result = run_command(["systemsetup", "-getremotelogin"])
        if result.code != 0:
            return "remote login: indisponivel", findings
        if "On" in result.stdout:
            findings.append(
                make_finding(
                    "low",
                    "Remote Login habilitado",
                    result.stdout,
                    "Desabilite o SSH remoto se ele nao for necessario.",
                    fix_key="macos_remote_login_disable",
                )
            )
        return f"remote login: {result.stdout or 'desconhecido'}", findings

    def check_listening_ports(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        if not self.available("lsof"):
            return "portas: lsof nao encontrado", findings

        result = run_command(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=20)
        if result.code != 0:
            return "portas: indisponivel", findings

        lines = result.stdout.splitlines()[1:]
        findings.extend(
            make_finding(
                "low",
                "Porta TCP em escuta",
                line,
                "Confirme se o servico precisa escutar em interfaces externas.",
            )
            for line in lines[:20]
        )
        return f"portas expostas: {len(lines)}", findings

    def check_path_permissions(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        risky = []
        for item in os.environ.get("PATH", "").split(":"):
            if not item:
                continue
            try:
                mode = os.stat(item).st_mode
            except OSError:
                continue
            if mode & 0o002:
                risky.append(item)
        if risky:
            findings.append(
                make_finding(
                    "high",
                    "Diretorio do PATH com escrita global",
                    ", ".join(risky),
                    "Revise permissoes do PATH para evitar trojanizacao local.",
                )
            )
        return f"path suspeito: {len(risky)}", findings
