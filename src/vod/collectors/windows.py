from __future__ import annotations

import os
import platform

from vod.collectors.base import HostCollector, make_finding, run_command
from vod.models import Finding, HostSnapshot


class WindowsCollector(HostCollector):
    platform_name = "Windows"

    def collect(self) -> HostSnapshot:
        summary = [f"sistema: Windows {platform.release()}"]
        findings: list[Finding] = []

        for collector in (
            self.check_firewall,
            self.check_open_ssh,
            self.check_listening_ports,
            self.check_path_permissions,
        ):
            line, collector_findings = collector()
            summary.append(line)
            findings.extend(collector_findings)

        return HostSnapshot(
            platform=self.platform_name,
            summary=summary,
            findings=findings,
            usb_devices=[],
            usb_note="coleta USB Windows ainda nao implementada",
        )

    def powershell(self, script: str) -> tuple[str, list[Finding]]:
        if not self.available("powershell"):
            return "", []
        result = run_command(["powershell", "-NoProfile", "-Command", script], timeout=20)
        return result.stdout, []

    def check_firewall(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        if not self.available("powershell"):
            return "firewall: powershell nao encontrado", findings
        result = run_command(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) -join ','",
            ]
        )
        if result.code != 0:
            return "firewall: indisponivel", findings
        if "False" in result.stdout:
            findings.append(
                make_finding(
                    "medium",
                    "Algum perfil do Windows Firewall esta desabilitado",
                    result.stdout,
                    "Ative o firewall em todos os perfis que fizerem sentido para o uso do equipamento.",
                )
            )
        return f"firewall: {result.stdout or 'desconhecido'}", findings

    def check_open_ssh(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        if not self.available("powershell"):
            return "OpenSSH: powershell nao encontrado", findings
        result = run_command(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Service sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status",
            ]
        )
        if result.code != 0 or not result.stdout:
            return "OpenSSH: nao detectado", findings
        if result.stdout.strip().lower() == "running":
            findings.append(
                make_finding(
                    "low",
                    "Servico OpenSSH em execucao",
                    "sshd status=Running",
                    "Confirme se o acesso remoto esta realmente necessario.",
                )
            )
        return f"OpenSSH: {result.stdout.strip()}", findings

    def check_listening_ports(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        if not self.available("powershell"):
            return "portas: powershell nao encontrado", findings
        result = run_command(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetTCPConnection -State Listen | Select-Object -First 20 LocalAddress,LocalPort | Format-Table -HideTableHeaders",
            ],
            timeout=20,
        )
        if result.code != 0:
            return "portas: indisponivel", findings
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        findings.extend(
            make_finding(
                "low",
                "Porta TCP em escuta",
                line,
                "Confirme se a escuta precisa estar disponivel para outras maquinas.",
            )
            for line in lines
        )
        return f"portas expostas: {len(lines)}", findings

    def check_path_permissions(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        path_items = [item for item in os.environ.get("PATH", "").split(";") if item]
        return f"path entries: {len(path_items)}", findings
