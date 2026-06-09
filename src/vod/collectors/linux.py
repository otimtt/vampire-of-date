from __future__ import annotations

import os
from pathlib import Path

from vod.collectors.base import HostCollector, make_finding, run_command
from vod.models import Finding, HostSnapshot

EXPOSED_PORTS = {
    22: "SSH exposto",
    80: "HTTP exposto",
    443: "HTTPS exposto",
    3000: "Servidor dev exposto",
    3306: "MySQL exposto",
    5432: "PostgreSQL exposto",
    6379: "Redis exposto",
    8080: "Painel HTTP exposto",
}


class LinuxCollector(HostCollector):
    platform_name = "Linux"

    def collect(self) -> HostSnapshot:
        summary: list[str] = [self.parse_os_release()]
        findings: list[Finding] = []

        for collector in (
            self.check_firewall,
            self.check_ssh,
            self.check_listening_ports,
            self.check_package_updates,
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

    def parse_os_release(self) -> str:
        path = Path("/etc/os-release")
        if not path.exists():
            return "sistema operacional nao identificado"

        values: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
        pretty_name = values.get("PRETTY_NAME", "Linux")
        distro_id = values.get("ID", "desconhecido")
        return f"sistema: {pretty_name} ({distro_id})"

    def collect_usb_devices(self) -> tuple[list[str], str]:
        if not self.available("lsusb"):
            return [], "lsusb nao encontrado"
        result = run_command(["lsusb"])
        if result.code == 0 and result.stdout:
            return result.stdout.splitlines(), ""
        return [], result.stderr or "coleta USB indisponivel"

    def check_firewall(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        states: list[str] = []

        for service in ("ufw", "firewalld"):
            if not self.available("systemctl"):
                break
            result = run_command(["systemctl", "is-active", service])
            if result.code == 0 and result.stdout:
                states.append(f"{service}: {result.stdout}")

        if self.available("nft"):
            nft_result = run_command(["nft", "list", "ruleset"])
            if nft_result.code == 0 and nft_result.stdout:
                states.append("nftables: configurado")

        if not states:
            findings.append(
                make_finding(
                    "medium",
                    "Firewall local nao identificado como ativo",
                    "Nao foi detectado ufw, firewalld ou nftables ativos.",
                    "Ative um firewall local e revise regras para portas expostas.",
                )
            )
            return "firewall: inativo ou nao detectado", findings

        return f"firewall: {', '.join(states)}", findings

    def check_ssh(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        if not self.available("systemctl"):
            return "sshd: sem systemctl", findings

        result = run_command(["systemctl", "is-active", "sshd"])
        if result.code != 0:
            return "sshd: inativo", findings

        config = self.parse_sshd_config()
        permit_root_login = config.get("permitrootlogin", "unset").lower()
        password_auth = config.get("passwordauthentication", "unset").lower()

        if permit_root_login in {"yes", "prohibit-password", "without-password"}:
            findings.append(
                make_finding(
                    "high",
                    "SSH permite login de root",
                    f"PermitRootLogin={permit_root_login}",
                    "Desabilite login direto de root e use sudo a partir de uma conta comum.",
                )
            )
        if password_auth == "yes":
            findings.append(
                make_finding(
                    "medium",
                    "SSH aceita autenticacao por senha",
                    "PasswordAuthentication=yes",
                    "Prefira autenticacao por chave e reduza superficie para brute force.",
                )
            )
        return "sshd: ativo", findings

    def parse_sshd_config(self) -> dict[str, str]:
        config: dict[str, str] = {}
        content = self.read_text("/etc/ssh/sshd_config")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pieces = line.split(None, 1)
            if len(pieces) == 2:
                config[pieces[0].lower()] = pieces[1]
        return config

    def check_listening_ports(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        if not self.available("ss"):
            return "portas: ss nao encontrado", findings

        result = run_command(["ss", "-ltnH"])
        if result.code != 0:
            return "portas: indisponivel", findings

        exposed = 0
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            local_address = parts[3]
            host, _, port_text = local_address.rpartition(":")
            host = host.strip("[]")
            if not port_text.isdigit():
                continue
            if host in {"127.0.0.1", "::1"}:
                continue
            exposed += 1
            port = int(port_text)
            findings.append(
                make_finding(
                    "medium" if port in EXPOSED_PORTS else "low",
                    EXPOSED_PORTS.get(port, "Porta exposta fora do loopback"),
                    local_address,
                    "Confirme se essa escuta precisa ser publica e restrinja via firewall quando possivel.",
                )
            )
        return f"portas expostas: {exposed}", findings

    def check_package_updates(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        managers = (
            ("pacman", ["pacman", "-Qu"], "pacotes pendentes (pacman)"),
            ("apt", ["apt", "list", "--upgradable"], "pacotes pendentes (apt)"),
            ("dnf", ["dnf", "check-update"], "pacotes pendentes (dnf)"),
            ("zypper", ["zypper", "list-updates"], "pacotes pendentes (zypper)"),
        )

        for binary, command, label in managers:
            if not self.available(binary):
                continue
            result = run_command(command, timeout=20)
            if result.code not in {0, 1, 100}:
                return f"updates: indisponivel ({binary})", findings

            lines = [line for line in result.stdout.splitlines() if line.strip()]
            if binary == "apt" and lines:
                lines = lines[1:]
            if binary == "zypper" and len(lines) > 4:
                lines = lines[4:]
            pending = len(lines)
            if pending > 0:
                findings.append(
                    make_finding(
                        "medium" if pending < 25 else "high",
                        "Pacotes locais com atualizacao pendente",
                        f"{pending} item(ns) detectados por {binary}",
                        "Revise as atualizacoes pendentes e priorize navegador, kernel, OpenSSL e componentes de rede.",
                    )
                )
            return f"{label}: {pending}", findings

        return "updates: nenhum gerenciador suportado detectado", findings

    def check_path_permissions(self) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        risky: list[str] = []
        for item in os.environ.get("PATH", "").split(":"):
            if not item:
                continue
            path = Path(item)
            try:
                mode = path.stat().st_mode
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
                    "Remova permissao global de escrita ou tire o diretorio do PATH.",
                )
            )
        return f"path suspeito: {len(risky)}", findings
