from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from vod.collectors.base import run_command
from vod.models import Finding, ScanReport


@dataclass(slots=True)
class RemediationResult:
    key: str
    title: str
    platform: str
    status: str
    details: str


RemediationHandler = Callable[[], RemediationResult]


def _powershell(script: str) -> tuple[int, str, str]:
    result = run_command(["powershell", "-NoProfile", "-Command", script], timeout=30)
    return result.code, result.stdout, result.stderr


def _shell(command: list[str], timeout: int = 30) -> tuple[int, str, str]:
    result = run_command(command, timeout=timeout)
    return result.code, result.stdout, result.stderr


def remediate_windows_firewall() -> RemediationResult:
    code, stdout, stderr = _powershell(
        "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; "
        "(Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table -HideTableHeaders | Out-String).Trim()"
    )
    if code == 0:
        return RemediationResult("windows_firewall_enable", "Windows Firewall", "Windows", "aplicado", stdout or "Firewall habilitado.")
    return RemediationResult("windows_firewall_enable", "Windows Firewall", "Windows", "falhou", stderr or stdout or "Nao foi possivel habilitar o firewall.")


def remediate_windows_ssh() -> RemediationResult:
    code, stdout, stderr = _powershell(
        "Stop-Service sshd -ErrorAction SilentlyContinue; "
        "Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue; "
        "$svc = Get-Service sshd -ErrorAction SilentlyContinue; "
        "if ($svc) { $svc.Status } else { 'sshd removido ou indisponivel' }"
    )
    if code == 0:
        return RemediationResult("windows_ssh_disable", "OpenSSH", "Windows", "aplicado", stdout or "Servico sshd desabilitado.")
    return RemediationResult("windows_ssh_disable", "OpenSSH", "Windows", "falhou", stderr or stdout or "Nao foi possivel desabilitar o sshd.")


def remediate_linux_firewall() -> RemediationResult:
    if run_command(["sh", "-lc", "command -v ufw >/dev/null 2>&1"], timeout=10).code == 0:
        code, stdout, stderr = _shell(["sudo", "ufw", "enable"], timeout=30)
        if code == 0:
            return RemediationResult("linux_firewall_enable", "Firewall local", "Linux", "aplicado", stdout or "ufw habilitado.")
        return RemediationResult("linux_firewall_enable", "Firewall local", "Linux", "falhou", stderr or stdout or "Nao foi possivel habilitar ufw.")
    if run_command(["sh", "-lc", "command -v systemctl >/dev/null 2>&1 && command -v firewall-cmd >/dev/null 2>&1"], timeout=10).code == 0:
        code, stdout, stderr = _shell(["sudo", "systemctl", "enable", "--now", "firewalld"], timeout=30)
        if code == 0:
            return RemediationResult("linux_firewall_enable", "Firewall local", "Linux", "aplicado", stdout or "firewalld habilitado.")
        return RemediationResult("linux_firewall_enable", "Firewall local", "Linux", "falhou", stderr or stdout or "Nao foi possivel habilitar firewalld.")
    return RemediationResult("linux_firewall_enable", "Firewall local", "Linux", "indisponivel", "Nenhum firewall local suportado foi encontrado.")


def remediate_linux_ssh() -> RemediationResult:
    code, stdout, stderr = _shell(["sudo", "systemctl", "disable", "--now", "sshd"], timeout=30)
    if code == 0:
        return RemediationResult("linux_ssh_disable", "sshd", "Linux", "aplicado", stdout or "sshd desabilitado.")
    return RemediationResult("linux_ssh_disable", "sshd", "Linux", "falhou", stderr or stdout or "Nao foi possivel desabilitar sshd.")


def remediate_linux_ssh_password() -> RemediationResult:
    script = r'''
python - <<'PY'
from pathlib import Path
cfg = Path('/etc/ssh/sshd_config')
text = cfg.read_text(encoding='utf-8', errors='ignore').splitlines()
out = []
replaced = False
for line in text:
    stripped = line.strip()
    if stripped and not stripped.startswith('#') and stripped.lower().startswith('passwordauthentication'):
        out.append('PasswordAuthentication no')
        replaced = True
    else:
        out.append(line)
if not replaced:
    out.append('PasswordAuthentication no')
cfg.write_text('\n'.join(out) + '\n', encoding='utf-8')
PY
'''
    code, stdout, stderr = _shell(["sudo", "sh", "-lc", script], timeout=30)
    if code == 0:
        restart_code, restart_out, restart_err = _shell(["sudo", "systemctl", "restart", "sshd"], timeout=30)
        if restart_code == 0:
            return RemediationResult("linux_ssh_password_disable", "SSH password auth", "Linux", "aplicado", "PasswordAuthentication definido como no e sshd reiniciado.")
        return RemediationResult("linux_ssh_password_disable", "SSH password auth", "Linux", "parcial", restart_err or restart_out or "Config atualizada, mas o restart falhou.")
    return RemediationResult("linux_ssh_password_disable", "SSH password auth", "Linux", "falhou", stderr or stdout or "Nao foi possivel atualizar sshd_config.")


def remediate_macos_firewall() -> RemediationResult:
    code, stdout, stderr = _shell(["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"], timeout=30)
    if code == 0:
        return RemediationResult("macos_firewall_enable", "Firewall do macOS", "macOS", "aplicado", stdout or "Application Firewall habilitado.")
    return RemediationResult("macos_firewall_enable", "Firewall do macOS", "macOS", "falhou", stderr or stdout or "Nao foi possivel habilitar o firewall.")


def remediate_macos_remote_login() -> RemediationResult:
    code, stdout, stderr = _shell(["sudo", "systemsetup", "-setremotelogin", "off"], timeout=30)
    if code == 0:
        return RemediationResult("macos_remote_login_disable", "Remote Login", "macOS", "aplicado", stdout or "Remote Login desabilitado.")
    return RemediationResult("macos_remote_login_disable", "Remote Login", "macOS", "falhou", stderr or stdout or "Nao foi possivel desabilitar Remote Login.")


REMEDIATIONS: dict[str, RemediationHandler] = {
    "windows_firewall_enable": remediate_windows_firewall,
    "windows_ssh_disable": remediate_windows_ssh,
    "linux_firewall_enable": remediate_linux_firewall,
    "linux_ssh_disable": remediate_linux_ssh,
    "linux_ssh_password_disable": remediate_linux_ssh_password,
    "macos_firewall_enable": remediate_macos_firewall,
    "macos_remote_login_disable": remediate_macos_remote_login,
}


def iter_fixable_findings(report: ScanReport) -> list[Finding]:
    findings = list(report.host.findings)
    for device in report.android_reports:
        findings.extend(device.findings)
    return [finding for finding in findings if finding.fix_key in REMEDIATIONS]


def plan_remediations(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    ordered: list[Finding] = []
    for finding in findings:
        if finding.fix_key in seen:
            continue
        if finding.fix_key not in REMEDIATIONS:
            continue
        ordered.append(finding)
        seen.add(finding.fix_key)
    return ordered


def platform_for_fix_key(fix_key: str) -> str:
    if fix_key.startswith("windows_"):
        return "Windows"
    if fix_key.startswith("linux_"):
        return "Linux"
    if fix_key.startswith("macos_"):
        return "macOS"
    return "Outros"


def group_findings_by_platform(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(platform_for_fix_key(finding.fix_key), []).append(finding)
    return grouped


def apply_remediations(findings: list[Finding]) -> list[RemediationResult]:
    results: list[RemediationResult] = []
    for finding in plan_remediations(findings):
        handler = REMEDIATIONS.get(finding.fix_key)
        if handler is None:
            continue
        results.append(handler())
    return results
