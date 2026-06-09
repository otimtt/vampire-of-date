from __future__ import annotations

import re
import shutil

from vod.collectors.base import run_command
from vod.models import DeviceReport, Finding


def adb_devices() -> tuple[list[str], str]:
    if shutil.which("adb") is None:
        return [], "adb nao encontrado"
    result = run_command(["adb", "devices"])
    if result.code != 0 or not result.stdout:
        return [], result.stderr or "ADB indisponivel ou sem permissao"

    devices: list[str] = []
    for line in result.stdout.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        pieces = line.split()
        if len(pieces) >= 2 and pieces[1] == "device":
            devices.append(pieces[0])
    if not devices:
        return [], "nenhum Android autorizado no adb"
    return devices, ""


def adb_shell(serial: str, command: str) -> str:
    result = run_command(["adb", "-s", serial, "shell", command], timeout=12)
    return result.stdout.strip() if result.code == 0 else ""


def android_report(serial: str) -> DeviceReport:
    report = DeviceReport(name=serial)
    brand = adb_shell(serial, "getprop ro.product.brand")
    model = adb_shell(serial, "getprop ro.product.model")
    android_version = adb_shell(serial, "getprop ro.build.version.release")
    patch_level = adb_shell(serial, "getprop ro.build.version.security_patch")
    verified_boot = adb_shell(serial, "getprop ro.boot.verifiedbootstate").lower()
    flash_locked = adb_shell(serial, "getprop ro.boot.flash.locked")
    ro_secure = adb_shell(serial, "getprop ro.secure")
    ro_debuggable = adb_shell(serial, "getprop ro.debuggable")
    adb_secure = adb_shell(serial, "getprop ro.adb.secure")
    adb_tcp = adb_shell(serial, "getprop service.adb.tcp.port")
    dev_settings = adb_shell(serial, "settings get global development_settings_enabled")
    verifier = adb_shell(serial, "settings get global package_verifier_enable")

    report.summary.extend(
        [
            f"dispositivo: {' '.join(piece for piece in (brand, model) if piece) or serial}",
            f"android: {android_version or 'desconhecido'}",
            f"patch: {patch_level or 'desconhecido'}",
            f"verified boot: {verified_boot or 'desconhecido'}",
        ]
    )

    if ro_secure == "0":
        report.findings.append(
            Finding(
                scope=serial,
                severity="critical",
                title="Android com ro.secure desabilitado",
                evidence="ro.secure=0",
                recommendation="Evite usar esse aparelho para dados sensiveis; a build parece insegura para uso comum.",
            )
        )
    if ro_debuggable == "1":
        report.findings.append(
            Finding(
                scope=serial,
                severity="high",
                title="Build Android debuggable",
                evidence="ro.debuggable=1",
                recommendation="Prefira firmware de producao sem modo debuggable.",
            )
        )
    if adb_secure == "0":
        report.findings.append(
            Finding(
                scope=serial,
                severity="high",
                title="ADB seguro desabilitado",
                evidence="ro.adb.secure=0",
                recommendation="Habilite autenticacao segura do ADB ou troque para uma build mais protegida.",
            )
        )
    if verified_boot and verified_boot != "green":
        report.findings.append(
            Finding(
                scope=serial,
                severity="high" if verified_boot in {"orange", "red"} else "medium",
                title="Verified Boot fora do estado verde",
                evidence=f"ro.boot.verifiedbootstate={verified_boot}",
                recommendation="Confirme se o bootloader e a cadeia de inicializacao continuam integras.",
            )
        )
    if flash_locked == "0":
        report.findings.append(
            Finding(
                scope=serial,
                severity="high",
                title="Bootloader aparenta desbloqueado",
                evidence="ro.boot.flash.locked=0",
                recommendation="Relock o bootloader se o objetivo for endurecer o aparelho.",
            )
        )
    if adb_tcp and adb_tcp not in {"", "-1", "0"}:
        report.findings.append(
            Finding(
                scope=serial,
                severity="high",
                title="ADB via rede habilitado",
                evidence=f"service.adb.tcp.port={adb_tcp}",
                recommendation="Desabilite ADB over TCP quando nao estiver em uso.",
            )
        )
    if dev_settings == "1":
        report.findings.append(
            Finding(
                scope=serial,
                severity="low",
                title="Opcoes de desenvolvedor habilitadas",
                evidence="development_settings_enabled=1",
                recommendation="Se o aparelho for de uso comum, considere desligar as opcoes de desenvolvedor.",
            )
        )
    if verifier == "0":
        report.findings.append(
            Finding(
                scope=serial,
                severity="medium",
                title="Verificador de apps desabilitado",
                evidence="package_verifier_enable=0",
                recommendation="Reative a verificacao de apps para reduzir risco de sideload inseguro.",
            )
        )
    if patch_level and not re.match(r"^\d{4}-\d{2}-\d{2}$", patch_level):
        report.findings.append(
            Finding(
                scope=serial,
                severity="low",
                title="Patch de seguranca com formato incomum",
                evidence=f"ro.build.version.security_patch={patch_level}",
                recommendation="Confira se a ROM expoe corretamente o nivel de patch.",
            )
        )

    return report


def collect_android_reports() -> tuple[list[DeviceReport], str]:
    serials, note = adb_devices()
    reports = [android_report(serial) for serial in serials]
    return reports, note
