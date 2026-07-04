from __future__ import annotations

import curses
import textwrap

from .models import Finding
from .remediation import apply_remediations, group_findings_by_platform, iter_fixable_findings, plan_remediations
from .scanner import build_report

SCREEN_HOME = 0
SCREEN_REPORT = 1
TAB_HOST = 0
TAB_ANDROID = 1

COLOR_DEFAULT = 1
COLOR_SCAN = 2
COLOR_WAIT = 3
COLOR_SUCCESS = 4
COLOR_ERROR = 5


def collect_tab_findings(report, active_tab: int) -> tuple[str, list[Finding], list[str]]:
    if active_tab == TAB_HOST:
        summary = list(report.host.summary)
        summary.append(f"plataforma: {report.host.platform}")
        summary.append(f"usb detectados: {len(report.host.usb_devices)}")
        if report.host.usb_note:
            summary.append(report.host.usb_note)
        else:
            summary.extend([f"usb: {line}" for line in report.host.usb_devices[:6]])
        return "Host", report.host.findings, summary

    findings: list[Finding] = []
    summary = [f"androids conectados: {len(report.android_reports)}"]
    if report.android_note:
        summary.append(report.android_note)
    for device in report.android_reports:
        summary.extend(device.summary)
        findings.extend(device.findings)
    return "Android USB", findings, summary


def severity_badge(severity: str) -> str:
    return {
        "critical": "[CRIT]",
        "high": "[HIGH]",
        "medium": "[MED ]",
        "low": "[LOW ]",
        "info": "[INFO]",
    }.get(severity, "[UNKN]")


def draw_wrapped(stdscr, start_y: int, start_x: int, width: int, text: str, attr: int = 0) -> int:
    lines = textwrap.wrap(text, max(10, width)) or [""]
    for offset, line in enumerate(lines):
        stdscr.addnstr(start_y + offset, start_x, line, width, attr)
    return len(lines)


def center_x(width: int, text: str) -> int:
    return max(0, (width - len(text)) // 2)


def prompt_yes_no(stdscr, message: str) -> bool:
    height, width = stdscr.getmaxyx()
    box_width = min(width - 4, max(50, len(message) + 12))
    box_x = max(2, (width - box_width) // 2)
    box_y = max(2, height // 2 - 2)
    stdscr.attron(curses.color_pair(COLOR_WAIT) | curses.A_BOLD)
    stdscr.addnstr(box_y, box_x, " " * box_width, box_width)
    stdscr.addnstr(box_y + 1, box_x, f"{message} [s/n]", box_width, curses.A_BOLD)
    stdscr.addnstr(box_y + 2, box_x, " " * box_width, box_width)
    stdscr.attroff(curses.color_pair(COLOR_WAIT) | curses.A_BOLD)
    stdscr.refresh()
    while True:
        key = stdscr.getch()
        if key in {ord("s"), ord("S"), ord("y"), ord("Y")}: 
            return True
        if key in {ord("n"), ord("N"), 27}: 
            return False


def draw_home(stdscr, status_line: str, phase_line: str, phase_color: int = COLOR_DEFAULT) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()

    hero = [
        "Vampire of Date (VOD)",
        "local host and android hardening scanner",
        "",
        "Escolha quando iniciar a auditoria.",
        "O scan nao comeca automaticamente.",
    ]
    start_y = max(2, height // 2 - 8)
    for offset, line in enumerate(hero):
        attr = curses.A_BOLD if offset == 0 else curses.A_DIM if offset == 1 else curses.A_NORMAL
        stdscr.addnstr(start_y + offset, center_x(width, line), line, max(1, width - 2), attr)

    card_width = min(64, width - 6)
    card_x = max(2, (width - card_width) // 2)
    card_y = start_y + 7

    stdscr.hline(card_y, card_x, curses.ACS_HLINE, card_width)
    stdscr.hline(card_y + 6, card_x, curses.ACS_HLINE, card_width)
    stdscr.vline(card_y, card_x, curses.ACS_VLINE, 7)
    stdscr.vline(card_y, card_x + card_width, curses.ACS_VLINE, 7)
    stdscr.addch(card_y, card_x, curses.ACS_ULCORNER)
    stdscr.addch(card_y, card_x + card_width, curses.ACS_URCORNER)
    stdscr.addch(card_y + 6, card_x, curses.ACS_LLCORNER)
    stdscr.addch(card_y + 6, card_x + card_width, curses.ACS_LRCORNER)

    stdscr.addnstr(card_y + 1, card_x + 3, "[ Enter ] Iniciar scan", card_width - 6, curses.A_REVERSE)
    stdscr.addnstr(card_y + 2, card_x + 3, "[ Q ] Sair", card_width - 6, curses.A_NORMAL)
    stdscr.addnstr(card_y + 4, card_x + 3, "O VOD verifica host, USB e Android via adb quando disponivel.", card_width - 6, curses.A_DIM)
    stdscr.addnstr(card_y + 5, card_x + 3, phase_line or status_line, card_width - 6, curses.color_pair(phase_color) | curses.A_BOLD)

    footer = "Enter comeca a auditoria   q sai"
    stdscr.addnstr(height - 2, center_x(width, footer), footer, max(1, width - 2), curses.A_DIM)


def build_preview_sections(planned: list[Finding]) -> dict[str, list[Finding]]:
    grouped = group_findings_by_platform(planned)
    ordered: dict[str, list[Finding]] = {}
    for platform in ("Windows", "Linux", "macOS", "Outros"):
        if platform in grouped:
            ordered[platform] = grouped[platform]
    return ordered


def render_remediation_preview(stdscr, planned: list[Finding], phase_line: str) -> bool:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    stdscr.addnstr(1, 2, "Confirmacao de correcao", width - 4, curses.A_BOLD)
    stdscr.addnstr(2, 2, phase_line, width - 4, curses.color_pair(COLOR_WAIT) | curses.A_BOLD)

    if not planned:
        stdscr.addnstr(4, 2, "Nenhuma correcao automatica disponivel.", width - 4, curses.A_NORMAL)
        stdscr.addnstr(height - 2, 2, "Pressione qualquer tecla para voltar.", width - 4, curses.A_DIM)
        stdscr.refresh()
        stdscr.getch()
        return False

    y = 4
    sections = build_preview_sections(planned)
    for platform, items in sections.items():
        if y >= height - 3:
            break
        stdscr.addnstr(y, 2, platform, width - 4, curses.A_BOLD)
        y += 1
        for finding in items:
            if y >= height - 3:
                break
            y += draw_wrapped(stdscr, y, 2, width - 4, f"- {finding.title}")
            y += draw_wrapped(stdscr, y, 4, width - 6, f"Evidencia: {finding.evidence}", curses.A_DIM)
            y += draw_wrapped(stdscr, y, 4, width - 6, f"Acao: {finding.recommendation}")
        y += 1

    stdscr.addnstr(height - 2, 2, f"Aplicar {len(planned)} correcao(oes)? [s/n]", width - 4, curses.A_REVERSE)
    stdscr.refresh()
    return prompt_yes_no(stdscr, f"Aplicar {len(planned)} correcao(oes) agora?")


def render_remediation_summary(stdscr, results: list[str], phase_line: str, phase_color: int = COLOR_SUCCESS) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    stdscr.addnstr(1, 2, "Resumo de correcao", width - 4, curses.A_BOLD)
    stdscr.addnstr(2, 2, phase_line, width - 4, curses.color_pair(phase_color) | curses.A_BOLD)
    if not results:
        stdscr.addnstr(3, 2, "Nenhuma acao foi executada.", width - 4, curses.A_NORMAL)
    else:
        y = 3
        for line in results:
            if y >= height - 2:
                break
            y += draw_wrapped(stdscr, y, 2, width - 4, f"- {line}")
    stdscr.addnstr(height - 2, 2, "Pressione qualquer tecla para voltar ao relatorio.", width - 4, curses.A_DIM)
    stdscr.refresh()
    stdscr.getch()


def format_result_summary(results) -> list[str]:
    lines: list[str] = []
    counts: dict[str, int] = {}
    by_platform: dict[str, int] = {}
    for result in results:
        lines.append(f"{result.platform} | {result.title}: {result.status} - {result.details}")
        counts[result.status] = counts.get(result.status, 0) + 1
        by_platform[result.platform] = by_platform.get(result.platform, 0) + 1
    if results:
        lines.append("Por plataforma: " + ", ".join(f"{platform}={count}" for platform, count in sorted(by_platform.items())))
        lines.append("Por status: " + ", ".join(f"{status}={count}" for status, count in sorted(counts.items())))
    return lines


def draw_report_summary(stdscr, remediation_summary: list[str], auto_available: bool) -> None:
    height, width = stdscr.getmaxyx()
    start_y = max(1, height - len(remediation_summary) - 5)
    stdscr.hline(start_y - 1, 2, curses.ACS_HLINE, max(10, width - 4))
    stdscr.addnstr(start_y, 2, f"Correcoes automáticas: {'sim' if auto_available else 'nao'}", width - 4, curses.A_BOLD)
    y = start_y + 1
    if remediation_summary:
        for line in remediation_summary[-5:]:
            if y >= height - 1:
                break
            y += draw_wrapped(stdscr, y, 2, width - 4, line)
    else:
        stdscr.addnstr(y, 2, "Nenhuma correcao aplicada nesta sessao.", width - 4, curses.A_DIM)


def maybe_prompt_remediation(stdscr, report, phase_line: str) -> tuple[list[str], bool]:
    fixable = plan_remediations(iter_fixable_findings(report))
    if not fixable:
        return [], False
    if not render_remediation_preview(stdscr, fixable, phase_line):
        return [], True
    results = apply_remediations(fixable)
    summary = format_result_summary(results)
    render_remediation_summary(stdscr, summary, "Correcoes aplicadas com sucesso.", COLOR_SUCCESS)
    return summary, True


def init_colors() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(COLOR_DEFAULT, curses.COLOR_WHITE, -1)
    curses.init_pair(COLOR_SCAN, curses.COLOR_CYAN, -1)
    curses.init_pair(COLOR_WAIT, curses.COLOR_YELLOW, -1)
    curses.init_pair(COLOR_SUCCESS, curses.COLOR_GREEN, -1)
    curses.init_pair(COLOR_ERROR, curses.COLOR_RED, -1)


def run_tui(stdscr) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    init_colors()
    stdscr.nodelay(False)
    stdscr.keypad(True)

    report = None
    screen = SCREEN_HOME
    status_line = "Pronto para iniciar"
    phase_line = "Pronto para iniciar"
    phase_color = COLOR_DEFAULT
    active_tab = TAB_HOST
    selected = 0
    remediation_results: list[str] = []
    remediation_available = False

    while True:
        if screen == SCREEN_HOME:
            draw_home(stdscr, status_line, phase_line, phase_color)
            stdscr.refresh()
            key = stdscr.getch()

            if key in {ord("q"), ord("Q"), 27}:
                break
            if key in {10, 13, curses.KEY_ENTER, ord(" ")}:
                status_line = "Auditoria concluida"
                phase_line = "Escaneando host e dispositivos"
                phase_color = COLOR_SCAN
                draw_home(stdscr, status_line, phase_line, phase_color)
                stdscr.refresh()
                report = build_report()
                screen = SCREEN_REPORT
                active_tab = TAB_HOST
                selected = 0
                phase_line = "Verificando se ha correcoes automaticas"
                phase_color = COLOR_WAIT
                remediation_results, remediation_available = maybe_prompt_remediation(
                    stdscr,
                    report,
                    "Aplicando correcoes disponiveis...",
                )
                if remediation_results:
                    phase_line = "Correcoes aplicadas com sucesso"
                    phase_color = COLOR_SUCCESS
                elif remediation_available:
                    phase_line = "Correcao cancelada pelo usuario"
                    phase_color = COLOR_ERROR
                else:
                    phase_line = "Nenhuma correcao automatica disponivel"
                    phase_color = COLOR_DEFAULT
            continue

        stdscr.erase()
        height, width = stdscr.getmaxyx()
        left_width = max(40, width // 2 - 2)
        right_x = left_width + 2
        right_width = max(20, width - right_x - 1)

        title = "Vampire of Date (VOD)  host + android audit"
        footer = "q sair   h home   r rescan   Tab alterna   j/k navega"
        stdscr.addnstr(0, 2, title, width - 4, curses.A_BOLD)
        stdscr.addnstr(1, 2, footer, width - 4, curses.A_DIM)

        host_attr = curses.A_REVERSE if active_tab == TAB_HOST else curses.A_NORMAL
        android_attr = curses.A_REVERSE if active_tab == TAB_ANDROID else curses.A_NORMAL
        stdscr.addnstr(3, 2, " Host ", 10, host_attr)
        stdscr.addnstr(3, 10, " Android USB ", 16, android_attr)

        tab_name, findings, summary = collect_tab_findings(report, active_tab)
        selected = min(selected, max(0, len(findings) - 1))

        y = 5
        stdscr.addnstr(y, 2, f"Resumo: {tab_name}", left_width - 2, curses.A_BOLD)
        y += 1
        for line in summary:
            if y >= height - 2:
                break
            y += draw_wrapped(stdscr, y, 2, left_width - 2, f"- {line}")

        list_y = y + 1
        if list_y < height - 1:
            stdscr.addnstr(list_y, 2, "Achados", left_width - 2, curses.A_BOLD)
            list_y += 1

        visible_rows = max(1, height - list_y - 2)
        top_index = 0
        if selected >= visible_rows:
            top_index = selected - visible_rows + 1

        for row, finding in enumerate(findings[top_index : top_index + visible_rows]):
            index = top_index + row
            attr = curses.A_REVERSE if index == selected else curses.A_NORMAL
            line = f"{severity_badge(finding.severity)} {finding.title}"
            stdscr.addnstr(list_y + row, 2, line, left_width - 2, attr)

        stdscr.vline(4, left_width, curses.ACS_VLINE, max(0, height - 5))
        stdscr.addnstr(5, right_x, "Detalhes", right_width, curses.A_BOLD)

        if findings:
            current = findings[selected]
            details = [
                f"Escopo: {current.scope}",
                f"Severidade: {current.severity}",
                "",
                f"Titulo: {current.title}",
                "",
                f"Evidencia: {current.evidence}",
                "",
                f"Recomendacao: {current.recommendation}",
            ]
            if current.fix_key:
                details.extend(["", "Correcoes disponiveis aparecem automaticamente apos o scan."])
        else:
            details = [
                "Nenhum achado nesta aba.",
                "",
                "No host, o VOD mostra sinais simples de exposicao local.",
                "Na aba Android, ele audita propriedades de hardening via adb.",
            ]

        if remediation_results:
            details.extend(["", "Correcoes recentes:"])
            details.extend(remediation_results[-6:])

        detail_y = 7
        for line in details:
            if detail_y >= height - 1:
                break
            detail_y += draw_wrapped(stdscr, detail_y, right_x, right_width, line)

        draw_report_summary(stdscr, remediation_results, remediation_available)
        stdscr.addnstr(height - 1, 2, phase_line[:max(1, width - 4)], max(1, width - 4), curses.color_pair(phase_color) | curses.A_BOLD)
        stdscr.refresh()
        key = stdscr.getch()

        if key in {ord("q"), 27}:
            break
        if key in {ord("h"), ord("H")}:
            screen = SCREEN_HOME
            status_line = "Pronto para iniciar outro scan."
            phase_line = "Voltando ao painel inicial"
            phase_color = COLOR_DEFAULT
            continue
        if key in {ord("r"), ord("R")}:
            phase_line = "Reexecutando scan"
            phase_color = COLOR_SCAN
            draw_home(stdscr, status_line, phase_line, phase_color)
            stdscr.refresh()
            report = build_report()
            selected = 0
            phase_line = "Verificando se ha correcoes automaticas"
            phase_color = COLOR_WAIT
            remediation_results, remediation_available = maybe_prompt_remediation(
                stdscr,
                report,
                "Aplicando correcoes disponiveis...",
            )
            if remediation_results:
                phase_line = "Correcoes aplicadas com sucesso"
                phase_color = COLOR_SUCCESS
            elif remediation_available:
                phase_line = "Correcao cancelada pelo usuario"
                phase_color = COLOR_ERROR
            else:
                phase_line = "Nenhuma correcao automatica disponivel"
                phase_color = COLOR_DEFAULT
            continue
        if key in {9, curses.KEY_BTAB}:
            active_tab = TAB_ANDROID if active_tab == TAB_HOST else TAB_HOST
            selected = 0
            continue
        if key in {ord("j"), curses.KEY_DOWN} and selected < len(findings) - 1:
            selected += 1
        if key in {ord("k"), curses.KEY_UP} and selected > 0:
            selected -= 1


def main() -> None:
    curses.wrapper(run_tui)


if __name__ == "__main__":
    main()

