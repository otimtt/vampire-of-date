from __future__ import annotations

import curses
import textwrap

from .models import Finding
from .scanner import build_report

SCREEN_HOME = 0
SCREEN_REPORT = 1
TAB_HOST = 0
TAB_ANDROID = 1


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


def draw_home(stdscr, status_line: str) -> None:
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
    stdscr.addnstr(card_y + 5, card_x + 3, status_line, card_width - 6, curses.A_NORMAL)

    footer = "Enter comeca a auditoria   q sai"
    stdscr.addnstr(height - 2, center_x(width, footer), footer, max(1, width - 2), curses.A_DIM)


def run_tui(stdscr) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    stdscr.nodelay(False)
    stdscr.keypad(True)

    report = None
    screen = SCREEN_HOME
    status_line = "Pronto para iniciar."
    active_tab = TAB_HOST
    selected = 0

    while True:
        if screen == SCREEN_HOME:
            draw_home(stdscr, status_line)
            stdscr.refresh()
            key = stdscr.getch()

            if key in {ord("q"), ord("Q"), 27}:
                break
            if key in {10, 13, curses.KEY_ENTER, ord(" ")}:
                status_line = "Auditoria concluida."
                report = build_report()
                screen = SCREEN_REPORT
                active_tab = TAB_HOST
                selected = 0
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
        else:
            details = [
                "Nenhum achado nesta aba.",
                "",
                "No host, o VOD mostra sinais simples de exposicao local.",
                "Na aba Android, ele audita propriedades de hardening via adb.",
            ]

        detail_y = 7
        for line in details:
            if detail_y >= height - 1:
                break
            detail_y += draw_wrapped(stdscr, detail_y, right_x, right_width, line)

        stdscr.refresh()
        key = stdscr.getch()

        if key in {ord("q"), 27}:
            break
        if key in {ord("h"), ord("H")}:
            screen = SCREEN_HOME
            status_line = "Pronto para iniciar outro scan."
            continue
        if key in {ord("r"), ord("R")}:
            report = build_report()
            selected = 0
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
