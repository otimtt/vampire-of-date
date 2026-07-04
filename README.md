# Vampire Of Date (VOD)

Vampire Of Date (VOD) is a terminal-based defensive audit tool for local host hardening and Android devices connected over USB/`adb`

It scans the current machine, explains what it finds, and can optionally apply a small set of safe remediations after explicit confirmation
After each scan, VOD automatically opens a confirmation flow when fixable findings are available

## Highlights

- Interactive terminal UI with a scan-first flow
- Host audit on Linux, macOS, and Windows
- Android audit via `adb`
- Findings include severity, evidence, and remediation guidance
- Optional fix preview before changes are applied
- Post-remediation summary grouped by platform and status

## What It Checks

### Host

- Listening TCP ports
- Local firewall state
- SSH / remote-login exposure
- Pending package updates on supported Linux package managers
- Unsafe `PATH` permissions

### Android

- Authorized devices detected by `adb`
- `ro.secure`
- `ro.debuggable`
- `ro.adb.secure`
- Verified Boot state
- Bootloader lock state
- ADB over TCP
- Developer options
- App verifier status

## Supported Platforms

- Linux: most complete host coverage and Linux remediations
- macOS: native host checks with safe remediations
- Windows: PowerShell-based host checks with safe remediations
- Android: diagnostic audit only, no automatic remediation

## Safety Model

VOD is intentionally conservative

- it scans first and only then asks for confirmation
- it shows the exact actions before any change is made
- it only ships remediations that are narrowly scoped and explicit
- it does not scan remote networks or exploit vulnerabilities

## Requirements

- Python 3.11+
- A terminal that supports `curses`
- Optional tools depending on platform:
  - Linux: `ss`, `systemctl`, `lsusb`, `ufw` or `firewalld`
  - macOS: `systemsetup`, `system_profiler`, `lsof`
  - Windows: PowerShell
  - Android: `adb`

## Installation

### From source

```bash
git clone https://github.com/otimtt/vampire-of-date.git
cd vampire-of-date
pip install .
```

### Windows note

On Windows, use the `py` launcher if `python` is not on `PATH`

```powershell
py -m pip install .
```

## Running

### Local clone

```bash
vod
```

Or:

```bash
python -m vod
```

### Windows

```powershell
py -m vod
```

## Controls

- `Enter`: start scan
- remediation preview opens automatically after a scan when fixable findings exist
- `s` / `n`: confirm or cancel remediation
- `r`: rescan
- `Tab`: switch between Host and Android tabs
- `j` / `k`: move through findings
- `h`: go back to the home screen
- `q`: quit

## Project Structure

- `src/vod/collectors`: platform-specific collectors
- `src/vod/remediation.py`: remediation registry and handlers
- `src/vod/scanner.py`: report orchestration
- `src/vod/tui.py`: terminal UI
- `src/vod/cli.py`: CLI entry point
- `tests/`: smoke tests

## License

MIT
