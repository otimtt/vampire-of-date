# Vampire Of Date (VOD)

Vampire Of Date (VOD) is a terminal-based defensive audit tool built to inspect the local host and Android devices connected through USB/`adb`.

It was designed to give a quick and practical security overview without changing system settings, exploiting vulnerabilities, or performing remote scans.

## What The Project Is For

VOD helps identify simple exposure points, weak configurations, and hardening gaps in the current machine and in authorized Android devices connected to it.

The project is useful for:

- checking the local host before daily use
- reviewing exposed services and basic security posture
- auditing connected Android devices through `adb`
- getting a fast defensive overview directly from the terminal

## Main Features

- Interactive terminal interface with a home screen and scan flow
- Host audit with platform-aware collectors
- USB device listing when supported by the host system
- Android security audit through `adb`
- Findings grouped with severity, evidence, and recommendation
- Separate tabs for host analysis and Android analysis

## Host Checks

- Listening TCP ports
- Local firewall status
- SSH or remote access exposure
- Pending package updates when a supported package manager is available
- PATH directories with unsafe permissions

## Android Checks

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

- Linux: main support and most complete host checks
- macOS: partial support with native host checks
- Windows: partial support through PowerShell-based host checks
- Android via `adb`: optional module reusable from any supported host

## Technologies Used

- Python 3.11+
- `curses` for the terminal user interface
- `subprocess` for system command execution
- `adb` for Android inspection
- Native system tools such as `ss`, `systemctl`, `lsusb`, and PowerShell

## Project Structure

- `src/vod/collectors`: collectors separated by operating system
- `src/vod/collectors/android.py`: Android audit module
- `src/vod/scanner.py`: report orchestration
- `src/vod/tui.py`: terminal interface
- `src/vod/cli.py`: CLI entry point
- `tests/`: basic smoke tests

## What VOD Does Not Do

- It does not exploit vulnerabilities
- It does not bypass protections
- It does not scan remote networks
- It does not change system settings automatically

## Requirements

- Python 3.11+
- A terminal compatible with `curses`
- Optional platform tools such as `ss`, `systemctl`, `lsusb`, `adb`, or PowerShell
- **Git** must be installed and available on your system (required for `pip install git+...`)

## Installation

### Linux / macOS

Install directly from GitHub:

```
pip install git+https://github.com/otimtt/vampire-of-date.git
```

Or clone the repository and install it locally:

```
git clone https://github.com/otimtt/vampire-of-date.git
cd vampire-of-date
pip install .
```

### Windows

On Windows, `python` and `pip` are not always registered in the system `PATH`, even when Python is installed correctly. To avoid `'pip' is not recognized` or `'python' is not recognized` errors, use the **`py` launcher** instead, which ships with the official Windows installer and is registered globally:

```powershell
py -m pip install git+https://github.com/otimtt/vampire-of-date.git
```

If this also fails, it usually means Python itself is not installed, or was installed without the launcher. Reinstall it from [python.org](https://www.python.org/downloads/windows/) and make sure the checkbox **"Add python.exe to PATH"** is checked during setup, then open a **new** terminal window.

On Windows, the package installs `windows-curses` automatically.

## Running

### Linux / macOS

```
vod
```

You can also run it as a module from a local clone:

```
python -m vod
```

### Windows

```powershell
py -m vod
```

If the `vod` / `vampire-of-date` commands are not recognized after installing (common when the Python `Scripts` folder isn't in `PATH`), always fall back to running it as a module with `py -m vod` — it works regardless of `PATH` configuration.

## Controls

- `Enter`: start the scan from the home screen
- `q`: quit
- `h`: go back to the home screen
- `r`: run the scan again
- `j` / `k`: navigate through findings
- `Tab`: switch between tabs
