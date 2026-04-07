# MacCrab v1.0.0

**Local-first macOS threat detection engine**

## Highlights

- 304 Sigma-compatible detection rules across 15 MITRE ATT&CK categories
- 5-tier detection: rules → sequences → ML → campaigns → cross-process correlation
- AI Guard: monitors 8 AI coding tools (Claude, Cursor, Copilot, Codex + more)
- Zero-entitlement kernel events via eslogger proxy
- Package freshness checking (npm, PyPI, Homebrew, Cargo)
- Ultrasonic attack detection (DolphinAttack, NUIT, SurfingAttack)
- On-device process tree ML (Markov chain anomaly detection)
- Natural language threat hunting
- Self-improving detection (auto rule generation from observed attacks)

## Requirements

- macOS 13 (Ventura) or later
- Root access (sudo) for the detection daemon
- Full Disk Access for Terminal (one-time setup for kernel events)

## Installation

### Homebrew (recommended)
```bash
brew install --cask maccrab
```

### Manual
1. Download `MacCrab-v1.0.0.dmg`
2. Open the DMG and run `install.sh`
3. Start the daemon: `sudo maccrabd`
4. Open the dashboard: `open /Applications/MacCrab.app`

## What's New

First public release.
