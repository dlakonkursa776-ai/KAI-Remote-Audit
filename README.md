# KAI Remote Audit — Windows x64 source

## Included in this implementation
- Native Windows one-file EXE packaging via PyInstaller (Python runtime bundled).
- Agent GUI with automatic UDP LAN discovery and recurring reports.
- Control Center GUI with TLS listener, certificate pinning, per-session random token,
  JSON report storage, report list, open/export controls.
- Six diagnostic groups: system, hardware, processes, network, installed software,
  Windows System event log.

## Build
Upload repository contents to GitHub. Open Actions → Build KAI Windows x64 →
Run workflow. Download artifact `KAI-Windows-x64`.

## Important operational/security notes
- This is a functional LAN-audit implementation, not a certified enterprise product.
  Validate it on isolated test machines before operational use.
- Agent and Control Center must be on the same LAN/VLAN; Windows Firewall must allow
  UDP 39571 and TCP 39572 between the two PCs.
- The agent window is visible and closing it stops collection. No service/autostart/
  stealth persistence is installed.
- First-run pairing is currently session-scoped: Control Center generates a random
  token and advertises it on the LAN; the agent pins the TLS certificate fingerprint
  from the discovery beacon. Use only on a trusted LAN. For hostile/shared LANs,
  add out-of-band pairing approval and encrypt/authenticate discovery itself.
- Event logs and some process/network details may require elevated rights; inaccessible
  data is omitted or marked unavailable.
- Remote CMD is deliberately not implemented as a custom command executor. Use
  Windows OpenSSH or PowerShell Remoting with named accounts, explicit authorization,
  firewall restrictions, and audit policy. KAI does not silently execute commands.
- No application can guarantee Windows Defender/SmartScreen will never warn about
  an unsigned self-built binary. Code signing requires a trusted signing certificate.
