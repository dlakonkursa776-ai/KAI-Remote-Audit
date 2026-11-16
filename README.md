# KAI Remote Audit — Windows x64 source

## Included
- `KAI_Control.exe`: Control Center with a saved-report history, search, computer/IP/time list,
  diagnostic tabs (summary, hardware, processes, network, software, Windows events), JSON export,
  and side-by-side text comparison of two selected reports.
- `KAI_Agent.exe`: diagnostic agent. By default it displays a small status window.
- Six diagnostic groups: system, hardware, processes, network, installed software,
  and Windows System event log.
- One-file EXE packaging through PyInstaller; Python runtime is bundled.

## Run
1. Start `KAI_Control.exe` on the management PC.
2. Start `KAI_Agent.exe` on the PC being audited. The default mode displays a status window.
3. The agent discovers the Control Center on the same LAN and sends a report initially,
   then every five minutes. The Control Center also loads reports already saved under
   `%LOCALAPPDATA%\\KAI\\reports` when it starts.
4. Select a report in the left list. Use the tabs to inspect its sections. Select exactly
   two reports with Ctrl/Shift-click and choose **Сравнить выбранные (2)** to compare them.

## Explicit headless launch
For a user who deliberately starts the agent from a command line and does not want its
status window, run:

`KAI_Agent.exe --headless`

This mode does not install a service, create an autorun entry, persist after reboot, or
provide a remote shell. It remains a normal running process until the user stops it in
Windows Task Manager (`KAI_Agent.exe`). The log is written to
`%LOCALAPPDATA%\\KAI\\agent.log`. Do not use this mode on a computer without its owner's
knowledge and authorization.

## Network and security notes
- Both PCs must be on a LAN/VLAN that allows UDP 39571 and TCP 39572 between them.
- The current pairing token and certificate fingerprint are announced over UDP discovery.
  This is suitable only for a trusted, isolated test LAN; it is not secure pairing against
  an attacker on a shared/untrusted network. Do not expose these ports to the internet.
- Reports can contain usernames, IP addresses, installed software, process names, network
  connection details, and Windows event information. Protect the report folder and exports.
- Event logs and some process/network details may require elevated rights; inaccessible
  data is omitted or marked unavailable.
- KAI deliberately does not execute arbitrary CMD/PowerShell commands remotely. For
  authorized administration, configure Windows OpenSSH Server or PowerShell Remoting
  separately with named accounts, explicit authorization, firewall restrictions, and logs.
- No application can guarantee Windows Defender/SmartScreen will never warn about an
  unsigned self-built binary. Code signing requires a trusted signing certificate.

## Build
Upload repository contents to GitHub. Open Actions → Build KAI Windows x64 → Run workflow.
Download artifact `KAI-Windows-x64`.


## Readable interface and connection states
The Control Center displays diagnostic values as readable Russian labels instead of raw JSON
in the main tabs. The activity area records startup, listener errors, incoming reports,
and successful saves. The Agent reports search, discovery, collection, sending, acceptance,
and retry/error states. The Full JSON tab remains available for technical troubleshooting.

## Important network limitation
This build does not bypass network restrictions. Both computers must be on a network where
the owner/admin has allowed UDP 39571 and TCP 39572 between them. Windows Firewall may block
these ports; allow the two executables only on the trusted Private network and only for the
local subnet, following the organization's policy. Do not expose these ports to the public
internet. The current discovery beacon sends its temporary token over UDP, so this version
is intended only for an isolated, trusted virtual lab and is not suitable for an open/shared
network. Use a properly authenticated VPN or a separately configured secure remote
administration service for networks you do not control.


## KAI interface theme
The Control Center uses a black and gold palette. Current connection state and
the action history are separate areas; the action history is bounded to the latest
100 entries so it does not crowd the dashboard. Diagnostic tabs use readable
Russian text and a consistent layout. The technical JSON tab remains available
for troubleshooting and export.


## Network tab presentation update
Network adapters and connections are now presented as readable entries with
friendly connection-state names and compact endpoint notation. The main report
text is white, gold is reserved for accents, and tab content uses a minimal
scrollbar without Windows arrow buttons.
