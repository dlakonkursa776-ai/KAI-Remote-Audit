# Remote administration

KAI's custom agent intentionally does not expose an arbitrary shell. For legitimate
administration, enable Windows OpenSSH Server or PowerShell Remoting on the target
through Windows' normal administrative process, restrict firewall scope to the
management PC, use a dedicated least-privilege account, and retain command logs.
Do not enable passwordless or unauthenticated remote command execution.
