---
title: HackTheBox - Legacy
date: 2021-01-05 17:58:12 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [htb-windows-easy, samba, MS08-067, CVE-2008-4250, metasploit, meterpreter, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/windows/easy/legacy/Legacy.png
---

## Enumeration

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Legacy-full-port-scan.txt 10.10.10.4
Nmap scan report for 10.10.10.4
Host is up (0.12s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: -3h56m10s, deviation: 1h24m51s, median: -4h56m10s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:67:71 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-01-05T13:28:59+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

The target is a **Windows XP** server running **Samba**.

### smb (ports 139 & 445)

```bash
$ smbclient -L //10.10.10.4/ -U '%' | tee services/139-smbclient.txt
protocol negotiation failed: NT_STATUS_IO_TIMEOUT
$ smbmap -H $TARGET -R
[+] IP: 10.10.10.4:445  Name: 10.10.10.4
$
```

### `nmap` scan vuln

```bash
$ nmap -min-rate 5000 --max-retries 1 --script vuln -oN vuln-scan.txt 10.10.10.4
```

![nmap vuln scan](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/legacy/nmap-vuln-scan.png)

Two critical vulnerabilities allowing remote code execution affect our target machine:

- **MS08-067** (`CVE-2008-4250`) 
- **MS17-010** (`CVE-2017-0143`) 

## Exploitation

Both of these vulns can be exploited through Metasploit modules.

### Metasploit (exploiting MS08-067)

![msf](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/legacy/msf.png)

## SYSTEM user

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > pwd
C:\WINDOWS\system32
meterpreter > search -f user.txt
Found 1 result...
    c:\Documents and Settings\john\Desktop\user.txt (32 bytes)
meterpreter > cat C:\\Documents\ and\ Settings\\john\\Desktop\\user.txt
e69af0e4f443de7e36876fda4ec7644f
meterpreter > search -f root.txt
Found 1 result...
    c:\Documents and Settings\Administrator\Desktop\root.txt (32 bytes)
meterpreter > cat C:\\Documents\ and\ Settings\\Administrator\\Desktop\\root.txt
993442d258b0e0ec917cae9e695d5713
```
___

## Useful links

- [CVE-2008-4250](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250)
- [Microsoft Security Bulletin MS08-067 - Critical](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-067?redirectedfrom=MSDN)