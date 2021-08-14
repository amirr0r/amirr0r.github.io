---
title: HackTheBox - Grandpa
date: 2021-08-14 00:34:46 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [Microsoft IIS, WebDav, davtest, metasploit, meterpreter, suggester, MS14-070, htb-windows-easy, writeup, oscp-prep]
image: /assets/img/htb/machines/windows/easy/grandpa/Grandpa.png
---

## Enumeration

### `nmap` scan

The only open port is port 80, running **Microsoft IIS 6.0**

```bash
$ nmap -sU -oN UDP-scan.txt 10.10.10.14 &
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-13 21:55 CEST
Nmap scan report for 10.10.10.14
Host is up (0.10s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Date: Fri, 13 Aug 2021 20:19:10 GMT
|   WebDAV type: Unknown
|_  Server Type: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

I decided to perform an agressive scan and look for vulnerabilities with `nmap`:

```bash
$ nmap -vvv --script vuln -oN vuln-scan.txt 10.10.10.14
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /postinfo.html: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.dll: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.exe: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.dll: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.exe: Frontpage file or folder
|   /_vti_bin/fpcount.exe?Page=default.asp|Image=3: Frontpage file or folder
|   /_vti_bin/shtml.dll: Frontpage file or folder
|_  /_vti_bin/shtml.exe: Frontpage file or folder
| http-frontpage-login: 
|   VULNERABLE:
|   Frontpage extension anonymous login
|     State: VULNERABLE
|       Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
|       
|     References:
|_      http://insecure.org/sploits/Microsoft.frontpage.insecurities.html
|_http-iis-webdav-vuln: WebDAV is ENABLED. No protected folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path>
```

### Port 80 (Microsoft IIS 6.0)

**Microsoft IIS 6.0** is for **Windows Server 2003**:

![](/assets/img/htb/machines/windows/easy/grandpa/IIS_Versions.png)

#### `gobuster`

```bash
$ gobuster dir -u http://10.10.10.14 -w /usr/share/wordlists/seclists/Discovery/Web-Content/co
mmon.txt -x .txt -o services/80-http.txt

===============================================================
/Images               (Status: 301) [Size: 149] [--> http://10.10.10.14/Images/]
/_private             (Status: 403) [Size: 1529]
/_vti_bin             (Status: 301) [Size: 155] [--> http://10.10.10.14/%5Fvti%5Fbin/]
/_vti_cnf             (Status: 403) [Size: 1529]
/_vti_bin/shtml.dll   (Status: 200) [Size: 96]
/_vti_log             (Status: 403) [Size: 1529]
/_vti_bin/_vti_adm/admin.dll (Status: 200) [Size: 195]
/_vti_bin/_vti_aut/author.dll (Status: 200) [Size: 195]
/_vti_pvt             (Status: 403) [Size: 1529]
/_vti_txt             (Status: 403) [Size: 1529]
/aspnet_client        (Status: 403) [Size: 218]
/images               (Status: 301) [Size: 149] [--> http://10.10.10.14/images/]
===============================================================
```

#### `nikto`

```bash
$ nikto -h $TARGET -output services/80-nikto.txt
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    10.10.10.14
+ Target Port:        80
+ Start Time:         2021-08-13 22:11:52 (GMT2)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (PROPPATCH COPY UNLOCK MKCOL PROPFIND LOCK SEARCH listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
/_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 8015 requests: 0 error(s) and 27 item(s) reported on remote host
+ End Time:           2021-08-13 22:28:53 (GMT2) (1021 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

#### `davtest`

We saw earlier from the `nmap` scan that the target server is using the **WebDav** protocol and **HTTP PUT** method is allowed. This could potentially give us the ability to upload files.

We can check that with `davtest`:

```bash
$ davtest --url http://$TARGET
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.14
********************************************************
NOTE    Random string for this session: XVHfy6LGFmkc
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     pl      FAIL
PUT     cgi     FAIL
PUT     shtml   FAIL
PUT     php     FAIL
PUT     txt     FAIL
PUT     jsp     FAIL
PUT     jhtml   FAIL
PUT     html    FAIL
PUT     asp     FAIL
PUT     cfm     FAIL
PUT     aspx    FAIL

********************************************************
/usr/bin/davtest Summary:
```

Unfortunately, all tests failed.

## Exploitation

Assembling the pieces together, we can look for exploits using `metasploit`:

![](/assets/img/htb/machines/windows/easy/grandpa/msf.png)

Let's try this exploit on the web server:

![](/assets/img/htb/machines/windows/easy/grandpa/meterpreter.png)

Nice! Now let's try `post/multi/recon/local_exploit_suggester`:

![](/assets/img/htb/machines/windows/easy/grandpa/suggester.png)

The target appears to be vulnerable to multiple exploits.

Let's migrate to another process before and then run the exploit:

![](/assets/img/htb/machines/windows/easy/grandpa/SYSTEM.png)

BOUM! We are **SYSTEM**! This machine was a piece of cake, it was predictable because it's a very old server with known vulnerabilities that had patches available.

