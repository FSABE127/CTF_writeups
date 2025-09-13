# [Guardian] - [HTB]
**Difficulty:** [Hard]  
**OS:** [Linux]  
**Date:** []  

---

## 1. Summary
- **Objective:** [ ] Capture user flag  
- **Objective:** [ ] Capture root flag / administrator access  
- **Description / Notes:** [Brief overview of the machine, main services, challenges]  
- **Skills Practiced:** 
  - [ ] Enumeration
  - [ ] Web Exploitation
  - [ ] Binary Exploitation
  - [ ] Privilege Escalation
---

## 2. Recon & Enumeration

### 2.1 Network Scanning
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.10.11.84 -vv  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 08:07 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
Initiating Ping Scan at 08:07
Scanning 10.10.11.84 [4 ports]
Completed Ping Scan at 08:07, 0.31s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:07
Completed Parallel DNS resolution of 1 host. at 08:07, 0.06s elapsed
Initiating SYN Stealth Scan at 08:07
Scanning 10.10.11.84 [1000 ports]
Discovered open port 22/tcp on 10.10.11.84
Discovered open port 80/tcp on 10.10.11.84
Completed SYN Stealth Scan at 08:07, 2.73s elapsed (1000 total ports)
Initiating Service scan at 08:07
Scanning 2 services on 10.10.11.84
Completed Service scan at 08:07, 6.67s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.11.84
Initiating Traceroute at 08:07
Completed Traceroute at 08:07, 0.28s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 08:07
Completed Parallel DNS resolution of 2 hosts. at 08:07, 6.65s elapsed
NSE: Script scanning 10.10.11.84.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 7.03s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.82s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
Nmap scan report for 10.10.11.84
Host is up, received echo-reply ttl 63 (0.23s latency).
Scanned at 2025-09-13 08:07:32 IST for 27s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9c:69:53:e1:38:3b:de:cd:42:0a:c8:6b:f8:95:b3:62 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEtPLvoTptmr4MsrtI0K/4A73jlDROsZk5pUpkv1rb2VUfEDKmiArBppPYZhUo+Fopcqr4j90edXV+4Usda76kI=
|   256 3c:aa:b9:be:17:2d:5e:99:cc:ff:e1:91:90:38:b7:39 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHTkehIuVT04tJc00jcFVYdmQYDY3RuiImpFenWc9Yi6
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://guardian.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/13%OT=22%CT=1%CU=44471%PV=Y%DS=2%DC=T%G=Y%TM=68C4D90
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M577ST11NW7%O2=M577ST11NW7%O3=M577NNT11NW7%O4=M577ST11NW7%O5=M577ST1
OS:1NW7%O6=M577ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M577NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 29.209 days (since Fri Aug 15 03:06:57 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: _default_; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   272.95 ms 10.10.14.1
2   275.04 ms 10.10.11.84

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.37 seconds
           Raw packets sent: 1073 (48.094KB) | Rcvd: 1031 (42.034KB)
```
---

<img width="1919" height="914" alt="image" src="https://github.com/user-attachments/assets/76658989-a03e-4b5e-a10c-4b6b3d28f68a" />

---
```bash
┌──(sabeshan㉿kali)-[~]
└─$ ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://guardian.htb/ -H "Host: FUZZ.guardian.htb" -fw 20

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://guardian.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.guardian.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 20
________________________________________________

portal                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 417ms]
:: Progress: [4989/4989] :: Job [1/1] :: 202 req/sec :: Duration: [0:00:28] :: Errors: 0 ::
```
---

<img width="1435" height="591" alt="image" src="https://github.com/user-attachments/assets/e38b836f-3674-4edf-b25a-d280237fbc66" />

---

<img width="565" height="697" alt="image" src="https://github.com/user-attachments/assets/6ae2672f-03f9-4412-a327-7eb60b61b261" />

----

<img width="1919" height="852" alt="image" src="https://github.com/user-attachments/assets/b8ce7003-ad74-4d38-b7c3-51ac52175c5f" />

---

```bash
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~]
└─$ seq 1 20 > num.txt      
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~]
└─$ ffuf -u 'http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ1&chat_users[1]=FUZZ2' -w num.txt:FUZZ1 -w num.txt:FUZZ2 -mode clusterbomb -H 'Cookie: PHPSESSID=a1h9vl5qkeesaet8u206j9l40b' 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ1&chat_users[1]=FUZZ2
 :: Wordlist         : FUZZ1: /home/sabeshan/num.txt
 :: Wordlist         : FUZZ2: /home/sabeshan/num.txt
 :: Header           : Cookie: PHPSESSID=a1h9vl5qkeesaet8u206j9l40b
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 292ms]
    * FUZZ1: 18
    * FUZZ2: 2

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 291ms]
    * FUZZ1: 16
    * FUZZ2: 2

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 298ms]
    * FUZZ1: 16
    * FUZZ2: 1

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 299ms]
    * FUZZ1: 17
    * FUZZ2: 2

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 300ms]
    * FUZZ1: 12
    * FUZZ2: 1

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 307ms]
    * FUZZ1: 13
    * FUZZ2: 1

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 308ms]
    * FUZZ1: 15
    * FUZZ2: 1

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 309ms]
    * FUZZ1: 19
    * FUZZ2: 2

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 303ms]
    * FUZZ1: 11
    * FUZZ2: 1

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 292ms]
    * FUZZ1: 14
    * FUZZ2: 1

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 302ms]
    * FUZZ1: 18
    * FUZZ2: 1

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 287ms]
    * FUZZ1: 9
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 292ms]
    * FUZZ1: 7
    * FUZZ2: 3

[Status: 200, Size: 6859, Words: 2772, Lines: 178, Duration: 295ms]
    * FUZZ1: 4
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 295ms]
    * FUZZ1: 5
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 291ms]
    * FUZZ1: 8
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 295ms]
    * FUZZ1: 6
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 298ms]
    * FUZZ1: 3
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 289ms]
    * FUZZ1: 10
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 288ms]
    * FUZZ1: 11
    * FUZZ2: 3

[Status: 200, Size: 6847, Words: 2770, Lines: 178, Duration: 300ms]
    * FUZZ1: 2
    * FUZZ2: 3

[Status: 200, Size: 6838, Words: 2768, Lines: 178, Duration: 302ms]
    * FUZZ1: 1
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 299ms]
    * FUZZ1: 17
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 309ms]
    * FUZZ1: 20
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 311ms]
    * FUZZ1: 14
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 317ms]
    * FUZZ1: 13
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 305ms]
    * FUZZ1: 16
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 317ms]
    * FUZZ1: 15
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 300ms]
    * FUZZ1: 2
    * FUZZ2: 4

[Status: 200, Size: 6796, Words: 2763, Lines: 178, Duration: 302ms]
    * FUZZ1: 1
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 311ms]
    * FUZZ1: 19
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 312ms]
    * FUZZ1: 12
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 316ms]
    * FUZZ1: 18
    * FUZZ2: 3

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 293ms]
    * FUZZ1: 4
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 290ms]
    * FUZZ1: 10
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 292ms]
    * FUZZ1: 5
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 292ms]
    * FUZZ1: 9
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 293ms]
    * FUZZ1: 13
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 294ms]
    * FUZZ1: 12
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 295ms]
    * FUZZ1: 7
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 295ms]
    * FUZZ1: 8
    * FUZZ2: 4

[Status: 200, Size: 6853, Words: 2772, Lines: 178, Duration: 296ms]
    * FUZZ1: 6
    * FUZZ2: 4

[Status: 200, Size: 6859, Words: 2772, Lines: 178, Duration: 299ms]
    * FUZZ1: 3
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 291ms]
    * FUZZ1: 11
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 1308ms]
    * FUZZ1: 13
    * FUZZ2: 2

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 1309ms]
    * FUZZ1: 17
    * FUZZ2: 1

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 305ms]
    * FUZZ1: 15
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 299ms]
    * FUZZ1: 19
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 306ms]
    * FUZZ1: 16
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 299ms]
    * FUZZ1: 18
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 299ms]
    * FUZZ1: 1
    * FUZZ2: 5

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 310ms]
    * FUZZ1: 14
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 300ms]
    * FUZZ1: 17
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 301ms]
    * FUZZ1: 3
    * FUZZ2: 5

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 304ms]
    * FUZZ1: 20
    * FUZZ2: 4

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 304ms]
    * FUZZ1: 4
    * FUZZ2: 5

[Status: 200, Size: 6849, Words: 2769, Lines: 178, Duration: 303ms]
    * FUZZ1: 2
    * FUZZ2: 5

[Status: 200, Size: 5761, Words: 2176, Lines: 164, Duration: 212ms]
    * FUZZ1: 5
    * FUZZ2: 5

[Status: 200, Size: 6838, Words: 2768, Lines: 178, Duration: 211ms]
    * FUZZ1: 6
    * FUZZ2: 5

[WARN] Caught keyboard interrupt (Ctrl-C)
```
---
```bash                                                                                                                                                             
┌──(sabeshan㉿kali)-[~]
└─$ ffuf -u 'http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ1&chat_users[1]=FUZZ2' -w num.txt:FUZZ1 -w num.txt:FUZZ2 -mode clusterbomb -H 'Cookie: PHPSESSID=a1h9vl5qkeesaet8u206j9l40b' -fl 178,164

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ1&chat_users[1]=FUZZ2
 :: Wordlist         : FUZZ1: /home/sabeshan/num.txt
 :: Wordlist         : FUZZ2: /home/sabeshan/num.txt
 :: Header           : Cookie: PHPSESSID=a1h9vl5qkeesaet8u206j9l40b
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 178,164
________________________________________________

[Status: 200, Size: 7302, Words: 3055, Lines: 185, Duration: 3588ms]
    * FUZZ1: 1
    * FUZZ2: 2

[Status: 200, Size: 7306, Words: 3055, Lines: 185, Duration: 4610ms]
    * FUZZ1: 2
    * FUZZ2: 1

:: Progress: [400/400] :: Job [1/1] :: 144 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

---

<img width="1919" height="525" alt="image" src="https://github.com/user-attachments/assets/4ad446df-ece9-40cc-a671-f986641345c3" />

gitea: DHsNnk3V503 
---


