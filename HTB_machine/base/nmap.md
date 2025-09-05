```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.129.243.139 -vv       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-26 18:14 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:14
Completed NSE at 18:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:14
Completed NSE at 18:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:14
Completed NSE at 18:14, 0.00s elapsed
Initiating Ping Scan at 18:14
Scanning 10.129.243.139 [4 ports]
Completed Ping Scan at 18:14, 0.26s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:14
Completed Parallel DNS resolution of 1 host. at 18:14, 0.16s elapsed
Initiating SYN Stealth Scan at 18:14
Scanning 10.129.243.139 [1000 ports]
Discovered open port 22/tcp on 10.129.243.139
Discovered open port 80/tcp on 10.129.243.139
Completed SYN Stealth Scan at 18:15, 4.86s elapsed (1000 total ports)
Initiating Service scan at 18:15
Scanning 2 services on 10.129.243.139
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*\r\nServer: Virata-EmWeb/R([\d_]+)\r\nContent-Type: text/html; ?charset=UTF-8\r\nExpires: .*<title>HP (Color |)LaserJet ([\w._ -]+)&nbsp;&nbsp;&nbsp;'
Completed Service scan at 18:15, 7.04s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.129.243.139
Retrying OS detection (try #2) against 10.129.243.139
WARNING: OS didn't match until try #2
Initiating Traceroute at 18:15
Completed Traceroute at 18:15, 0.55s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 18:15
Completed Parallel DNS resolution of 2 hosts. at 18:15, 6.60s elapsed
NSE: Script scanning 10.129.243.139.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:15
Completed NSE at 18:15, 18.90s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:15
Completed NSE at 18:15, 2.23s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:15
Completed NSE at 18:15, 0.00s elapsed
Nmap scan report for 10.129.243.139
Host is up, received echo-reply ttl 63 (0.58s latency).
Scanned at 2025-08-26 18:14:56 IST for 52s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f6:5c:9b:38:ec:a7:5c:79:1c:1f:18:1c:52:46:f7:0b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQmgId8Z5lyLG718jzJ9KoLYQPuaKh/Z1++me8L01noJeFuv5RPeqgtoJSeWKcimm7Cw7q3HDUZEHL2LncJIad5v04ma8xgiAG+xUmiO+ntkOff06rtsEx51XRWrbuN4gcTxDCPQQyTJKnTAfleagTbtoWtPNvi82SzaaPyU88nhcn/72USczCeiVfRvawQCcAIHKqUnJzTGlSHAwd6Fj+4sq4CTw0MCrZSTG9JCQmyUVbCFJaF/AtQ0PDOQ/fVhZH8E7E+faAlJKWTYr2sIfQZmC7enT2W82zzWL/JRiQXgAzsI8B6JTJOl3gbmy3+rLY9H+1qztceYKaA8wjFT/5
|   256 65:0c:f7:db:42:03:46:07:f2:12:89:fe:11:20:2c:53 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA3Z4xQdzt1Zxsy5gdOFTrv3k9HtD0UppMhGWFIFWnHZgWAdONjTRzD/ZeiyGeDUgYWGGpQOzl74HXesdUhr+h0=
|   256 b8:65:cd:3f:34:d8:02:6a:e3:18:23:3e:77:dd:87:40 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINbQMzI8ONrv2TFdy0S8PtObPfizkmQ+217qx1pejwce
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome to Base
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=8/26%OT=22%CT=1%CU=41701%PV=Y%DS=2%DC=T%G=Y%TM=68ADAC7
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=102%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=9)OPS(O1=M569ST11NW7%O2=M569ST11
OS:NW7%O3=M569NNT11NW7%O4=M569ST11NW7%O5=M569ST11NW7%O6=M569ST11)WIN(W1=FE8
OS:8%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M56
OS:9NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y
OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
OS:=40%CD=S)

Uptime guess: 26.946 days (since Wed Jul 30 19:33:42 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   549.34 ms 10.10.16.1
2   255.42 ms 10.129.243.139

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:15
Completed NSE at 18:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:15
Completed NSE at 18:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:15
Completed NSE at 18:15, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.21 seconds
           Raw packets sent: 1170 (53.172KB) | Rcvd: 1156 (72.590KB)
```
