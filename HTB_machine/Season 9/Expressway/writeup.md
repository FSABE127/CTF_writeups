```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.10.11.87 -vv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-21 11:58 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
Initiating Ping Scan at 11:58
Scanning 10.10.11.87 [4 ports]
Completed Ping Scan at 11:58, 0.45s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:58
Completed Parallel DNS resolution of 1 host. at 11:58, 0.04s elapsed
Initiating SYN Stealth Scan at 11:58
Scanning 10.10.11.87 [1000 ports]
Discovered open port 22/tcp on 10.10.11.87
Completed SYN Stealth Scan at 11:58, 5.97s elapsed (1000 total ports)
Initiating Service scan at 11:58
Scanning 1 service on 10.10.11.87
Completed Service scan at 11:58, 1.33s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 10.10.11.87
Initiating Traceroute at 11:58
Completed Traceroute at 11:58, 0.71s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 11:58
Completed Parallel DNS resolution of 2 hosts. at 11:59, 6.67s elapsed
NSE: Script scanning 10.10.11.87.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 21.81s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
Nmap scan report for 10.10.11.87
Host is up, received echo-reply ttl 63 (0.54s latency).
Scanned at 2025-09-21 11:58:40 IST for 43s
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/21%OT=22%CT=1%CU=35588%PV=Y%DS=2%DC=T%G=Y%TM=68CF9B4
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M569ST11NW9%O2=M569ST11NW9%O3=M569NNT11NW9%O4=M569ST11NW9%O5=M569ST1
OS:1NW9%O6=M569ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M569NNSNW9%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 46.158 days (since Wed Aug  6 08:11:13 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   705.39 ms 10.10.16.1
2   322.77 ms 10.10.11.87

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.47 seconds
           Raw packets sent: 1144 (51.154KB) | Rcvd: 1131 (46.002KB)
```
---
```bash
