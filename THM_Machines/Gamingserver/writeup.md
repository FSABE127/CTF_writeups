```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.201.67.16 -vv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-14 11:54 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
Initiating Ping Scan at 11:54
Scanning 10.201.67.16 [4 ports]
Completed Ping Scan at 11:54, 0.34s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:54
Completed Parallel DNS resolution of 1 host. at 11:54, 0.04s elapsed
Initiating SYN Stealth Scan at 11:54
Scanning 10.201.67.16 [1000 ports]
Discovered open port 22/tcp on 10.201.67.16
Discovered open port 80/tcp on 10.201.67.16
Increasing send delay for 10.201.67.16 from 0 to 5 due to 317 out of 792 dropped probes since last increase.
Increasing send delay for 10.201.67.16 from 5 to 10 due to 11 out of 26 dropped probes since last increase.
Completed SYN Stealth Scan at 11:54, 14.57s elapsed (1000 total ports)
Initiating Service scan at 11:54
Scanning 2 services on 10.201.67.16
Completed Service scan at 11:54, 6.87s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.201.67.16
Initiating Traceroute at 11:54
Completed Traceroute at 11:54, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 11:54
Completed Parallel DNS resolution of 2 hosts. at 11:54, 6.58s elapsed
NSE: Script scanning 10.201.67.16.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 8.54s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 1.16s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
Nmap scan report for 10.201.67.16
Host is up, received echo-reply ttl 61 (0.27s latency).
Scanned at 2025-09-14 11:54:08 IST for 44s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrmafoLXloHrZgpBrYym3Lpsxyn7RI2PmwRwBsj1OqlqiGiD4wE11NQy3KE3Pllc/C0WgLBCAAe+qHh3VqfR7d8uv1MbWx1mvmVxK8l29UH1rNT4mFPI3Xa0xqTZn4Iu5RwXXuM4H9OzDglZas6RIm6Gv+sbD2zPdtvo9zDNj0BJClxxB/SugJFMJ+nYfYHXjQFq+p1xayfo3YIW8tUIXpcEQ2kp74buDmYcsxZBarAXDHNhsEHqVry9I854UWXXCdbHveoJqLV02BVOqN3VOw5e1OMTqRQuUvM5V4iKQIUptFCObpthUqv9HeC/l2EZzJENh+PmaRu14izwhK0mxL
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEaXrFDvKLfEOlKLu6Y8XLGdBuZ2h/sbRwrHtzsyudARPC9et/zwmVaAR9F/QATWM4oIDxpaLhA7yyh8S8m0UOg=
|   256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLrnjg+MVLy+IxVoSmOkAtdmtSWG0JzsWVDV2XvNwrY
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: House of danak
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/14%OT=22%CT=1%CU=30277%PV=Y%DS=4%DC=T%G=Y%TM=68C65FB
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST1
OS:1NW6%O6=M508ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 19.951 days (since Mon Aug 25 13:05:55 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   208.65 ms 10.8.0.1
2   ... 3
4   272.44 ms 10.201.67.16

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.81 seconds
           Raw packets sent: 1584 (70.490KB) | Rcvd: 1914 (150.710KB)
```
---
