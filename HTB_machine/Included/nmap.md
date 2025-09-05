```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.129.151.160 -vv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-21 18:42 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:42
Completed NSE at 18:42, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:42
Completed NSE at 18:42, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:42
Completed NSE at 18:42, 0.00s elapsed
Initiating Ping Scan at 18:42
Scanning 10.129.151.160 [4 ports]
Completed Ping Scan at 18:42, 0.52s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:42
Completed Parallel DNS resolution of 1 host. at 18:42, 0.26s elapsed
Initiating SYN Stealth Scan at 18:42
Scanning 10.129.151.160 [1000 ports]
Discovered open port 80/tcp on 10.129.151.160
Completed SYN Stealth Scan at 18:42, 4.71s elapsed (1000 total ports)
Initiating Service scan at 18:42
Scanning 1 service on 10.129.151.160
Completed Service scan at 18:42, 7.43s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 10.129.151.160
Retrying OS detection (try #2) against 10.129.151.160
Retrying OS detection (try #3) against 10.129.151.160
WARNING: OS didn't match until try #3
Initiating Traceroute at 18:42
Completed Traceroute at 18:42, 0.86s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 18:42
Completed Parallel DNS resolution of 2 hosts. at 18:42, 6.65s elapsed
NSE: Script scanning 10.129.151.160.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:42
Completed NSE at 18:43, 14.91s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:43
Completed NSE at 18:43, 3.28s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:43
Completed NSE at 18:43, 0.00s elapsed
Nmap scan report for 10.129.151.160
Host is up, received reset ttl 63 (0.67s latency).
Scanned at 2025-08-21 18:42:04 IST for 64s
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.129.151.160/?file=home.php
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=8/21%OT=80%CT=1%CU=44751%PV=Y%DS=2%DC=T%G=Y%TM=68A71B6
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=108%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:07%GCD=1%ISR=10D%TI=Z%CI=Z%TS=9)SEQ(SP=FC%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)O
OS:PS(O1=M569ST11NW7%O2=M569ST11NW7%O3=M569NNT11NW7%O4=M569ST11NW7%O5=M569S
OS:T11NW7%O6=M569ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)E
OS:CN(R=Y%DF=Y%TG=40%W=FAF0%O=M569NNSNW7%CC=Y%Q=)ECN(R=Y%DF=Y%T=40%W=FAF0%O
OS:=M569NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)T1(R=Y%DF=Y%
OS:T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%TG
OS:=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0
OS:%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL
OS:=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%TG=40%CD=S)IE(R=Y%DFI=N%T=40%
OS:CD=S)

Uptime guess: 43.586 days (since Wed Jul  9 04:39:24 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   545.66 ms 10.10.16.1
2   855.11 ms 10.129.151.160

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:43
Completed NSE at 18:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:43
Completed NSE at 18:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:43
Completed NSE at 18:43, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.50 seconds
           Raw packets sent: 1236 (60.082KB) | Rcvd: 1220 (53.463KB)
-----------------------------------------------------------------------------------------------------
2.Switched to the UDP scan identifed the any open ports.                                                                                      
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sU 10.129.151.160 -vv 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-21 18:41 IST
Initiating Ping Scan at 18:41
Scanning 10.129.151.160 [4 ports]
Completed Ping Scan at 18:41, 0.31s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:41
Completed Parallel DNS resolution of 1 host. at 18:41, 0.16s elapsed
Initiating UDP Scan at 18:41
Scanning 10.129.151.160 [1000 ports]
Increasing send delay for 10.129.151.160 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 10.129.151.160 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.129.151.160 from 100 to 200 due to 11 out of 14 dropped probes since last increase.
UDP Scan Timing: About 4.60% done; ETC: 18:53 (0:10:43 remaining)
Increasing send delay for 10.129.151.160 from 200 to 400 due to 11 out of 14 dropped probes since last increase.
UDP Scan Timing: About 7.86% done; ETC: 18:54 (0:11:55 remaining)
Increasing send delay for 10.129.151.160 from 400 to 800 due to 11 out of 19 dropped probes since last increase.
UDP Scan Timing: About 10.77% done; ETC: 18:55 (0:12:34 remaining)
UDP Scan Timing: About 25.09% done; ETC: 18:57 (0:11:51 remaining)
UDP Scan Timing: About 31.44% done; ETC: 18:57 (0:11:03 remaining)
UDP Scan Timing: About 37.46% done; ETC: 18:58 (0:10:13 remaining)
UDP Scan Timing: About 42.96% done; ETC: 18:58 (0:09:23 remaining)
UDP Scan Timing: About 48.46% done; ETC: 18:58 (0:08:32 remaining)
UDP Scan Timing: About 53.86% done; ETC: 18:58 (0:07:41 remaining)
UDP Scan Timing: About 59.27% done; ETC: 18:58 (0:06:49 remaining)
UDP Scan Timing: About 64.77% done; ETC: 18:58 (0:05:55 remaining)
UDP Scan Timing: About 70.06% done; ETC: 18:58 (0:05:02 remaining)
UDP Scan Timing: About 75.24% done; ETC: 18:58 (0:04:10 remaining)
UDP Scan Timing: About 80.34% done; ETC: 18:58 (0:03:19 remaining)
UDP Scan Timing: About 85.66% done; ETC: 18:58 (0:02:26 remaining)
UDP Scan Timing: About 90.84% done; ETC: 18:58 (0:01:33 remaining)
UDP Scan Timing: About 96.13% done; ETC: 18:58 (0:00:39 remaining)
Completed UDP Scan at 18:59, 1070.55s elapsed (1000 total ports)
Nmap scan report for 10.129.151.160
Host is up, received echo-reply ttl 63 (0.32s latency).
Scanned at 2025-08-21 18:41:47 IST for 1070s
Not shown: 997 closed udp ports (port-unreach)
PORT      STATE         SERVICE REASON
68/udp    open|filtered dhcpc   no-response
69/udp    open|filtered tftp    no-response
34862/udp open|filtered unknown no-response
-------------------------------------------------------------------------------------------------------------
```
