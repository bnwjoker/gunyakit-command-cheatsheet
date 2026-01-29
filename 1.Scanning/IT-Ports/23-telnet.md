# Port 23 - Telnet

## Table of Contents
- [Enumeration](#enumeration)
- [Banner Grabbing](#banner-grabbing)
- [Brute Force](#brute-force)
- [Exploitation](#exploitation)

---

## Enumeration

### Nmap

```shell
nmap -sV -sC -p 23 $rhost
nmap -p 23 --script telnet-brute $rhost
nmap -p 23 --script telnet-encryption $rhost
nmap -p 23 --script telnet-ntlm-info $rhost
```

### Banner Grabbing

```shell
# Netcat
nc -nv $rhost 23

# Telnet
telnet $rhost 23

# Nmap
nmap -p 23 --script banner $rhost
```

---

## Brute Force

### Hydra

```shell
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://$rhost
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt telnet://$rhost
```

### Ncrack

```shell
ncrack -p 23 --user admin -P /usr/share/wordlists/rockyou.txt $rhost
```

### Metasploit

```shell
use auxiliary/scanner/telnet/telnet_login
set RHOSTS $rhost
set USER_FILE users.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

---

## Exploitation

### Common Default Credentials

| Device/Service | Username | Password |
| :--- | :--- | :--- |
| Cisco | cisco | cisco |
| Cisco | admin | admin |
| Router | admin | admin |
| Router | root | root |
| Embedded | root | (blank) |

### Cisco Telnet

```shell
# Connect
telnet $rhost

# Enable mode
enable
show running-config
show version
```

### Capture Credentials (Cleartext)

```shell
# Wireshark filter
tcp.port == 23

# tcpdump
tcpdump -i eth0 port 23 -A
```

---

## Quick Reference

| Command | Description |
| :--- | :--- |
| `telnet $rhost` | Connect to telnet |
| `nc -nv $rhost 23` | Banner grab |
| `hydra -l admin -P pass.txt telnet://$rhost` | Brute force |
