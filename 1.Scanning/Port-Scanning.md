# Port Scanning

## Table of Contents
- [Host Discovery](#host-discovery)
- [Nmap](#nmap)
- [Masscan](#masscan)
- [Rustscan](#rustscan)
- [NetExec](#netexec)
- [Tips](#tips)

---

## Host Discovery

### Quick Check (One-liner)

```shell
# Quick network discovery + port scan
nmap -sn $cidr | grep "Up" | awk '{print $5}' | xargs -I{} nmap -sC -sV -Pn {} -oN nmap_{}.txt
```

### Ping Sweep

> ICMP ping sweep (find live hosts)

```shell
# Nmap ping sweep (one-liner)
nmap -sn $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# Nmap ARP scan (local network only - most reliable)
sudo nmap -sn -PR $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# fping (fast)
fping -a -g $cidr 2>/dev/null | tee live_hosts.txt

# Ping sweep with bash (ICMP)
for i in {1..254}; do (ping -c1 -W1 192.168.1.$i &>/dev/null && echo "192.168.1.$i" &); done | tee live_hosts.txt
```

### ARP Discovery (Layer 2)

```shell
# arp-scan (most reliable on local network)
sudo arp-scan -l | grep -v "^Interface\|^Starting\|packets" | awk '{print $1}' | tee live_hosts.txt

# arp-scan specific range
sudo arp-scan $cidr | awk '/([0-9a-f]{2}:){5}[0-9a-f]{2}/{print $1}' | tee live_hosts.txt

# Netdiscover
sudo netdiscover -r $cidr -P | awk '/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/{print $1}' | tee live_hosts.txt
```

### TCP/UDP Discovery (When ICMP Blocked)

```shell
# TCP SYN discovery on common ports
nmap -sn -PS22,80,443,445 $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# TCP ACK discovery
sudo nmap -sn -PA80,443 $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# UDP discovery
sudo nmap -sn -PU53,161 $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# Combined TCP + UDP + ICMP
sudo nmap -sn -PE -PS22,80,443 -PU53,161 $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt
```

### NetExec Host Discovery

```shell
# SMB discovery (Windows hosts)
nxc smb $cidr --gen-relay-list live_smb.txt 2>/dev/null && cat live_smb.txt

# Multiple protocols one-liner
for proto in smb rdp winrm ssh; do nxc $proto $cidr 2>/dev/null | grep -E "^\d|SMB|RDP|WINRM|SSH" | awk '{print $2}' | sort -u; done | sort -u | tee live_hosts.txt
```

### Quick Reference - Host Discovery

| Method | Command | Best For |
|--------|---------|----------|
| ICMP Ping | `nmap -sn $cidr` | General discovery |
| ARP Scan | `sudo arp-scan -l` | Local network (most reliable) |
| TCP SYN | `nmap -sn -PS22,80,443 $cidr` | When ICMP blocked |
| TCP ACK | `nmap -sn -PA80 $cidr` | Bypass stateless firewall |
| UDP | `nmap -sn -PU53,161 $cidr` | Find DNS/SNMP hosts |
| NetExec | `nxc smb $cidr` | Windows/AD environments |

---

## Nmap

### Basic Scan (One-liner)

> Quick scan + version detection (one-liner)

```shell
sudo nmap -sV -sC -oN scan.nmap $rhost
```

> Full port scan then detailed scan (one-liner)

```shell
sudo nmap -p- --min-rate 10000 $rhost -oG - | grep '/open' | awk -F'/' '{print $1}' | awk '{print $NF}' | tr '\n' ',' | sed 's/,$//' | xargs -I{} sudo nmap -sV -sC -p {} -oN detail.nmap $rhost
```

> Full scan with auto port extraction (traditional)

```shell
port=$(sudo nmap -p- --min-rate 10000 $rhost | grep '^[0-9]' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//') && sudo nmap -sV -sC -p $port -oN scan.nmap $rhost
```

### UDP Scan (One-liner)

> Top 100 UDP ports with version detection

```shell
sudo nmap -sU --top-ports 100 -sV -oN udp.nmap $rhost
```

> Quick UDP scan common ports

```shell
sudo nmap -sU -p 53,67,68,69,123,161,162,500,514,1900 -sV -oN udp_common.nmap $rhost
```

### CIDR Scan (One-liner)

> Find hosts with specific port open

```shell
nmap -p 445 --open $cidr -oG - | grep '/open' | awk '{print $2}' | tee smb_hosts.txt
```

> Scan multiple ports and extract live hosts

```shell
nmap -p 22,80,443,445,3389 --open $cidr -oG - | grep '/open' | awk '{print $2}' | sort -u | tee live_services.txt
```

### Vulnerability Scan (One-liner)

```shell
sudo nmap -sV --script vuln -oN vuln.nmap $rhost
```

> Safe enumeration scripts

```shell
sudo nmap -sV --script "safe and not brute" -oN safe.nmap $rhost
```

### Firewall Evasion (One-liner)

> Skip host discovery + full scan

```shell
sudo nmap -Pn -p- --min-rate 10000 -oN pn_scan.nmap $rhost
```

> Fragment packets + decoys

```shell
sudo nmap -f -D RND:10 -p 80,443,445 $rhost
```

> Source port 53 (DNS - often allowed)

```shell
sudo nmap --source-port 53 -p- $rhost
```

## Masscan (One-liner)

> Full port scan + pipe to nmap

```shell
sudo masscan -p1-65535 $rhost --rate=1000 -oL - 2>/dev/null | grep 'open' | cut -d' ' -f3 | sort -n | uniq | tr '\n' ',' | sed 's/,$//' | xargs -I{} sudo nmap -sV -sC -p {} -oN mass_detail.nmap $rhost
```

> Quick common ports

```shell
sudo masscan -p21,22,23,25,53,80,110,139,443,445,3306,3389,5985,8080 $rhost --rate=1000 2>/dev/null | tee masscan.txt
```

> CIDR range scan (one-liner with output)

```shell
sudo masscan -p80,443,445 $cidr --rate=10000 2>/dev/null | awk '/open/{print $6}' | sort -u | tee mass_hosts.txt
```

## Rustscan (One-liner)

> Fast scan with nmap integration

```shell
rustscan -a $rhost --ulimit 5000 -- -sV -sC -oN rust_scan.nmap
```

> Greppable output for scripting

```shell
rustscan -a $rhost --ulimit 5000 -g 2>/dev/null | tr ',' '\n'
```

> Batch scan from file

```shell
rustscan -a $(cat live_hosts.txt | tr '\n' ',') --ulimit 5000 -- -sV -oN batch_scan.nmap
```

## NetExec (One-liner)

> Multi-protocol discovery

```shell
for p in smb ldap winrm mssql rdp ssh ftp; do echo "=== $p ===" && nxc $p $cidr 2>/dev/null | grep -v "^\[" | head -20; done | tee nxc_discovery.txt
```

> SMB signing check (for relay attacks)

```shell
nxc smb $cidr --gen-relay-list relay_targets.txt 2>/dev/null
```

> Quick Windows enumeration

```shell
nxc smb $rhost -u '' -p '' --shares --users --groups 2>/dev/null
```

## Tips

### Speed Optimization
| Option | Description |
|--------|-------------|
| `-T4` | Aggressive timing (faster) |
| `-T5` | Insane timing (fastest, may miss ports) |
| `--min-rate 10000` | Minimum packet rate |
| `--max-retries 1` | Reduce retries for speed |

### Common Options
| Option | Description |
|--------|-------------|
| `-sV` | Version detection |
| `-sC` | Default scripts |
| `-sS` | SYN stealth scan |
| `-sT` | TCP connect scan |
| `-sU` | UDP scan |
| `-Pn` | Skip host discovery |
| `-A` | Aggressive scan (OS, version, scripts, traceroute) |
| `-O` | OS detection |
| `-oN` | Normal output |
| `-oG` | Greppable output |
| `-oA` | All formats |

### Useful Script Categories
```shell
# List available scripts
ls /usr/share/nmap/scripts/*.nse | wc -l

# Search for specific scripts
ls /usr/share/nmap/scripts/*smb*.nse
ls /usr/share/nmap/scripts/*http*.nse
ls /usr/share/nmap/scripts/*vuln*.nse

# Use script category
sudo nmap --script "default,safe" -p $port $rhost
sudo nmap --script "vuln and safe" -p $port $rhost
```

---

## See Also

- **[IT-Ports/](IT-Ports/)** - Service-specific enumeration (SMB, SSH, HTTP, etc.)
- **[OT-Ports/](OT-Ports/)** - Industrial/SCADA protocol scanning
- **[AD Exploitation](../3.AD-Exploit/3.1.AD-Exploitation.md)** - Post-scan AD enumeration
- **[Web Application Analysis](../7.Web-Exploit/7.0.Web-Application-Analysis.md)** - Web service scanning

