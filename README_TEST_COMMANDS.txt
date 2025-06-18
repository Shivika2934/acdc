# Test Commands for ACDC Modules

## 1. Honeypot Module

### SSH Honeypot (default port 22 or 2222)
ssh testuser@localhost -p 22
ssh testuser@localhost -p 2222

### FTP Honeypot (default port 21 or 2121)
ftp localhost 21
ftp localhost 2121

# Or using curl for FTP:
curl ftp://localhost:21

### Telnet Honeypot (default port 23 or 2323)
telnet localhost 23
telnet localhost 2323

### HTTP Honeypot (default port 80, 8080, 8443)
curl http://localhost:80/
curl http://localhost:8080/
curl http://localhost:8443/

# Simulate attack patterns:
curl "http://localhost:80/?q=../../etc/passwd"
curl "http://localhost:80/?q=<script>alert(1)</script>"
curl "http://localhost:80/?q=1;ls"

## 2. Endpoint Security Monitor

# Create, modify, or delete files in monitored directories:
echo "test" > testfile.txt
echo "append" >> testfile.txt
rm testfile.txt

# Create a suspicious file:
echo "malware" > evil.exe

## 3. Network Analyzer

# ICMP (Ping)
ping 127.0.0.1

# TCP/UDP traffic (using netcat)
nc -vz localhost 80
nc -u -vz localhost 8080

# Simulate port scan (using nmap)
nmap -p 20-25,80,8080,8443 localhost

# Simulate SYN flood (requires root)
hping3 -S -p 80 --flood 127.0.0.1

# DNS Query (if DNS monitoring is enabled)
nslookup google.com

# Simulate SQL injection payload
curl "http://localhost:80/?id=1 UNION SELECT password FROM users"

## 4. Cryptanalysis Module

# Run the cryptanalysis module and follow prompts:
python d:\acdc\cryptanalysis.py

# Try encrypting/decrypting messages with both XOR and Monoalphabetic ciphers.

---

# Note:
# - Replace 'localhost' with your server's IP if testing from another machine.
# - Some commands (like hping3, nmap) may require installation and root/admin privileges.
# - Ensure the relevant module is running before testing.
