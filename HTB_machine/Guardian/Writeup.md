# [Guardian] - [HTB]
**Difficulty:** [Hard]  
**OS:** [Linux]  
**Date:** []  

---

## 1. Summary
- **Objective:** [ ] Capture user flag  
- **Objective:** [ ] Capture root flag / administrator access  
- **Description / Notes:** [Brief overview of the machine, main services, challenges]  
- **Skills Practiced:** 
  - [ ] Enumeration
  - [ ] Web Exploitation
  - [ ] Binary Exploitation
  - [ ] Privilege Escalation
---

## 2. Recon & Enumeration

### 2.1 Network Scanning
```bash
# Nmap Quick Scan
nmap -sC -sV -oN nmap_initial.txt [IP]

# Nmap Full Port Scan
nmap -p- -T4 -oN nmap_full.txt [IP]

gobuster dir -u http://[IP] -w /usr/share/wordlists/dirb/common.txt

