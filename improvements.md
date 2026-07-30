# Sigma → Wazuh Lab Setup & Attack Plan
## Complete Guide for Windows AD + Ubuntu Tomcat + Kali Environment

---

## Lab Architecture

```
                    ┌─────────────────┐
                    │   Kali Linux    │  ← Attacker (no Wazuh agent)
                    │   (Offensive)   │
                    └────────┬────────┘
                             │ Attacks
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼────────┐  ┌────────▼────────┐  ┌──────▼──────┐
│ Windows AD 2019│  │  Wazuh Server   │  │Ubuntu+Tomcat│
│   (Agent)      │  │   (Manager)     │  │   (Agent)   │
└────────────────┘  └─────────────────┘  └─────────────┘
```

---

## Phase 1: Preparation

### 1.1 Install Sysmon on Windows AD

Without Sysmon, Wazuh only sees Windows Security logs (logins/logouts). **Sysmon gives you process creation, network connections, file modifications, registry changes.**

**On Windows AD (PowerShell as Administrator):**

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Sysmon"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

**Tell Wazuh agent to read Sysmon logs.** Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and add:

```xml
<localfile>
  <log_format>eventchannel</log_format>
  <location>Microsoft-Windows-Sysmon/Operational</location>
</localfile>
```

**Restart Wazuh agent:**

```powershell
Restart-Service -Name wazuh
```

---

### 1.2 Configure Tomcat Log Collection on Ubuntu

Edit `/var/ossec/etc/ossec.conf` on the Ubuntu VM and add:

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/tomcat9/access_log.*</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/tomcat9/catalina.out</location>
</localfile>
```

> **Note:** If you already have a Tomcat `<localfile>` entry with `log_format=syslog`, change it to `apache`. Tomcat access logs use Apache/NCSA combined format, not syslog.

**Also add auditd log forwarding:**

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

**Enable auditd for Linux process monitoring:**

```bash
sudo apt install auditd audispd-plugins -y
sudo auditctl -a always,exit -F arch=b64 -S execve -k process_monitoring
```

**Restart the Wazuh agent:**

```bash
sudo systemctl restart wazuh-agent
```

**Verify auditd is capturing execve:**

```bash
sudo auditctl -l | grep execve
sudo tail -f /var/log/audit/audit.log | grep exe=
```

---

## Phase 2: Generate Normal Baseline (1–2 Days)

Before attacking, you need **normal data**. Wazuh needs to learn what "good" looks like so you can prove your alerts are not false positives.

### On Ubuntu (Tomcat)
- Browse the website normally (click pages, login, logout)
- Restart Tomcat a few times:
  ```bash
  sudo systemctl restart tomcat9
  ```
- Run normal admin commands:
  ```bash
  sudo apt update
  df -h
  ps aux
  ```

### On Windows AD
- Normal user logins (RDP from your host)
- Group Policy updates
- Scheduled tasks running
- Service installations (normal software)

> **Why this matters:** When you demo your project, you show the ML model distinguishing normal cron jobs from malicious ones.

---

## Phase 3: The Attack Chain (MITRE ATT&CK)

Don't do random attacks. Do a **story**. Here is a realistic 7-step kill chain for your lab.

| Step | MITRE Technique | What You Do on Kali | What Should Be Detected |
|------|----------------|---------------------|------------------------|
| 1 | **Reconnaissance** (T1046) | `nmap -sV -p 80,8080,3389,22 192.168.1.0/24` | Port scans in Wazuh (if you have Suricata) or `auth.log` connection attempts |
| 2 | **Initial Access** (T1110) | `hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.1.10` | Multiple failed RDP logins (Event ID 4625) |
| 3 | **Initial Access** (T1190) | Exploit Tomcat manager upload (Metasploit: `exploit/multi/http/tomcat_mgr_upload`) | JSP shell upload, suspicious WAR deployment |
| 4 | **Execution** (T1059) | PowerShell reverse shell on Windows; Bash commands on Linux | Sysmon Event ID 1 (process creation) showing `powershell -enc` or `bash -i` |
| 5 | **Persistence** (T1136) | `net user hacker P@ssw0rd /add` on Windows; add SSH key on Linux | New user created (Event ID 4720), SSH `authorized_keys` modified |
| 6 | **Credential Access** (T1003) | Run Mimikatz `sekurlsa::logonpasswords` | LSASS access, suspicious process accessing SAM hive (Sysmon) |
| 7 | **Impact** (T1485) | Delete logs: `wevtutil cl Security` | Event log cleared (Event ID 1102) |

---

## Phase 4: Sigma Rules to Convert

These are the exact Sigma rules from the [official Sigma repo](https://github.com/SigmaHQ/sigma) that match your lab. Convert each using your pipeline.

### A. Windows Rules (Install Sysmon First!)

| Rule File | What It Detects | Why You Need It |
|-----------|----------------|-----------------|
| `windows/builtin/security/win_susp_failed_logons.yml` | Multiple failed logins (4625) | Catches your Hydra brute force |
| `windows/builtin/security/win_susp_login_after_logon.yml` | Impossible travel / odd login times | Baseline anomaly |
| `windows/process_creation/proc_creation_win_susp_powershell_enc_cmd.yml` | PowerShell with encoded commands | Catches reverse shells |
| `windows/process_creation/proc_creation_win_susp_cmd.yml` | Suspicious `cmd.exe` usage | General execution detection |
| `windows/process_creation/proc_creation_win_net_user_add.yml` | `net user /add` commands | Catches persistence |
| `windows/process_creation/proc_creation_win_mimikatz_command_line.yml` | Mimikatz execution | Credential dumping detection |
| `windows/builtin/security/win_event_log_cleared.yml` | Security log cleared (1102) | Impact step detection |
| `windows/process_creation/proc_creation_win_susp_schtasks.yml` | Scheduled task creation | Persistence |
| `windows/process_creation/proc_creation_win_lsass_access.yml` | LSASS memory access | Credential access |

### B. Linux Rules (Ubuntu + Tomcat)

| Rule File | What It Detects | Why You Need It |
|-----------|----------------|-----------------|
| `linux/process_creation/proc_creation_lnx_susp_kill_command.yml` | Kill commands (your test rule!) | Process termination |
| `linux/process_creation/proc_creation_lnx_susp_shell_spawn.yml` | Shell spawning from web server | Tomcat exploitation → shell |
| `linux/auditd/lnx_auditd_susp_file_modification.yml` | Sensitive file modified | `/etc/passwd`, `/etc/shadow` changes |
| `linux/auditd/lnx_auditd_susp_cmds.yml` | Suspicious commands via auditd | Privilege escalation attempts |
| `linux/builtin/lnx_susp_ssh_login.yml` | Suspicious SSH patterns | Lateral movement |

### C. Web / Tomcat Rules

| Rule File | What It Detects | Why You Need It |
|-----------|----------------|-----------------|
| `web/webserver_generic/web_susp_useragents.yml` | Suspicious User-Agents | Metasploit/Scanner UA strings |
| `web/apache/apache_tomcat_susp_deployment.yml` *(custom)* | WAR file deployment | Catches your Metasploit upload |
| `web/webserver_generic/web_webshell_detection.yml` | Webshell access patterns | JSP shell usage after upload |

> **Note:** Some Tomcat-specific rules don't exist in Sigma yet. For those, write a simple Sigma rule manually:

```yaml
title: Tomcat Suspicious WAR Deployment
logsource:
    product: apache
    service: tomcat
detection:
    selection:
        cs-method: 'PUT'
        cs-uri-stem|contains: '.war'
    condition: selection
```

---

## Phase 5: How to Run the Experiment

### Day 1: Baseline
1. Start all VMs. Verify Wazuh agents are active (green check in Wazuh dashboard).
2. Run normal activity for 2–4 hours.
3. Check Wazuh dashboard → confirm no critical alerts.

### Day 2: Attack & Detect
1. **Morning:** Run the Sigma → Wazuh pipeline. Convert all rules from Phase 4.
2. Install generated rules on the Wazuh server:
   ```bash
   # On Wazuh Server
   sudo cp generated_rules/*.xml /var/ossec/etc/rules/
   sudo systemctl restart wazuh-manager
   ```
3. **Afternoon:** Execute the MITRE chain from Kali (Step 1 → Step 7).
4. Watch the Wazuh dashboard. You should see alerts firing in real-time.

### Day 3: Response Actions
Configure Wazuh **Active Response** to automatically fight back.

Edit `/var/ossec/etc/ossec.conf` on the manager:

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <level>10</level>
  <timeout>1800</timeout>
</active-response>
```

Now when your brute force rule fires at level 10, Wazuh **automatically blocks the Kali IP for 30 minutes**.

---

## Phase 6: The Advanced ML Layer

This is what separates a student project from a research project. Add **two ML systems** on top of Wazuh.

### 6.1 Alert Correlation Engine (The "Brain")

**Problem:** Wazuh sees 7 separate alerts. A human sees "an attack in progress."

**Your Solution:** Build a Python service that reads Wazuh's `alerts.json` and correlates alerts by time window + source IP + MITRE technique.

```python
# Pseudo-code for your correlation engine
class AttackGraph:
    def __init__(self):
        self.time_window = 300  # 5 minutes

    def correlate(self, alerts):
        # Group alerts by source IP
        # If you see: port_scan → failed_login → powershell → mimikatz
        # Raise a "CRITICAL: Active Intrusion" alert
```

**Architecture:**

```
Wazuh Manager → alerts.json → Your Python Correlator → New "Meta-Alert" → Dashboard
```

### 6.2 Anomaly Classification Model

**Problem:** Static rules miss zero-days. ML catches "weird."

**Your Solution:** Train a model on your **baseline data** (Phase 2), then during attacks, flag anomalies.

**Features to extract from Wazuh alerts:**
- Alert frequency per agent (per minute)
- Ratio of rule levels (how many level 5 vs level 15?)
- Time-of-day patterns (login at 3 AM?)
- MITRE technique diversity (how many different TTPs in 10 minutes?)

**Simple but effective model:**

```python
from sklearn.ensemble import IsolationForest

# Train on 2 days of normal logs
model = IsolationForest(contamination=0.01)
model.fit(normal_features)

# During attack
if model.predict(current_features) == -1:
    print("ANOMALY: Attack pattern detected beyond static rules!")
```

### 6.3 MITRE ATT&CK Navigator Layer

Map every alert to its MITRE technique ID. After the attack, generate a heatmap showing which techniques were detected and which were missed.

Use the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) and color techniques:
- **Green:** Detected by your Sigma rules
- **Red:** Not detected (gap analysis)

---

## Phase 7: Project Deliverables

| Deliverable | What It Proves |
|-------------|---------------|
| **Before/After Dashboard** | "This is normal. This is the attack." |
| **Sigma Rule Conversion Pipeline** | "I automated threat intelligence translation." |
| **Generated Decoder + Rule XML** | "I can handle unknown log sources." |
| **MITRE ATT&CK Heatmap** | "I understand the attack lifecycle." |
| **ML Anomaly Detection Graph** | "I go beyond static signatures." |
| **Active Response Demo** | "My system autonomously defends itself." |

---

## Quick Start: Your First 3 Rules to Convert

Start small. Convert these three rules first, test them, then expand:

1. **Windows Brute Force:** `win_susp_failed_logons.yml`
2. **Windows Mimikatz:** `proc_creation_win_mimikatz_command_line.yml`
3. **Linux Suspicious Shell:** `proc_creation_lnx_susp_shell_spawn.yml`

Run your pipeline on each. Install the XML. Execute the matching attack from Kali. Verify the alert fires. **Once these 3 work, the rest is just repetition.**

---

## Quick Command Reference

| Task | Command |
|------|---------|
| Restart Wazuh Agent (Windows) | `Restart-Service -Name wazuh` |
| Restart Wazuh Agent (Linux) | `sudo systemctl restart wazuh-agent` |
| Restart Wazuh Manager | `sudo systemctl restart wazuh-manager` |
| Verify auditd execve | `sudo auditctl -l \| grep execve` |
| Monitor audit logs | `sudo tail -f /var/log/audit/audit.log \| grep exe=` |
| Test rule with logtest | `sudo /var/ossec/bin/wazuh-logtest` |

---

*End of Document*




-----------------------------------------------------------------------------------------------------------------





imporve the rag search (metadata)

┌─────────────────┐
│   Sigma Rule    │
│   + SigWaz XML  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│  GENERATOR LLM              │
│  (Simple, no tools)         │
│                             │
│  Input:                     │
│  - Sigma YAML               │
│  - SigWaz XML               │
│  - RAG results (top 5 rules,│
│    decoder, docs)           │
│  - Reviews (if any)         │
│                             │
│  Output: Wazuh XML draft    │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  VALIDATOR AGENT            │
│  (Has tools + can search)   │
│                             │
│  Step 1: Extract if_sid     │
│          from generated XML │
│                             │
│  Step 2: TOOL CALL          │
│          get_rule_by_id(    │
│            proposed_if_sid) │
│          → returns parent   │
│            rule XML + meta  │
│                             │
│  Step 3: TOOL CALL          │
│          get_decoder(       │
│            parent_decoder)  │
│          → returns decoder  │
│            fields           │
│                             │
│  Step 4: Validate           │
│          ✓ if_sid exists?   │
│          ✓ category match?  │
│          ✓ fields extracted?│
│                             │
│  Step 5: If FAIL            │
│          → Search for       │
│            better parent:   │
│            search_rules(    │
│              category="web",│
│              has_children=  │
│              true)          │
│          → Pick new parent  │
│          → Write review     │
│                             │
│  Output:                    │
│  PASS ✅  → Done            │
│  FAIL 🔁  → Reviews +       │
│             suggested_fixes │
└────────┬────────────────────┘
         │ FAIL
         ▼
   Reviews → back to GENERATOR
   (loop max 3 times)


----------------------------------------------------------------------------


                    NEW HYBRID FLOW:
                    
            ┌───────────────────────┐
            │ convert_sigma_to_xml()|  ──►  SigWaz output
            └────────┬──────────────┘
                    │
                    ▼
            ┌─────────────────────────────┐
            │ STEP 1: CLASSIFY Sigma rule │
            │ Determine:                  │
            │   - logsource category      │
            │   - platform (web/win/linux)│
            │   - expected decoder family │
            └────────┬────────────────────┘
                    │
                    ▼
            ┌─────────────────────────────┐
            │ STEP 2: FILTERED RAG        │
            │ retriever.invoke() with:    │
            │   filter={"platform": "web"}│
            │   OR hybrid search:         │
            │   semantic + keyword boost  │
            │   k=5 (more context)        │
            └────────┬────────────────────┘
                    │
                    ▼
            ┌─────────────────────────────┐
            │ STEP 3: ADD PARENTS         │
            │ add_parent_rules()          │
            │   (same, but now also       │
            │    check parent has_children│
            │    and is_valid_parent)     │
            └────────┬────────────────────┘
                    │
                    ▼
            ┌─────────────────────────────┐
            │ STEP 4: ADD DECODERS        │
            │ Query ChromaDB for decoder  │
            │ instead of filesystem       │
            │ (decoder is now in DB)      │
            └────────┬────────────────────┘
                    │
                    ▼
            ┌─────────────────────────────┐
            │ STEP 5: GENERATOR LLM       │
            │ llm_call()                  │
            │   Input: Sigma + SigWaz +   │
            │   RAG results + decoders    │
            │   NO reviews (first pass)   │
            │   Output: Wazuh XML draft   │
            └────────┬────────────────────┘
                    │
                    ▼
            ┌─────────────────────────────┐
            │ STEP 6: VALIDATOR AGENT     │
            │ validate_rule()             │
            │   Has tools:                │
            │   • get_rule_by_id(id)      │
            │   • get_decoder(name)       │
            │   • search_better_parent()  │
            │   • validate_xml_syntax()   │
            │                             │
            │   Checks:                   │
            │   1. XML syntax             │
            │   2. if_sid exists in DB?   │
            │   3. Parent category match? │
            │   4. Decoder has fields?    │
            │   5. if_sid triggers?       │
            │                             │
            │   Output:                   │
            │   PASS → Done ✅            │
            │   FAIL → Reviews + fixes 🔁 │
            └────────┬────────────────────┘
                    │ FAIL
                    ▼
            ┌─────────────────────────────┐
            │ STEP 7: LOOP                │
            │ If reviews exist:           │
            │   reviews → add to prompt   │
            │   llm_call() again          │
            │   (max 3 iterations)        │
            │                             │
            │   Generator prompt now has: │
            │   "Previous attempt errors: │
            │    {reviews}"               │
            └────────┬────────────────────┘
                    │
                    ▼
            Back to STEP 6 (Validator)