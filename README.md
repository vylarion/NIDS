# Network Intrusion Detection System with Snort

A signature-based Network Intrusion Detection System (NIDS) implementation using Snort 2.9.20 on Ubuntu that detects common network attacks including ICMP sweeps, Nmap scans, SSH brute-force attempts, SQL injection, and Cross-Site Scripting (XSS).

## Project Overview

This project demonstrates a complete NIDS setup that monitors network traffic in real-time and generates specific alerts for different attack types. The system is configured with customized rules to accurately differentiate between attack signatures, avoiding misclassification issues that plague generic configurations.

Key features:
- Precise attack classification (no mislabeling of SQLi as "Nmap Scan")
- Full HTTP normalization for accurate web attack detection
- Optimized configuration for both network-layer and application-layer threats
- Controlled attack simulation environment for validation

## Technology Stack

- **OS**: Ubuntu 22.04/24.04 LTS
- **NIDS Engine**: Snort 2.9.20
- **Web Server**: Apache 2.4
- **SSH Server**: OpenSSH 9.x
- **Attack Simulation**: Python 3.8+ with requests, socket libraries

## Installation & Setup

### Prerequisites
- Ubuntu VM with NAT networking (VirtualBox/VMware)
- Minimum 2GB RAM, 10GB disk space
- Internet connectivity for package installation

### Installation Steps
```bash
# 1. Install required packages
sudo apt update && sudo apt install -y snort apache2 openssh-server python3 python3-pip git

# 2. Install Python dependencies
pip3 install requests

# 3. Clone the repository
git clone https://github.com/yourusername/snort-nids-project.git
cd snort-nids-project

# 4. Deploy configuration files
sudo cp config/snort.conf /etc/snort/
sudo cp rules/local.rules /etc/snort/rules/

# 5. Adjust permissions
sudo chmod 644 /etc/snort/snort.conf
sudo chmod 644 /etc/snort/rules/local.rules
```

## Project Structure
```
snort-nids-project/
├── config/
│   └── snort.conf                # Main Snort configuration
├── rules/
│   └── local.rules               # Custom detection rules
├── scripts/
│   └── attack_simulator.py       # Attack simulation script
├── docs/
│   └── project_report.md         # Detailed project documentation
├── logs/
│   └── sample_alerts.log         # Example Snort alerts
├── .gitignore                    # Files to ignore in version control
└── README.md                     # This file
```

## Usage

### Starting the Detection System

1. Start required services:
```bash
sudo systemctl start apache2
sudo systemctl start ssh
```

2. Launch Snort in console mode:
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```
> Note: Replace `eth0` with your network interface name (use `ip a` to identify)

### Running Attack Simulation

From another machine (or VM), execute the attack simulator:

```bash
python3 scripts/attack_simulator.py 10.0.2.15
```

The script will sequentially execute:
1. ICMP ping sweep
2. Nmap SYN scan
3. SSH brute-force attempts
4. SQL injection payloads
5. XSS payloads

### Expected Output
You should see alerts in the Snort console similar to these examples:

```
12/01-14:28:17.664591  [**] [1:1000024:2] ICMP Ping Sweep Detected [**] [Classification: Attempted Information Leak] [Priority: 2] {ICMP} 10.0.2.2 -> 10.0.2.15
12/01-14:28:41.280887  [**] [1:1000001:3] NMAP SYN Scan Detected [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.2.2:52489 -> 10.0.2.15:22
12/01-14:29:02.546389  [**] [1:1000006:2] SSH Brute Force Attempt Detected [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 10.0.2.2:52497 -> 10.0.2.15:22
12/01-14:29:23.827103  [**] [1:1000011:2] SQL Injection Detected: OR 1=1 [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 10.0.2.2:52501 -> 10.0.2.15:80
12/01-14:29:43.156217  [**] [1:1000014:2] XSS Detected: <script> tag [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 10.0.2.2:52505 -> 10.0.2.15:80
```

## Configuration Highlights

### HTTP Normalization
The `snort.conf` file is optimized with HTTP normalization enabled to detect encoded attacks:
```conf
double_decode yes     # Handles double-encoded payloads (%2555 → %55 → 'U')
utf_8 yes             # Processes UTF-8 encoded attacks
iis_unicode yes       # Detects IIS Unicode exploits
client_flow_depth 65495  # Full HTTP client payload inspection
```

### Attack-Specific Rules
Custom rules are precisely targeted to avoid false positives:
```snort
# Only triggers Nmap scan on multiple ports
alert tcp any any -> $HOME_NET [22,80,443,3306] (msg:"NMAP SYN Scan Detected"; flags:S; threshold: type both, track by_src, count 5, seconds 10; sid:1000001; rev:3;)

# Only matches SQLi in normalized HTTP URIs
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"SQL Injection Detected: OR 1=1"; content:"OR"; nocase; http_uri; content:"1=1"; nocase; http_uri; sid:1000011; rev:2;)
```

## Troubleshooting

### Common Issues & Solutions

**Problem**: No alerts appearing for web attacks
- **Solution**: Ensure Apache is running (`sudo systemctl status apache2`)
- **Solution**: Verify HTTP normalization is enabled in snort.conf

**Problem**: All attacks showing as "NMAP SYN Scan"
- **Solution**: Update Nmap rules to target specific port lists instead of "any"
- **Solution**: Ensure proper threshold settings for different attack types

**Problem**: Snort fails to start with configuration errors
- **Solution**: Validate config before running: `sudo snort -T -c /etc/snort/snort.conf -i eth0`

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit your changes (`git commit -m 'Add some amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a pull request

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- The Snort development team for creating an excellent NIDS platform
- OWASP for vulnerability research and documentation
- The cybersecurity education community for sharing knowledge

---

> **Note**: This system is designed for educational purposes in a controlled lab environment. Do not deploy these configurations directly in production environments without thorough security review and testing.
