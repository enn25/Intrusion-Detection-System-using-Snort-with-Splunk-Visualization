# 📊 Intrusion Detection System using Snort with Splunk Visualization

[![Platform](https://img.shields.io/badge/Platform-Ubuntu-orange.svg)](https://ubuntu.com/)
[![Snort](https://img.shields.io/badge/IDS-Snort-red.svg)](https://www.snort.org/)
[![Splunk](https://img.shields.io/badge/SIEM-Splunk-green.svg)](https://www.splunk.com/)

A comprehensive real-time Intrusion Detection System (IDS) implementation using **Snort** integrated with **Splunk** for advanced security monitoring and threat visualization. This project demonstrates enterprise-level cybersecurity threat detection, analysis, and visualization capabilities with a focus on DDoS and packet flooding attack detection.

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Attack Simulation](#-attack-simulation)
- [Visualization](#-visualization)
- [Performance Metrics](#-performance-metrics)
- [Project Structure](#-project-structure)
- [Usage Examples](#-usage-examples)
- [Troubleshooting](#-troubleshooting)
- [Future Enhancements](#-future-enhancements)
- [Contributing](#-contributing)

## 🎯 Project Overview

This project combines the power of rule-based intrusion detection with advanced data visualization to create a comprehensive security monitoring solution. The system enhances situational awareness and reduces cognitive load for security analysts through intuitive graphical dashboards.

### Key Objectives
- **Real-time Threat Detection**: Immediate identification of network intrusions and anomalies
- **Advanced Visualization**: Transform raw security logs into actionable intelligence
- **Attack Simulation**: Controlled testing environment for various cyber attack scenarios
- **Performance Optimization**: Efficient processing of high-volume network traffic

## ✨ Features

- 🔍 **Real-time Network Monitoring** - Continuous packet inspection and analysis
- 🚨 **Multi-layered Attack Detection** - DDoS, packet flooding, port scanning detection
- 📈 **Interactive Dashboards** - Splunk-powered visualization and analytics
- 🎯 **Custom Rule Engine** - Flexible and extensible detection rules
- 📊 **Performance Metrics** - Comprehensive system monitoring and reporting
- 🔄 **Log Correlation** - Advanced event correlation and analysis
- 🛡️ **Threat Intelligence** - Integration-ready for external threat feeds

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Kali Linux    │    │     Ubuntu      │    │     Splunk      │
│  (Attack Sim)   │───▶│   Snort IDS     │───▶│  Visualization  │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Prerequisites

### System Requirements
- **Operating System**: Ubuntu 20.04 LTS or higher
- **Memory**: Minimum 8GB RAM (16GB recommended)
- **Storage**: 50GB available disk space
- **Network**: Multiple network interfaces for monitoring

### Software Dependencies
- **Snort**: Version 2.9.x or 3.x
- **Splunk Enterprise**: Version 8.x or higher
- **Kali Linux**: For attack simulation (can be virtualized)

## 🚀 Installation

### 1. Snort Installation and Setup

```bash
# Update system packages
sudo apt-get update && sudo apt-get upgrade -y

# Install dependencies
sudo apt-get install -y build-essential libpcap-dev libpcre3-dev \
    libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev

# Install Snort
sudo apt-get install snort

# Verify installation
snort --version
```

### 2. Splunk Installation

```bash
# Download Splunk Enterprise (replace with actual filename)
wget -O splunk-enterprise.deb "https://download.splunk.com/..."

# Install Splunk
sudo dpkg -i splunk-enterprise.deb

# Start Splunk service
sudo /opt/splunk/bin/splunk start --accept-license

# Enable boot start
sudo /opt/splunk/bin/splunk enable boot-start
```

### 3. Integration Setup

```bash
# Install Splunk Universal Forwarder
wget -O splunkforwarder.deb "https://download.splunk.com/..."
sudo dpkg -i splunkforwarder.deb

# Configure forwarder
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```

## ⚙️ Configuration

### Snort Configuration

1. **Edit main configuration file:**
```bash
sudo nano /etc/snort/snort.conf
```

2. **Key configuration settings:**
```bash
# Set your network range
var HOME_NET 192.168.1.0/24

# Set external network
var EXTERNAL_NET !$HOME_NET

# Configure rule paths
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules
```

3. **Create custom detection rules:**
```bash
sudo nano /etc/snort/rules/local.rules
```

Example rules:
```bash
# DDoS Detection
alert tcp any any -> $HOME_NET any (msg:"Possible DDoS Attack"; \
    flags:S; threshold:type both, track by_src, count 100, seconds 60; \
    sid:1000001; rev:1;)

# Port Scan Detection
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; \
    flags:S; threshold:type both, track by_src, count 20, seconds 60; \
    sid:1000002; rev:1;)
```

### Splunk Configuration

1. **Configure inputs.conf:**
```bash
sudo nano /opt/splunk/etc/system/local/inputs.conf
```

```ini
[monitor:///var/log/snort/alert]
disabled = false
sourcetype = snort_alert
index = security

[udp://514]
disabled = false
sourcetype = syslog
index = security
```

2. **Configure outputs.conf:**
```bash
sudo nano /opt/splunkforwarder/etc/system/local/outputs.conf
```

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = localhost:9997

[tcpout-server://localhost:9997]
```

## 🧪 Attack Simulation

### DDoS Attack Simulation
```bash
# From Kali Linux terminal
# SYN Flood attack
hping3 -S -p 80 --flood [target_ip]

# UDP Flood attack
hping3 -2 -p 80 --flood [target_ip]

# ICMP Flood attack
hping3 -1 --flood [target_ip]
```

### Port Scanning Simulation
```bash
# Nmap port scan
nmap -sS -p 1-1000 [target_ip]

# Aggressive scan
nmap -A -T4 [target_ip]
```

### Custom Attack Scripts
```bash
#!/bin/bash
# ddos_simulation.sh
TARGET_IP="192.168.1.100"
DURATION=60

echo "Starting DDoS simulation against $TARGET_IP for $DURATION seconds"
timeout $DURATION hping3 -S -p 80 --flood $TARGET_IP
echo "Attack simulation completed"
```

## 📊 Visualization

### Splunk Dashboard Components

1. **Real-time Alert Monitor**
   - Live feed of security alerts
   - Alert severity classification
   - Geographic IP mapping

2. **Attack Pattern Analysis**
   - Time-series analysis of attack patterns
   - Protocol distribution charts
   - Source IP frequency analysis

3. **Network Traffic Overview**
   - Bandwidth utilization metrics
   - Protocol usage statistics
   - Connection state analysis

### Sample Splunk Searches

```splunk
# Top attacking IPs
sourcetype=snort_alert | stats count by src_ip | sort -count | head 10

# Attack timeline
sourcetype=snort_alert | timechart count by alert_type

# Geographic distribution
sourcetype=snort_alert | iplocation src_ip | geostats count by Country
```

## 📈 Performance Metrics

| Metric | Description | Target Value |
|--------|-------------|--------------|
| **Detection Rate** | Percentage of attacks successfully detected | >95% |
| **False Positive Rate** | Percentage of false alarms | <5% |
| **Response Time** | Time from detection to alert visualization | <30 seconds |
| **Log Processing Rate** | Events processed per second | >1000 EPS |
| **System Uptime** | Continuous operation reliability | >99.9% |
| **Memory Usage** | System resource utilization | <80% |

## 📁 Project Structure

```
intrusion-detection-system/
├── README.md
├── docs/
│   ├── installation-guide.md
│   ├── configuration-guide.md
│   └── troubleshooting.md
├── configs/
│   ├── snort/
│   │   ├── snort.conf
│   │   └── rules/
│   │       ├── local.rules
│   │       └── custom-ddos.rules
│   └── splunk/
│       ├── inputs.conf
│       ├── outputs.conf
│       └── dashboards/
│           ├── security-overview.xml
│           └── attack-analysis.xml
├── scripts/
│   ├── attack-simulation/
│   │   ├── ddos-simulation.sh
│   │   ├── port-scan.sh
│   │   └── traffic-generator.py
│   ├── monitoring/
│   │   ├── system-health.sh
│   │   └── log-analyzer.py
│   └── utilities/
│       ├── setup-environment.sh
│       └── backup-configs.sh
├── logs/
│   ├── snort/
│   └── splunk/
└── tests/
    ├── unit-tests/
    ├── integration-tests/
    └── performance-tests/
```

## 💡 Usage Examples

### Starting the IDS
```bash
# Start Snort in daemon mode
sudo snort -D -c /etc/snort/snort.conf -l /var/log/snort/

# Verify Snort is running
sudo ps aux | grep snort

# Start Splunk services
sudo systemctl start splunk
```

### Monitoring Commands
```bash
# View real-time alerts
sudo tail -f /var/log/snort/alert

# Check Snort statistics
sudo kill -USR1 $(cat /var/run/snort.pid)

# Monitor system resources
htop
```

## 🔧 Troubleshooting

### Common Issues

**Snort not detecting attacks:**
- Verify network interface configuration
- Check rule syntax and paths
- Ensure proper permissions on log directories

**Splunk not receiving logs:**
- Verify forwarder configuration
- Check network connectivity on port 9997
- Review inputs.conf settings

**High false positive rates:**
- Tune detection thresholds
- Implement whitelist rules
- Adjust rule sensitivity

### Debug Commands
```bash
# Test Snort configuration
sudo snort -T -c /etc/snort/snort.conf

# Verbose Snort output
sudo snort -A console -c /etc/snort/snort.conf

# Check Splunk logs
sudo /opt/splunk/bin/splunk show splunkd-health
```

## Demo and Screenshots

<div align="center">
  <img src="https://github.com/user-attachments/assets/b01c03cc-18ed-41f3-a1bf-c96a403e8005" alt="splunk_alert" width="400"/>
  <br/>
  <img src="https://github.com/user-attachments/assets/4e1f0a26-fefd-4016-be74-8b00187407c3" alt="kali_system" width="400"/>
  <br/>
  <img src="https://github.com/user-attachments/assets/a2776db8-69f5-45bf-8689-5d5edd067e4a" alt="flood_detection" width="400"/>
</div>

## 🚀 Future Enhancements

### Planned Features
- **Machine Learning Integration**: AI-powered anomaly detection using TensorFlow
- **Cloud Deployment**: AWS/Azure cloud-native implementation
- **IoT Security**: Edge device monitoring capabilities
- **Threat Intelligence**: Integration with external threat feeds
- **Mobile Dashboard**: iOS/Android monitoring applications
- **Automated Response**: SOAR (Security Orchestration, Automation, and Response) integration

### Roadmap
- **Phase 1**: Enhanced rule engine with behavioral analysis
- **Phase 2**: Multi-node distributed deployment
- **Phase 3**: Advanced threat hunting capabilities
- **Phase 4**: Compliance reporting automation

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting pull requests.

### Development Setup
```bash
# Clone repository
git clone https://github.com/yourusername/intrusion-detection-system.git

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 🛡️ Security Notice

⚠️ **Important**: This system is designed for educational and authorized testing purposes only. All attack simulations should be performed in controlled laboratory environments. Ensure you have proper authorization before testing on any network infrastructure.

---

**Built with ❤️**

*Last Updated: May 2025*
