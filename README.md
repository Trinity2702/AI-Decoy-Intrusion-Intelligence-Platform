# AI-Powered Decoy-Based Intrusion Intelligence System with Real-Time Vulnerability Assessment

## 📌 Overview

This project presents an AI-powered cybersecurity monitoring platform designed to simulate, detect, analyze, and visualize malicious intrusion activities within a controlled virtualized environment. The system combines honeypot technology, machine learning-based anomaly detection, NLP-driven command analysis, and real-time dashboard visualization to improve intrusion intelligence and attacker behavior monitoring.

The platform captures attacker activities using the Cowrie SSH honeypot, processes intrusion logs through Python-based analytics pipelines, applies anomaly detection using Isolation Forest, and displays threat intelligence through an interactive Streamlit dashboard.

---

## 🎯 Objectives

* Deploy a realistic SSH honeypot environment
* Capture and analyze attacker behavior
* Perform real-time intrusion monitoring
* Detect anomalous sessions using machine learning
* Visualize attack analytics through an interactive dashboard
* Simulate vulnerability assessment using Nmap
* Improve cybersecurity intelligence using AI and NLP techniques

---

## 🏗️ System Architecture

The project architecture consists of:

* Kali Linux attacker machine
* Ubuntu-based Cowrie honeypot server
* Real-time JSON log collection
* AI/ML anomaly detection engine
* NLP-based command classification
* Streamlit visualization dashboard
* Nmap-based vulnerability assessment module

---

## 🧠 Key Features

### 🔹 Honeypot-Based Intrusion Capture

* SSH-based decoy environment using Cowrie
* Captures login attempts, commands, sessions, and attacker interactions

### 🔹 AI/ML Anomaly Detection

* Isolation Forest-based anomaly detection
* Behavioral session analysis
* Suspicious activity identification

### 🔹 NLP Command Analysis

* Command classification and behavioral interpretation
* Detection of malicious reconnaissance and payload activity

### 🔹 Real-Time Dashboard

* Streamlit-based interactive dashboard
* Live intrusion analytics and visualizations
* Attack trends and statistics

### 🔹 Vulnerability Assessment

* Nmap-based scanning and service enumeration
* Open port and service analysis

### 🔹 Multi-Attacker Simulation

* Multiple simulated attacker IPs
* Realistic intrusion intelligence generation

---

## 🛠️ Technologies Used

| Technology    | Purpose                     |
| ------------- | --------------------------- |
| Python        | Backend analytics and ML    |
| Cowrie        | SSH Honeypot                |
| Streamlit     | Dashboard visualization     |
| Scikit-learn  | Machine learning            |
| Pandas        | Log processing              |
| Plotly        | Interactive charts          |
| VirtualBox    | Virtualized lab environment |
| Kali Linux    | Attack simulation           |
| Ubuntu Server | Honeypot deployment         |
| Nmap          | Vulnerability assessment    |

---

## 📊 Machine Learning Model

### Isolation Forest

The project uses Isolation Forest, an unsupervised anomaly detection algorithm, to identify suspicious intrusion behavior based on attacker session patterns, command frequency, and login activity.

---

## 🌐 Virtualized Lab Environment

The system was deployed inside an isolated VirtualBox-based virtualized environment consisting of:

* Ubuntu honeypot server
* Kali Linux attacker machine
* Host-only networking for secure attack simulation

---

## 📈 Dashboard Functionalities

* Real-time intrusion monitoring
* Attack source tracking
* Session analytics
* Command monitoring
* Threat statistics visualization
* AI-based anomaly identification
* Vulnerability scan visualization

---

## 🔐 Cybersecurity Concepts Implemented

* Honeypot technology
* Intrusion intelligence
* Threat monitoring
* Behavioral analysis
* Anomaly detection
* Vulnerability assessment
* MITRE ATT&CK mapping
* SSH attack simulation

---

## 🚀 Future Enhancements

* SIEM integration using Wazuh/ELK Stack
* Real-time Telegram and email alerting
* Threat intelligence API integration
* Geo-location based attack analytics
* Dockerized deployment
* Deep learning-based threat prediction
* Multi-honeypot distributed deployment

---

## 📷 Project Screenshots

<img width="984" height="468" alt="image" src="https://github.com/user-attachments/assets/6952b29d-6465-4f7e-a6bc-cf2454625cd2" />
<img width="984" height="469" alt="image" src="https://github.com/user-attachments/assets/8c3e72ce-abfb-4c02-bca8-911f6c41184f" />
<img width="981" height="572" alt="image" src="https://github.com/user-attachments/assets/26dcc05a-4edc-42ed-97e2-530d65f710cb" />
<img width="985" height="689" alt="image" src="https://github.com/user-attachments/assets/9f493aac-9571-41c1-ba51-30bcaecfbec5" />
<img width="986" height="789" alt="image" src="https://github.com/user-attachments/assets/32437cd6-c43f-4899-af36-9c91e4340ac1" />
<img width="985" height="604" alt="image" src="https://github.com/user-attachments/assets/11e498b9-0766-4b94-9a12-2ca70918296c" />


---

## 📚 Academic Context

This project was developed as part of the B.Tech Information Technology major project at Manipal University Jaipur.

---

## 👨‍💻 Authors

* Ishaan Samal

