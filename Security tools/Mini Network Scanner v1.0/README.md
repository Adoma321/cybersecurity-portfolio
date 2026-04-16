# 🔍 Mini Network Scanner GUI

A **modern Python-based Network Scanner with GUI**, inspired by tools like Nmap.  
This tool allows users to scan IP ranges, discover live hosts, detect open ports, perform banner grabbing, and export results into professional reports.

Built with a focus on **Cybersecurity, Networking, and GUI UX design**.

---

## 🚀 Features

### 🌐 Network Scanning
- IP range / CIDR / single IP support
- Live host discovery
- Fast multithreaded scanning

### 🔓 Port Scanning
- TCP connect-based scanning
- Custom port range support
- Detection of open ports per host

### 🧠 Banner Grabbing
- Extract service banners from open ports
- Basic service identification (SSH, HTTP, FTP, etc.)

### 📊 Real-time GUI
- Modern graphical interface (CustomTkinter / PyQt)
- Live scan logs
- Progress bar
- Status updates
- Clean results table

### 📁 Export Options
- Export results to **JSON**
- Generate professional **PDF reports**

### ⚡ Performance
- Multithreaded scanning using `ThreadPoolExecutor`
- Non-blocking GUI (no freezing)
- Optimized timeout handling

---

## 🖥️ Tech Stack

- Python 3
- socket
- scapy
- threading / concurrent.futures
- customtkinter / PyQt5 / PySide6
- json
- reportlab
- logging

---
▶️ How to Run

Run the application using:
**python main.py**
----
👨‍💻 Author (adoma321)

Built as a cybersecurity learning project focusing on:

Network reconnaissance
GUI application design
Python automation
Security tool development
⭐ If you like this project

Give it a star ⭐ and feel free to contribute or improve it  :)
