# port-scanner-python
A multi-threaded Python port scanner with banner grabbing and service detection, built to explore practical cybersecurity concepts
# 🔐 Python Port Scanner

A fast and lightweight multi-threaded port scanner built in Python.  
This project was created to understand how network ports, services, and basic cybersecurity scanning work in real-world systems.

## 🚀 Features

- Multi-threaded scanning for faster performance  
- Supports custom port ranges and lists  
- Banner grabbing for service identification  
- Service detection for common ports  
- Command-line interface (CLI)  
- Option to save scan results to a file  

## 🛠️ Tech Stack

- Python  
- Socket Programming  
- Threading  

## 📌 Usage

```bash
python port_scanner.py example.com
python port_scanner.py 192.168.1.1 -p 1-1000
python port_scanner.py scanme.nmap.org -p 80,443 -v
