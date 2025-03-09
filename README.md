
# **Network Scanning Tool**

This is a Python-based network scanning tool built using the scapy library. It supports various network scanning techniques, including host discovery, OS detection, and port scanning. The tool is designed to be user-friendly, allowing users to select a scanning technique from a menu and providing detailed output based on the selected scan.

# 🚀 Features
The tool supports the following scanning techniques:

##  **Host Discovery**

1) ICMP Ping

2) TCP ACK Ping

3) SCTP Init Ping (Not Available)

4) ICMP Timestamp Ping

5) ICMP Address Mask Ping

6) ARP Ping

7) Find MAC Address of Victim

## **OS Discovery**
8) OS Detection (based on TTL or any suitable method)

## **Port Scanning**

9) Port Scanning

10) TCP Connect Scan

11) UDP Scan

12) TCP Null Scan

13) TCP FIN Scan

14) Xmas Scan

15) TCP ACK Scan

16) TCP Window Scan

17) TCP Maimon Scan

17) IP Protocol Scan


## 🛠️ Prerequisites/Dependencies

**Operating System:**
Linux (Debian-based distributions recommended).

**Required Libraries:**

- Scapy: For packet crafting and network scanning.

Install using:
```bash
pip install scapy
```

**Visual Studio Code (VS Code):**

  - Download and install from the official website.

  - Install the Python extension for VS Code to enable Python development.


## 👩‍💻 Usage

- **Run the Tool:**

    Open the terminal in the project directory and **run the script with sudo privileges**:

```python
sudo python3 Network-Scanning-Tool.py
```
- **Follow the Menu:**

  The tool will display a menu of scanning techniques.

  Enter the number corresponding to the desired scan.

  Provide the target IP address or network range when prompted.

- **View Results:**

  The tool will display detailed output based on the selected scan.

## 🤝 Authors

[@Abdul-Moeez4](https://github.com/Abdul-Moeez4)


## 📝 License
This project is licensed under the MIT License.

Feel free to contribute, report issues, or suggest new features!

