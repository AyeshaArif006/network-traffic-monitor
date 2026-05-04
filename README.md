# Network-traffic-monitor
A real time network packet sniffer with a live web dashboard. Built with Python, Scapy, and Flask. Captures TCP, UDP, and ICMP traffic and displays it in your browser as it happens.
# Features

Live packet capture — real-time sniffing via Scapy with Server-Sent Events.

Protocol detection — TCP, UDP, ICMP identification with color coding.

Service recognition — maps common port numbers (80, 443, 53, 22, etc.) to readable names

Live statistics — total packets, protocol breakdown, and average packet size

Filtering — filter by protocol, source IP, or destination IP on the fly

CSV export — all captured packets are automatically saved to packets.csv

Activity log — real-time event log panel in the dashboard
# network-traffic-monitor
│
├── app.py             
├── sniffer.py               
│
└── templates/
    └── index.html    

# Getting Started
Prerequisites:
Python 3.8+

pip package manager

Root / Administrator privileges( required by Scapy for raw packet access)

# Installation

Clone the repository

bash   git clone https://github.com/AyeshaArif006/network-traffic-monitor.git
   cd network-traffic-monitor

# Install dependencies

bash   pip install flask scapy

-Run the app

On Linux / macOS (requires sudo for packet capture):
sudo python app.py

On Windows (run terminal as Administrator):
bash   python app.py

# Open the dashboard
Visit http://localhost:5000 in your browser

# Packet Data Format
Each captured packet is recorded as a JSON object / CSV row with these fields:
{

  "time":     "14:23:01",
  "src_ip":   "192.168.1.5",
  "dst_ip":   "8.8.8.8",
  "protocol": "UDP",
  "size":     74,
  "src_port": 54321,
  "dst_port": 53,
  "service":  "DNS"
  
}

# Important Notes

Permissions:Scapy requires elevated privileges to capture raw packets. Always run with sudo (Linux/macOS) or as Administrator (Windows).

Legal & ethical use:only capture traffic on networks you own or have explicit permission to monitor. Unauthorized packet sniffing may violate laws in your jurisdiction.

Performance:the dashboard renders up to the latest 200 packets at a time to keep the UI responsive. All packets are still saved to the CSV regardless.

Firewall / antivirus:some security software may flag or block raw packet capture. You may need to add an exception.
