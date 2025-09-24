# VoIP Traffic Analyzer

## Description
This Python project captures and analyzes VoIP RTP packets on your local network. It prints sequence number, timestamp, and payload type for each RTP packet. 

## Features
- Sniff RTP packets
- Extract and display packet information
- Safe to run on your own network

## Requirements
- Python 3.x
- Scapy library

## How to Install
Install Scapy:
```
pip install scapy
```

## How to Run
1. Clone the repository:
```
git clone https://github.com/TanakaShumba/voip-traffic-analyzer.git
```
2. Navigate to the folder:
```
cd voip-traffic-analyzer
```
3. Run the analyzer:
```
python voip_analyzer.py
```

## Notes
- Only run on networks you own or have permission to monitor.
