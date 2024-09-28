# PRODIGY_CS_05
# Network Packet Analyzer - Prodigy Infotech Task 05

## Project Overview

This project is a **Network Packet Analyzer** developed as part of Task 05 for Prodigy Infotech. The tool captures and analyzes network packets in real-time and provides insightful packet statistics. The captured data is saved in a log file, categorized based on protocol types (TCP, UDP, HTTP), and includes visualization of the traffic patterns. The tool also triggers automatic alerts based on network conditions such as high TCP or HTTP traffic.

---

## Features

- **Packet Sniffing**: Real-time capture of network packets using `Scapy`.
- **Protocol Analysis**: Classifies packets by protocol (TCP, UDP, HTTP, Other).
- **Data Logging**: Stores packet data (time, protocol, source IP, destination IP, etc.) in a `.txt` file.
- **Packet Statistics Visualization**: Displays real-time statistics using `matplotlib` with bar graphs for different protocols.
- **Automatic Alerts**: Alerts triggered based on high TCP/HTTP traffic.
  
---

## Installation

### Prerequisites

1. **Python 3.x** installed on your system.
2. Install the necessary Python packages using `pip`:
   ```bash
   pip install scapy matplotlib
   ```

### Running the Script

1. Clone the repository:
   ```bash
   git clone https://github.com/JobanSingh0001/PRODIGY_CS_04.git
   cd PRODIGY_CS_04
   ```

2. Run the Python script with administrator privileges:
   ```bash
   sudo python3 packet_analyzer_with_stats.py
   ```

3. Specify the network interface in the code if needed (e.g., `"wlan0"` for Wi-Fi).

---

## Usage

1. Start the packet sniffing on your network interface.
2. Captured data will be saved in `packet_data.txt` for analysis.
3. Statistics will be displayed every 50 packets using `matplotlib`.
4. Alerts will trigger when TCP traffic exceeds 100 packets or HTTP traffic exceeds 50 packets.
   
**Example of logged data**:
```
Time: 2024-09-28 12:34:56.789000
Protocol: HTTP
Source IP: 192.168.1.100
Destination IP: 192.168.1.101
HTTP Request: www.example.com /index.html
========================================
```

---

## Future Improvements

- **HTTP Data Parsing**: Improve analysis of HTTP requests and responses.
- **Enhanced Alerts**: Add more conditions for network alerts (e.g., UDP flooding).
- **GUI**: Develop a graphical user interface to visualize packet data in real time.
- **Packet Filtering**: Add support for custom packet filters (e.g., capture only specific IPs or protocols).

---

## Contributing

If you would like to contribute, feel free to submit a pull request or open an issue to discuss the change.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

### Instructions for Updating
- You can replace `PRODIGY_CS_05` with your actual repository name if needed.
- Modify the features section and usage instructions based on the actual functionality of the tool.
- Make sure the file `LICENSE` exists if you choose to include a license.

This should give anyone visiting your GitHub repository a clear understanding of your project, how to install it, and what it does!
