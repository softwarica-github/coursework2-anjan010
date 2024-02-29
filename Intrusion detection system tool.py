from flask import Flask, render_template
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import time

# Configuration for anomaly detection
MAX_PACKET_SIZE = 1500  # Maximum packet size in bytes for normal traffic
REQUEST_THRESHOLD = 100  # Number of requests to a single port before triggering an alert
ALERT_LOG_FILE = "ids_alerts.log"

# Stateful data structures
packet_sizes = defaultdict(list)
port_requests = defaultdict(int)
connection_states = defaultdict(lambda: {"start": None, "packet_count": 0})
alerts = []  # Alerts list for the web dashboard

# Check anomalies in each packet
def check_anomalies(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_dport = packet[TCP].dport
        packet_size = len(packet)

        # Anomaly detection based on packet size
        if packet_size > MAX_PACKET_SIZE:
            log_alert(f"Large packet: Size {packet_size} from {ip_src} to {ip_dst}")

        # Frequency analysis for port requests
        port_requests[tcp_dport] += 1
        if port_requests[tcp_dport] > REQUEST_THRESHOLD:
            log_alert(f"High request volume to port {tcp_dport} from {ip_src}")

        # Track connections
        if not connection_states[(ip_src, ip_dst, tcp_dport)]["start"]:
            connection_states[(ip_src, ip_dst, tcp_dport)]["start"] = time.time()
        connection_states[(ip_src, ip_dst, tcp_dport)]["packet_count"] += 1

# Log alerts to console and file, and add to web dashboard list
def log_alert(message):
    print(f"ALERT: {message}")
    with open(ALERT_LOG_FILE, "a") as file:
        file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    alerts.append(message)  # Add alert to the list for the web dashboard

# Callback for Scapy sniffing
def packet_callback(packet):
    check_anomalies(packet)

# Flask web server setup
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', alerts=alerts)

if __name__ == '__main__':
    # Start the packet sniffing in a separate thread
    sniffing_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, filter="ip", store=False))
    sniffing_thread.start()

    # Run the Flask app
    app.run(debug=True, use_reloader=False)
