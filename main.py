from flask import Flask, render_template
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import time

# Configuration and stateful data structures as you've defined...

# Anomaly detection functions as you've defined...

# Flask app setup as you've defined...

if __name__ == '__main__':
    # Start packet sniffing in a separate thread as you've defined...
    sniffing_thread = threading.Thread(target=lambda: sniff(prn= packet_callback , filter="ip", store=False))
    sniffing_thread.start()

    # Run the Flask app as you've defined...
    app.run(debug=True, use_reloader=False)
