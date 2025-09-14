#!/usr/bin/env python3
import os
import datetime
import c104
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGFILE = os.path.join(BASE_DIR, "ampdefend.log")

def log_event(msg: str):
    print(msg)
    with open(LOGFILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {msg}\n")

def main():
    log_event("Starting IEC104 Honeypot via c104 library on port 2404")
    
    server = c104.Server(ip="0.0.0.0", port=2404)
    station = server.add_station(common_address=1)
    station.add_point(io_address=100, type=c104.Type.M_ME_NC_1, report_ms=5000)
    
    # Define callback functions
    def on_receive_raw(server, data):
        # This gets called when any data is received
        client_ip = server.get_client_ip() if hasattr(server, 'get_client_ip') else "unknown"
        log_event(f"IEC104 connection from {client_ip}")
        log_event(f"IEC104 Interrogation from {client_ip}")
    
    def on_connect(server):
        log_event("IEC104 connection established")
    
    # Register callbacks with the server
    server.on_receive_raw = on_receive_raw
    server.on_connect = on_connect
    
    server.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_event("IEC104 Honeypot stopped")
        server.stop()

if __name__ == "__main__":
    main()

