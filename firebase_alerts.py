#!/usr/bin/env python3
import json
import requests
import time
import os
from datetime import datetime

# Firebase Configuration
FIREBASE_URL = "https://ampdefender-9bf8e-default-rtdb.firebaseio.com/"
FIREBASE_API_KEY = None  # Optional for auth

# File paths
ALERTS_FILE = "/home/raspberrypi/ampdefend/ampdefend_alerts.log"
BLOCKED_IPS_FILE = "/home/raspberrypi/ampdefend/blocked_ips.txt"
OFFSET_FILE = "/home/raspberrypi/ampdefend/.firebase_offset"

def read_offset():
    """Read the last processed file position"""
    try:
        with open(OFFSET_FILE, 'r') as f:
            return int(f.read().strip())
    except:
        return 0

def write_offset(offset):
    """Write the current file position"""
    with open(OFFSET_FILE, 'w') as f:
        f.write(str(offset))

def parse_alert_line(line):
    """Parse an alert log line into structured data"""
    line = line.strip()
    if not line:
        return None
    
    # Extract timestamp (assuming format: "Day Mon DD HH:MM:SS TZ YYYY")
    parts = line.split(" - ", 1)
    if len(parts) != 2:
        return None
    
    timestamp_str = parts[0]
    message = parts[1]
    
    # Parse different types of alerts
    alert_data = {
        "timestamp": timestamp_str,
        "raw_message": message,
        "alert_type": "unknown",
        "severity": "medium"
    }
    
    # Categorize alerts
    if "ALERT: Intrusion detected!" in message:
        alert_data["alert_type"] = "intrusion_detected"
        alert_data["severity"] = "high"
    elif "Would have blocked IP" in message or "Blocked IP" in message:
        alert_data["alert_type"] = "ip_blocked"
        alert_data["severity"] = "high"
        # Extract IP address
        words = message.split()
        for word in words:
            if word.count('.') == 3:  # Simple IP detection
                alert_data["blocked_ip"] = word
                break
    elif "VPN likelihood" in message:
        alert_data["alert_type"] = "vpn_analysis"
        alert_data["severity"] = "low"
        # Extract VPN percentage
        if "%" in message:
            try:
                percentage = message.split("%")[0].split()[-1]
                alert_data["vpn_likelihood"] = int(percentage)
            except:
                pass
    
    return alert_data

def send_to_firebase(data, endpoint="alerts"):
    """Send data to Firebase Realtime Database"""
    url = f"{FIREBASE_URL}/{endpoint}.json"
    
    if FIREBASE_API_KEY:
        url += f"?auth={FIREBASE_API_KEY}"
    
    try:
        response = requests.post(url, json=data, timeout=10)
        response.raise_for_status()
        return True, response.json()
    except requests.RequestException as e:
        return False, str(e)

def send_blocked_ips():
    """Send current blocked IPs list to Firebase"""
    try:
        with open(BLOCKED_IPS_FILE, 'r') as f:
            blocked_ips = [ip.strip() for ip in f.readlines() if ip.strip()]
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "blocked_ips": blocked_ips,
            "total_blocked": len(blocked_ips)
        }
        
        success, result = send_to_firebase(data, "blocked_ips")
        if success:
            print(f"✅ Uploaded {len(blocked_ips)} blocked IPs to Firebase")
        else:
            print(f"❌ Failed to upload blocked IPs: {result}")
            
    except Exception as e:
        print(f"❌ Error reading blocked IPs: {e}")

def monitor_alerts():
    """Monitor alerts file and upload new alerts to Firebase"""
    print("🔥 Starting Firebase alerts uploader...")
    print(f"📁 Monitoring: {ALERTS_FILE}")
    print(f"🌐 Firebase URL: {FIREBASE_URL}")
    
    while True:
        try:
            # Check if alerts file exists
            if not os.path.exists(ALERTS_FILE):
                print("⏳ Waiting for alerts file...")
                time.sleep(10)
                continue
            
            # Get current file size
            current_size = os.path.getsize(ALERTS_FILE)
            last_offset = read_offset()
            
            # Check if file has new content
            if current_size > last_offset:
                print(f"📊 New alerts detected (size: {current_size}, offset: {last_offset})")
                
                with open(ALERTS_FILE, 'r') as f:
                    f.seek(last_offset)
                    new_content = f.read()
                
                # Process each new line
                new_lines = new_content.strip().split('\n')
                alerts_sent = 0
                
                for line in new_lines:
                    if line.strip():
                        alert_data = parse_alert_line(line)
                        if alert_data:
                            # Add metadata
                            alert_data["device_id"] = "raspberrypi"
                            alert_data["uploaded_at"] = datetime.now().isoformat()
                            
                            success, result = send_to_firebase(alert_data)
                            if success:
                                print(f"✅ Alert uploaded: {alert_data['alert_type']}")
                                alerts_sent += 1
                            else:
                                print(f"❌ Failed to upload alert: {result}")
                
                # Update offset
                write_offset(current_size)
                print(f"📤 Uploaded {alerts_sent} new alerts")
                
                # Also update blocked IPs periodically
                send_blocked_ips()
            
            # Wait before checking again
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\n👋 Stopping Firebase uploader...")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            time.sleep(10)

def upload_existing_alerts():
    """One-time upload of all existing alerts"""
    print("📚 Uploading all existing alerts...")
    
    try:
        with open(ALERTS_FILE, 'r') as f:
            lines = f.readlines()
        
        alerts_sent = 0
        for line in lines:
            if line.strip():
                alert_data = parse_alert_line(line)
                if alert_data:
                    alert_data["device_id"] = "raspberrypi"
                    alert_data["uploaded_at"] = datetime.now().isoformat()
                    
                    success, result = send_to_firebase(alert_data)
                    if success:
                        alerts_sent += 1
                    else:
                        print(f"❌ Failed to upload: {result}")
        
        print(f"✅ Uploaded {alerts_sent} historical alerts")
        
        # Set offset to current file size
        write_offset(os.path.getsize(ALERTS_FILE))
        
    except Exception as e:
        print(f"❌ Error uploading existing alerts: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--upload-all":
        upload_existing_alerts()
    else:
        monitor_alerts()
