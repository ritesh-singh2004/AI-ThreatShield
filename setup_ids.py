import psutil
import socket
import json
import os
from datetime import datetime

print("=== CYBER SECURITY IDS COMPLETE SETUP ===")
print("Setting up intrusion detection system...")

# Create sample logs to test
sample_logs = [
    {
        "remote_address": "103.216.154.205:3389",
        "local_address": "192.168.1.5:54321",
        "pid": 1234,
        "status": "ESTABLISHED",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reason": "Suspicious port 3389 used - RDP Attack",
        "geolocation": {
            "city": "Beijing",
            "region": "Beijing",
            "country": "China",
            "isp": "China Telecom"
        }
    },
    {
        "remote_address": "45.67.89.123:445",
        "local_address": "192.168.1.5:54322",
        "pid": 5678,
        "status": "ESTABLISHED",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reason": "Suspicious port 445 used - SMB Exploit",
        "geolocation": {
            "city": "Moscow",
            "region": "Moscow Oblast",
            "country": "Russia",
            "isp": "Russian Telecom"
        }
    },
    {
        "pid": 9101,
        "name": "suspicious_service.exe",
        "cpu": 85.5,
        "memory": 45.2,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reason": "High resource usage detected - Possible Miner"
    }
]

# Save logs
with open("intrusion_logs.json", "w") as f:
    json.dump(sample_logs, f, indent=4)

print("✅ Sample logs created: intrusion_logs.json")
print(f"✅ Created {len(sample_logs)} sample threat entries")

# Create system info
print("\n=== CURRENT SYSTEM STATUS ===")
print(f"CPU Usage: {psutil.cpu_percent()}%")
print(f"Memory Usage: {psutil.virtual_memory().percent}%")
print(f"Hostname: {socket.gethostname()}")
print(f"IP Address: {socket.gethostbyname(socket.gethostname())}")

# Check network connections
print("\n=== ACTIVE CONNECTIONS ===")
try:
    connections = psutil.net_connections()
    print(f"Total connections: {len(connections)}")
    
    for conn in connections[:5]:  # First 5 connections
        if conn.raddr:
            print(f"  → {conn.raddr.ip}:{conn.raddr.port}")
except:
    print("Could not retrieve connections")

print("\n=== SETUP COMPLETE ===")
print("Now run: python ids_detector.py")