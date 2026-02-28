import psutil
import socket
import datetime
import time
import json
import os
import random
from datetime import datetime

class EnhancedIntrusionDetection:
    def __init__(self):
        self.log_file = "intrusion_logs.json"
        self.suspicious_ips = [
            "103.216.154.205",  # China
            "45.67.89.123",     # Russia
            "192.187.123.45",   # Unknown
            "34.56.78.90",      # USA
            "78.91.234.56"      # Germany
        ]
        
    def generate_fake_attack(self):
        """Test ke liye fake attack generate karein"""
        attack_types = [
            {
                "type": "port_scan",
                "port": random.choice([22, 23, 3389, 445, 4444, 5555]),
                "ip": random.choice(self.suspicious_ips)
            },
            {
                "type": "process_injection",
                "process": random.choice(["svchost.exe", "explorer.exe", "chrome.exe"]),
                "cpu": random.randint(80, 99)
            },
            {
                "type": "ddos_attempt",
                "ip": random.choice(self.suspicious_ips),
                "port": 80
            }
        ]
        
        return random.choice(attack_types)
    
    def detect_real_threats(self):
        """Real threats detect karein"""
        threats = []
        
        # Real connections check
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    
                    # Suspicious ports
                    if port in [22, 23, 3389, 445, 4444]:
                        threat = {
                            "type": "REAL",
                            "remote_address": f"{ip}:{port}",
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "pid": conn.pid,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "reason": f"Real suspicious port detected: {port}",
                            "status": "HIGH"
                        }
                        threats.append(threat)
        except:
            pass
        
        return threats
    
    def run_detection_cycle(self):
        """Ek complete detection cycle"""
        print("\n" + "="*60)
        print("🔍 ENHANCED THREAT DETECTION CYCLE")
        print("="*60)
        
        all_threats = []
        
        # Real threats detect karein
        real_threats = self.detect_real_threats()
        if real_threats:
            print(f"🚨 REAL THREATS FOUND: {len(real_threats)}")
            all_threats.extend(real_threats)
        
        # Fake attack generate karein (demo ke liye)
        if random.random() > 0.5:  # 50% chance fake attack
            fake_attack = self.generate_fake_attack()
            
            if fake_attack["type"] == "port_scan":
                threat = {
                    "type": "DEMO",
                    "remote_address": f"{fake_attack['ip']}:{fake_attack['port']}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "reason": f"Port scan detected on port {fake_attack['port']}",
                    "geolocation": self.get_fake_location(fake_attack['ip']),
                    "status": "MEDIUM"
                }
            elif fake_attack["type"] == "process_injection":
                threat = {
                    "type": "DEMO",
                    "process_name": fake_attack["process"],
                    "cpu_usage": fake_attack["cpu"],
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "reason": f"Process injection detected: {fake_attack['process']}",
                    "status": "HIGH"
                }
            else:
                threat = {
                    "type": "DEMO",
                    "remote_address": f"{fake_attack['ip']}:{fake_attack['port']}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "reason": "DDoS attempt detected",
                    "geolocation": self.get_fake_location(fake_attack['ip']),
                    "status": "CRITICAL"
                }
            
            all_threats.append(threat)
            print(f"📊 DEMO THREAT GENERATED: {fake_attack['type']}")
        
        # Save threats
        if all_threats:
            self.save_threats(all_threats)
            print(f"✅ Total threats logged: {len(all_threats)}")
            
            # Display threats
            print("\n📋 THREAT DETAILS:")
            for i, threat in enumerate(all_threats, 1):
                print(f"\nThreat #{i}:")
                for key, value in threat.items():
                    if key != "type":
                        print(f"  {key}: {value}")
        else:
            print("✅ No threats detected this cycle")
        
        return len(all_threats)
    
    def get_fake_location(self, ip):
        """Fake geolocation generate karein"""
        locations = {
            "103.216.154.205": {"city": "Beijing", "country": "China", "isp": "China Telecom"},
            "45.67.89.123": {"city": "Moscow", "country": "Russia", "isp": "Russian Telecom"},
            "192.187.123.45": {"city": "Unknown", "country": "Unknown", "isp": "Hidden"},
            "34.56.78.90": {"city": "New York", "country": "USA", "isp": "AWS"},
            "78.91.234.56": {"city": "Berlin", "country": "Germany", "isp": "Deutsche Telekom"}
        }
        return locations.get(ip, {"city": "Unknown", "country": "Unknown", "isp": "Unknown"})
    
    def save_threats(self, threats):
        """Threats save karein"""
        existing = []
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                try:
                    existing = json.load(f)
                except:
                    existing = []
        
        # Original code me ye change karein:
                threat = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
# Ensure it's always string format
        
        with open(self.log_file, 'w') as f:
            json.dump(existing, f, indent=4)
    
    def display_current_status(self):
        """Current system status display karein"""
        print("\n📊 SYSTEM STATUS:")
        print(f"  CPU Usage: {psutil.cpu_percent()}%")
        print(f"  Memory Usage: {psutil.virtual_memory().percent}%")
        print(f"  Disk Usage: {psutil.disk_usage('C:/').percent if os.name == 'nt' else psutil.disk_usage('/').percent}%")
        print(f"  Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"  Log File: {self.log_file}")

def main():
    detector = EnhancedIntrusionDetection()
    
    print("🚀 ENHANCED CYBER SECURITY IDS STARTED")
    print("Press Ctrl+C to stop\n")
    
    cycle = 1
    total_threats = 0
    
    while True:
        try:
            print(f"\n🔁 CYCLE #{cycle}")
            detector.display_current_status()
            
            threats = detector.run_detection_cycle()
            total_threats += threats
            
            print(f"\n📈 TOTAL THREATS SO FAR: {total_threats}")
            print(f"⏳ Next scan in 15 seconds...")
            
            time.sleep(15)
            cycle += 1
            
        except KeyboardInterrupt:
            print(f"\n\n🛑 System stopped. Total threats detected: {total_threats}")
            print(f"📁 Logs saved to: intrusion_logs.json")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()