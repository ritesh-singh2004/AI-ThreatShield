import psutil
import socket
import datetime
import time
import json
import os
from datetime import datetime
import requests
import pandas as pd

class IntrusionDetectionSystem:
    def __init__(self):
        self.log_file = "intrusion_logs.json"
        self.suspicious_activities = []
        self.whitelist_ips = ["127.0.0.1", "192.168.1.1"]  # Apne trusted IPs
        
    def get_system_info(self):
        """System ki current information get kare"""
        info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent if os.name == 'posix' else psutil.disk_usage('C:/').percent
        }
        return info
    
    def check_network_connections(self):
        """Active network connections check kare"""
        suspicious_connections = []
        
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Suspicious ports check kare
                    suspicious_ports = [22, 23, 3389, 4444, 5555, 6666, 7777, 8888]
                    
                    if remote_port in suspicious_ports:
                        suspicious_connections.append({
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote_address": f"{remote_ip}:{remote_port}",
                            "pid": conn.pid,
                            "status": conn.status,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "reason": f"Suspicious port {remote_port} used"
                        })
                    
                    # Unknown IPs check kare
                    if remote_ip not in self.whitelist_ips and not remote_ip.startswith("192.168."):
                        suspicious_connections.append({
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote_address": f"{remote_ip}:{remote_port}",
                            "pid": conn.pid,
                            "status": conn.status,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "reason": f"Connection from unknown IP: {remote_ip}"
                        })
                        
        except Exception as e:
            print(f"Error checking connections: {e}")
            
        return suspicious_connections
    
    def check_processes(self):
        """Suspicious processes check kare"""
        suspicious_processes = []
        suspicious_keywords = [
            "keylogger", "rat", "backdoor", "rootkit", 
            "meterpreter", "exploit", "injector", "hack"
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                
                # Suspicious name check
                for keyword in suspicious_keywords:
                    if keyword in proc_name:
                        suspicious_processes.append({
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "cpu": proc_info['cpu_percent'],
                            "memory": proc_info['memory_percent'],
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "reason": f"Process name contains suspicious keyword: {keyword}"
                        })
                        break
                
                # High resource usage check
                if proc_info['cpu_percent'] > 80 or proc_info['memory_percent'] > 80:
                    suspicious_processes.append({
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "cpu": proc_info['cpu_percent'],
                        "memory": proc_info['memory_percent'],
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "reason": "High resource usage detected"
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return suspicious_processes
    
    def get_geolocation(self, ip_address):
        """IP address ki geolocation find kare"""
        try:
            if ip_address.startswith(("192.168.", "10.", "172.16.", "127.")):
                return {
                    "city": "Local Network",
                    "region": "Private IP",
                    "country": "N/A",
                    "isp": "Local Network"
                }
                
            response = requests.get(f"http://ip-api.com/json/{ip_address}")
            data = response.json()
            
            if data["status"] == "success":
                return {
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "isp": data.get("isp", "Unknown")
                }
        except:
            pass
            
        return {
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "isp": "Unknown"
        }
    
    def save_logs(self, data):
        """Logs save kare JSON file me"""
        try:
            # Purane logs read kare
            existing_logs = []
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    existing_logs = json.load(f)
            
            # Naye logs add kare
            if isinstance(data, list):
                existing_logs.extend(data)
            else:
                existing_logs.append(data)
            
            # Save kare
            with open(self.log_file, 'w') as f:
                json.dump(existing_logs, f, indent=4)
                
        except Exception as e:
            print(f"Error saving logs: {e}")
    
    def run_detection(self):
        """Main detection function"""
        print("=" * 60)
        print("CYBER SECURITY INTRUSION DETECTION SYSTEM")
        print("=" * 60)
        
        # System info collect kare
        system_info = self.get_system_info()
        print(f"\n[SYSTEM INFO] Time: {system_info['timestamp']}")
        print(f"CPU Usage: {system_info['cpu_usage']}% | "
              f"Memory: {system_info['memory_usage']}% | "
              f"Disk: {system_info['disk_usage']}%")
        
        # Network connections check
        print("\n[CHECKING NETWORK CONNECTIONS...]")
        suspicious_connections = self.check_network_connections()
        
        if suspicious_connections:
            print(f"[WARNING]  {len(suspicious_connections)} SUSPICIOUS CONNECTIONS FOUND!")
            for conn in suspicious_connections:
                print(f"\n   From: {conn['remote_address']}")
                print(f"   To: {conn['local_address']}")
                print(f"   Reason: {conn['reason']}")
                print(f"   Time: {conn['timestamp']}")
                
                # Geolocation find kare
                ip = conn['remote_address'].split(':')[0]
                geo = self.get_geolocation(ip)
                print(f"   Location: {geo['city']}, {geo['region']}, {geo['country']}")
                print(f"   ISP: {geo['isp']}")
                
                # Log me save kare
                conn['geolocation'] = geo
                self.save_logs(conn)
        else:
            print("[OK] No suspicious connections found")
        
        # Processes check
        print("\n[CHECKING RUNNING PROCESSES...]")
        suspicious_processes = self.check_processes()
        
        if suspicious_processes:
            print(f"[WARNING]  {len(suspicious_processes)} SUSPICIOUS PROCESSES FOUND!")
            for proc in suspicious_processes:
                print(f"\n   Process: {proc['name']} (PID: {proc['pid']})")
                print(f"   CPU: {proc['cpu']}% | Memory: {proc['memory']}%")
                print(f"   Reason: {proc['reason']}")
                print(f"   Time: {proc['timestamp']}")
                
                self.save_logs(proc)
        else:
            print("[OK] No suspicious processes found")
        
        print("\n" + "=" * 60)
        print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Logs saved to: {self.log_file}")
        print("=" * 60)
        
        return len(suspicious_connections) + len(suspicious_processes)

def main():
    ids = IntrusionDetectionSystem()
    
    while True:
        try:
            threats_detected = ids.run_detection()
            
            if threats_detected > 0:
                print(f"\n[ALERT] ALERT: {threats_detected} potential threats detected!")
                # Yaha pe aap alert bhej sakte hain (email, notification, etc.)
            
            # 30 seconds wait kare next scan se pehle
            print("\nNext scan in 30 seconds... (Press Ctrl+C to stop)")
            time.sleep(30)
            
        except KeyboardInterrupt:
            print("\n\n🛑 Intrusion Detection System stopped by user")
            break
        except Exception as e:
            print(f"\n[ERROR] Error occurred: {e}")
            time.sleep(60)  # Error hone par 1 minute wait kare

if __name__ == "__main__":
    main()