"""
COMPLETE CYBER SECURITY SYSTEM - FIXED VERSION
All in one file - No errors
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ==================== SYSTEM IMPORTS ====================
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Note: Install psutil for full features: pip install psutil")

# ==================== 1. INTRUSION DETECTION SYSTEM ====================
class IntrusionDetectionSystem:
    def __init__(self):
        self.log_file = "intrusion_logs.json"
        self.whitelist_ips = ["127.0.0.1", "192.168.1.1"]
    
    def get_system_info(self):
        """System information"""
        if not PSUTIL_AVAILABLE:
            return {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        
        info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
        }
        
        try:
            if os.name == 'nt':
                info["disk_usage"] = psutil.disk_usage('C:/').percent
            else:
                info["disk_usage"] = psutil.disk_usage('/').percent
        except:
            info["disk_usage"] = 0
        
        return info
    
    def check_network_connections(self):
        """Check network connections"""
        suspicious_connections = []
        
        if not PSUTIL_AVAILABLE:
            return suspicious_connections
        
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Check suspicious ports
                    suspicious_ports = [22, 23, 3389, 4444, 5555]
                    
                    if remote_port in suspicious_ports:
                        suspicious_connections.append({
                            "remote_address": f"{remote_ip}:{remote_port}",
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "reason": f"Suspicious port {remote_port} used"
                        })
                    
                    # Check unknown IPs
                    if remote_ip not in self.whitelist_ips and not remote_ip.startswith("192.168."):
                        suspicious_connections.append({
                            "remote_address": f"{remote_ip}:{remote_port}",
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "reason": f"Connection from unknown IP: {remote_ip}"
                        })
                        
        except Exception as e:
            print(f"Network check error: {e}")
            
        return suspicious_connections
    
    def check_processes(self):
        """Check suspicious processes"""
        suspicious_processes = []
        
        if not PSUTIL_AVAILABLE:
            return suspicious_processes
        
        suspicious_keywords = ["keylogger", "rat", "backdoor", "rootkit", "exploit"]
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                
                # Check suspicious keywords
                for keyword in suspicious_keywords:
                    if keyword in proc_name:
                        suspicious_processes.append({
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "cpu": proc_info['cpu_percent'],
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "reason": f"Process contains keyword: {keyword}"
                        })
                        break
                
                # Check high CPU usage
                if proc_info['cpu_percent'] > 80:
                    suspicious_processes.append({
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "cpu": proc_info['cpu_percent'],
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "reason": "High CPU usage"
                    })
                    
            except:
                continue
                
        return suspicious_processes
    
    def save_logs(self, data):
        """Save logs to JSON file"""
        try:
            existing_logs = []
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    existing_logs = json.load(f)
            
            if isinstance(data, list):
                existing_logs.extend(data)
            else:
                existing_logs.append(data)
            
            with open(self.log_file, 'w') as f:
                json.dump(existing_logs, f, indent=4)
                
        except Exception as e:
            print(f"Error saving logs: {e}")
    
    def run_detection(self, callback=None):
        """Run detection scan"""
        threats_found = 0
        
        # Get system info
        system_info = self.get_system_info()
        
        # Check network
        suspicious_connections = self.check_network_connections()
        threats_found += len(suspicious_connections)
        
        # Check processes
        suspicious_processes = self.check_processes()
        threats_found += len(suspicious_processes)
        
        # Save threats
        all_threats = suspicious_connections + suspicious_processes
        if all_threats:
            self.save_logs(all_threats)
        
        # Callback for GUI
        if callback:
            callback(threats_found, system_info, all_threats)
        
        return threats_found, system_info, all_threats

# ==================== 2. LOG ANALYZER ====================
class LogAnalyzer:
    def __init__(self):
        self.log_file = "intrusion_logs.json"
    
    def load_logs(self):
        """Load logs from file"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    return json.load(f)
            return []
        except:
            return []
    
    def analyze_logs(self):
        """Analyze logs and return text"""
        logs = self.load_logs()
        
        if not logs:
            return "No logs found."
        
        analysis = []
        analysis.append("="*50)
        analysis.append("SECURITY LOG ANALYSIS")
        analysis.append("="*50)
        analysis.append(f"Total logs: {len(logs)}")
        
        # Count by reason
        reasons = {}
        for log in logs:
            reason = log.get('reason', 'Unknown')
            reasons[reason] = reasons.get(reason, 0) + 1
        
        if reasons:
            analysis.append("\nEvent Types:")
            for reason, count in reasons.items():
                analysis.append(f"  {reason}: {count} times")
        
        # Time analysis
        timestamps = [log.get('timestamp', '') for log in logs if 'timestamp' in log]
        if timestamps:
            analysis.append(f"\nFirst event: {min(timestamps)}")
            analysis.append(f"Last event: {max(timestamps)}")
        
        # IP analysis
        ips = []
        for log in logs:
            if 'remote_address' in log:
                ip = log['remote_address'].split(':')[0]
                if ip not in ips:
                    ips.append(ip)
        
        if ips:
            analysis.append(f"\nUnique IPs found: {len(ips)}")
            for ip in ips[:5]:
                analysis.append(f"  {ip}")
        
        return "\n".join(analysis)
    
    def generate_report(self):
        """Generate report file"""
        analysis = self.analyze_logs()
        report_file = "security_report.txt"
        
        with open(report_file, 'w') as f:
            f.write(analysis)
        
        return f"Report saved to {report_file}"

# ==================== 3. FIREWALL MANAGER ====================
class FirewallManager:
    @staticmethod
    def block_ip(ip_address):
        """Block IP address"""
        try:
            if sys.platform == "win32":
                rule_name = f"Block_{ip_address}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    return f"Blocked IP: {ip_address}"
                else:
                    return f"Failed: {result.stderr}"
            else:
                return "Windows only feature"
        except Exception as e:
            return f"Error: {e}"

# ==================== 4. SIMPLIFIED GUI - NO ERRORS ====================
class CyberSecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Security System")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f0f0")
        
        # Initialize components
        self.ids = IntrusionDetectionSystem()
        self.log_analyzer = LogAnalyzer()
        self.firewall_manager = FirewallManager()
        
        # State
        self.monitoring = False
        self.threat_count = 0
        
        # Setup GUI - SIMPLIFIED VERSION
        self.setup_simple_gui()
        
        # Initial update
        self.update_log_display()
    
    def setup_simple_gui(self):
        """Simple GUI without notebook errors"""
        # Main container
        main_container = tk.Frame(self.root, bg="#f0f0f0")
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top frame - Title and status
        top_frame = tk.Frame(main_container, bg="#2c3e50", height=80)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        top_frame.pack_propagate(False)
        
        tk.Label(top_frame, text="[LOCK] CYBER SECURITY SYSTEM", 
                font=("Arial", 20, "bold"), fg="white", bg="#2c3e50").pack(pady=20)
        
        # Status bar
        status_frame = tk.Frame(main_container, bg="#34495e", height=40)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Status: STOPPED", 
                                    font=("Arial", 12, "bold"), fg="red", bg="#34495e")
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        self.threat_label = tk.Label(status_frame, text="Threats: 0", 
                                    font=("Arial", 12, "bold"), fg="orange", bg="#34495e")
        self.threat_label.pack(side=tk.RIGHT, padx=20)
        
        # Left panel - Controls
        left_panel = tk.Frame(main_container, width=250, bg="#ecf0f1", relief=tk.RAISED, borderwidth=2)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)
        
        tk.Label(left_panel, text="CONTROLS", font=("Arial", 14, "bold"),
                bg="#ecf0f1").pack(pady=20)
        
        # Control buttons
        btn_style = {"font": ("Arial", 11), "width": 20, "pady": 8, "bd": 2}
        
        tk.Button(left_panel, text="▶ START MONITORING", command=self.start_monitoring,
                 bg="#27ae60", fg="white", **btn_style).pack(pady=5)
        
        tk.Button(left_panel, text="⏹ STOP MONITORING", command=self.stop_monitoring,
                 bg="#e74c3c", fg="white", **btn_style).pack(pady=5)
        
        tk.Button(left_panel, text="[CHART] ANALYZE LOGS", command=self.analyze_logs,
                 bg="#3498db", fg="white", **btn_style).pack(pady=5)
        
        tk.Button(left_panel, text="[SHIELD] BLOCK SELECTED", command=self.block_selected,
                 bg="#9b59b6", fg="white", **btn_style).pack(pady=5)
        
        tk.Button(left_panel, text="[CLEAN] CLEAR LOGS", command=self.clear_logs,
                 bg="#e67e22", fg="white", **btn_style).pack(pady=5)
        
        tk.Button(left_panel, text="[DOCUMENT] GENERATE REPORT", command=self.generate_report,
                 bg="#1abc9c", fg="white", **btn_style).pack(pady=5)
        
        tk.Button(left_panel, text="[GRAPH] SYSTEM INFO", command=self.show_system_info,
                 bg="#f39c12", fg="white", **btn_style).pack(pady=5)
        
        tk.Button(left_panel, text="[ERROR] EXIT", command=self.root.quit,
                 bg="#7f8c8d", fg="white", **btn_style).pack(pady=20)
        
        # System stats in left panel
        stats_frame = tk.Frame(left_panel, bg="#2c3e50")
        stats_frame.pack(pady=20, padx=10, fill=tk.X)
        
        tk.Label(stats_frame, text="SYSTEM STATS", font=("Arial", 12, "bold"),
                fg="white", bg="#2c3e50").pack(pady=5)
        
        self.cpu_label = tk.Label(stats_frame, text="CPU: --%", fg="#00ff88", bg="#2c3e50")
        self.cpu_label.pack()
        
        self.mem_label = tk.Label(stats_frame, text="Memory: --%", fg="#00ff88", bg="#2c3e50")
        self.mem_label.pack()
        
        # Right panel - Main content
        right_panel = tk.Frame(main_container, bg="white")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Tab system using frames (simpler than notebook)
        self.current_tab = 1
        
        # Tab buttons
        tab_frame = tk.Frame(right_panel, bg="#34495e", height=40)
        tab_frame.pack(fill=tk.X)
        tab_frame.pack_propagate(False)
        
        self.tab1_btn = tk.Button(tab_frame, text="[NOTE] LIVE LOGS", command=self.show_tab1,
                                 bg="#2980b9", fg="white", font=("Arial", 11), width=15)
        self.tab1_btn.pack(side=tk.LEFT, padx=2)
        
        self.tab2_btn = tk.Button(tab_frame, text="[ALERT] THREATS", command=self.show_tab2,
                                 bg="#34495e", fg="white", font=("Arial", 11), width=15)
        self.tab2_btn.pack(side=tk.LEFT, padx=2)
        
        self.tab3_btn = tk.Button(tab_frame, text="[CHART] ANALYSIS", command=self.show_tab3,
                                 bg="#34495e", fg="white", font=("Arial", 11), width=15)
        self.tab3_btn.pack(side=tk.LEFT, padx=2)
        
        # Content area
        self.content_frame = tk.Frame(right_panel, bg="white")
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Live Logs
        self.tab1_frame = tk.Frame(self.content_frame, bg="white")
        
        self.log_text = scrolledtext.ScrolledText(self.tab1_frame, height=25, 
                                                 font=("Consolas", 10), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 2: Threats
        self.tab2_frame = tk.Frame(self.content_frame, bg="white")
        
        # Threat list with scrollbar
        list_frame = tk.Frame(self.tab2_frame, bg="white")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.threat_listbox = tk.Listbox(list_frame, height=20, font=("Consolas", 10),
                                        selectmode=tk.SINGLE)
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.threat_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.threat_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.threat_listbox.yview)
        
        # Tab 3: Analysis
        self.tab3_frame = tk.Frame(self.content_frame, bg="white")
        
        self.analysis_text = scrolledtext.ScrolledText(self.tab3_frame, height=25,
                                                      font=("Consolas", 10), wrap=tk.WORD)
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Show initial tab
        self.show_tab1()
    
    def show_tab1(self):
        """Show live logs tab"""
        self.current_tab = 1
        self.tab1_btn.config(bg="#2980b9")
        self.tab2_btn.config(bg="#34495e")
        self.tab3_btn.config(bg="#34495e")
        
        # Hide all tabs
        for frame in [self.tab1_frame, self.tab2_frame, self.tab3_frame]:
            frame.pack_forget()
        
        # Show selected tab
        self.tab1_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_tab2(self):
        """Show threats tab"""
        self.current_tab = 2
        self.tab1_btn.config(bg="#34495e")
        self.tab2_btn.config(bg="#2980b9")
        self.tab3_btn.config(bg="#34495e")
        
        # Hide all tabs
        for frame in [self.tab1_frame, self.tab2_frame, self.tab3_frame]:
            frame.pack_forget()
        
        # Show selected tab
        self.tab2_frame.pack(fill=tk.BOTH, expand=True)
        self.update_threat_list()
    
    def show_tab3(self):
        """Show analysis tab"""
        self.current_tab = 3
        self.tab1_btn.config(bg="#34495e")
        self.tab2_btn.config(bg="#34495e")
        self.tab3_btn.config(bg="#2980b9")
        
        # Hide all tabs
        for frame in [self.tab1_frame, self.tab2_frame, self.tab3_frame]:
            frame.pack_forget()
        
        # Show selected tab
        self.tab3_frame.pack(fill=tk.BOTH, expand=True)
    
    def log_message(self, message):
        """Add message to log display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def update_log_display(self):
        """Update log count display"""
        logs = self.log_analyzer.load_logs()
        self.threat_count = len(logs)
        self.threat_label.config(text=f"Threats: {self.threat_count}")
    
    def update_threat_list(self):
        """Update threat listbox"""
        logs = self.log_analyzer.load_logs()
        self.threat_listbox.delete(0, tk.END)
        
        for i, log in enumerate(logs[-50:]):  # Last 50 threats
            timestamp = log.get('timestamp', '')[:16]
            reason = log.get('reason', 'Unknown')[:40]
            self.threat_listbox.insert(tk.END, f"{i+1:3}. {timestamp} - {reason}")
    
    def start_monitoring(self):
        """Start monitoring"""
        if not PSUTIL_AVAILABLE:
            messagebox.showwarning("Dependency Missing", 
                                 "Install psutil: pip install psutil\nMonitoring limited.")
        
        self.monitoring = True
        self.status_label.config(text="Status: MONITORING", fg="green")
        self.log_message("Monitoring started...")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        self.status_label.config(text="Status: STOPPED", fg="red")
        self.log_message("Monitoring stopped.")
    
    def monitor_loop(self):
        """Monitoring loop"""
        while self.monitoring:
            try:
                threats_found, system_info, threats = self.ids.run_detection(
                    callback=self.update_detection_results
                )
                
                # Update system stats
                self.root.after(0, self.update_system_stats, system_info)
                
                time.sleep(30)  # Scan every 30 seconds
                
            except Exception as e:
                self.log_message(f"Error: {e}")
                time.sleep(10)
    
    def update_detection_results(self, threats_found, system_info, threats):
        """Update with detection results"""
        if threats_found > 0:
            self.log_message(f"ALERT! {threats_found} threats detected!")
            
            for threat in threats:
                if 'remote_address' in threat:
                    self.log_message(f"  → {threat['reason']} from {threat['remote_address']}")
                else:
                    self.log_message(f"  → {threat['reason']}")
        
        # Update counts
        self.update_log_display()
        
        # Auto-switch to threats tab if threats found
        if threats_found > 0 and self.current_tab != 2:
            self.root.after(100, self.show_tab2)
    
    def update_system_stats(self, system_info):
        """Update system stats display"""
        if 'cpu_usage' in system_info:
            self.cpu_label.config(text=f"CPU: {system_info['cpu_usage']:.1f}%")
        if 'memory_usage' in system_info:
            self.mem_label.config(text=f"Memory: {system_info['memory_usage']:.1f}%")
    
    def analyze_logs(self):
        """Analyze logs"""
        if not PSUTIL_AVAILABLE:
            messagebox.showinfo("Analysis", "Logs analysis requires psutil.")
            return
        
        analysis = self.log_analyzer.analyze_logs()
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(1.0, analysis)
        
        # Show analysis tab
        self.show_tab3()
        
        self.log_message("Log analysis completed.")
    
    def block_selected(self):
        """Block selected threat"""
        selection = self.threat_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a threat from the list.")
            return
        
        index = selection[0]
        logs = self.log_analyzer.load_logs()
        
        if index < len(logs):
            threat = logs[index]
            if 'remote_address' in threat:
                ip = threat['remote_address'].split(':')[0]
                
                if messagebox.askyesno("Confirm", f"Block IP: {ip}?"):
                    result = self.firewall_manager.block_ip(ip)
                    self.log_message(result)
                    messagebox.showinfo("IP Blocked", result)
            else:
                messagebox.showinfo("No IP", "Selected threat has no IP.")
    
    def clear_logs(self):
        """Clear all logs"""
        if messagebox.askyesno("Confirm", "Clear all logs?"):
            try:
                files = ["intrusion_logs.json", "security_report.txt"]
                for file in files:
                    if os.path.exists(file):
                        os.remove(file)
                
                self.threat_count = 0
                self.threat_label.config(text="Threats: 0")
                self.threat_listbox.delete(0, tk.END)
                self.log_text.delete(1.0, tk.END)
                self.analysis_text.delete(1.0, tk.END)
                
                self.log_message("All logs cleared.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not clear: {e}")
    
    def generate_report(self):
        """Generate report"""
        result = self.log_analyzer.generate_report()
        self.log_message(result)
        messagebox.showinfo("Report", result)
    
    def show_system_info(self):
        """Show system information"""
        if not PSUTIL_AVAILABLE:
            messagebox.showinfo("System Info", 
                              "Install psutil for system info:\npip install psutil")
            return
        
        try:
            info = []
            info.append("=== SYSTEM INFORMATION ===")
            info.append(f"CPU Cores: {psutil.cpu_count()}")
            info.append(f"CPU Usage: {psutil.cpu_percent()}%")
            info.append(f"Memory: {psutil.virtual_memory().percent}%")
            info.append(f"Memory Total: {psutil.virtual_memory().total // (1024**3)} GB")
            
            messagebox.showinfo("System Info", "\n".join(info))
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not get info: {e}")

# ==================== 5. COMMAND LINE FUNCTIONS ====================
def quick_scan():
    """Quick scan function"""
    print("\n" + "="*50)
    print("QUICK SECURITY SCAN")
    print("="*50)
    
    if not PSUTIL_AVAILABLE:
        print("Install psutil: pip install psutil")
        return
    
    try:
        print(f"Time: {datetime.now()}")
        print(f"CPU: {psutil.cpu_percent()}%")
        print(f"Memory: {psutil.virtual_memory().percent}%")
        
        print("\n=== PROCESSES ===")
        found = False
        for proc in psutil.process_iter(['name']):
            try:
                name = proc.info['name'].lower()
                if any(kw in name for kw in ['keylog', 'rat', 'backdoor']):
                    print(f"[WARNING]  {proc.info['name']}")
                    found = True
            except:
                continue
        
        if not found:
            print("No suspicious processes")
        
        print("\n[OK] Scan completed!")
        
    except Exception as e:
        print(f"[ERROR] Error: {e}")

def command_line_mode():
    """Command line interface"""
    print("\n" + "="*50)
    print("COMMAND LINE MODE")
    print("="*50)
    
    ids = IntrusionDetectionSystem()
    analyzer = LogAnalyzer()
    
    while True:
        print("\nOptions:")
        print("1. Run Scan")
        print("2. Analyze Logs")
        print("3. Quick Scan")
        print("4. Back to Main")
        
        try:
            choice = input("\nChoice (1-4): ").strip()
            
            if choice == '1':
                print("\nScanning...")
                threats, info, _ = ids.run_detection()
                print(f"Threats found: {threats}")
            
            elif choice == '2':
                print("\n" + analyzer.analyze_logs())
            
            elif choice == '3':
                quick_scan()
            
            elif choice == '4':
                break
            
            else:
                print("Invalid choice")
                
        except KeyboardInterrupt:
            print("\nCancelled")
            break
        except Exception as e:
            print(f"Error: {e}")

# ==================== 6. MAIN FUNCTION ====================
def main():
    """Main function"""
    print("="*60)
    print("CYBER SECURITY SYSTEM")
    print("="*60)
    print("Integrated All-in-One Solution")
    
    # Check dependencies
    if not PSUTIL_AVAILABLE:
        print("\n[WARNING]  Note: Install psutil for full features")
        print("Run: pip install psutil")
    
    print("\nSelect Mode:")
    print("1. GUI Mode (Recommended)")
    print("2. Command Line")
    print("3. Quick Scan")
    print("4. Exit")
    
    while True:
        try:
            choice = input("\nChoice (1-4): ").strip()
            
            if choice == '1':
                print("\nStarting GUI...")
                root = tk.Tk()
                app = CyberSecurityGUI(root)
                
                # Center window
                root.update_idletasks()
                width = 900
                height = 700
                screen_width = root.winfo_screenwidth()
                screen_height = root.winfo_screenheight()
                x = (screen_width // 2) - (width // 2)
                y = (screen_height // 2) - (height // 2)
                root.geometry(f'{width}x{height}+{x}+{y}')
                
                root.mainloop()
                break
            
            elif choice == '2':
                command_line_mode()
                break
            
            elif choice == '3':
                quick_scan()
            
            elif choice == '4':
                print("\nGoodbye!")
                break
            
            else:
                print("Invalid choice")
                
        except KeyboardInterrupt:
            print("\nCancelled")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()