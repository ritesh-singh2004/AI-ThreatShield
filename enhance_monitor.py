import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import json
import os
from datetime import datetime

class EnhancedMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("🚨 CYBER SECURITY IDS - LIVE MONITOR")
        self.root.geometry("1000x800")
        self.root.configure(bg="#f0f0f0")
        
        self.log_file = "intrusion_logs.json"
        self.monitoring = False
        self.threat_count = 0
        
        self.setup_ui()
        self.load_existing_logs()
        
    def setup_ui(self):
        # Header
        header = tk.Frame(self.root, bg="#2c3e50", height=80)
        header.pack(fill=tk.X)
        
        tk.Label(
            header,
            text="🔒 CYBER SECURITY INTRUSION DETECTION SYSTEM",
            font=("Arial", 18, "bold"),
            fg="white",
            bg="#2c3e50"
        ).pack(pady=20)
        
        # Status Bar
        status_frame = tk.Frame(self.root, bg="#34495e", height=40)
        status_frame.pack(fill=tk.X)
        
        self.status_label = tk.Label(
            status_frame,
            text="STATUS: STOPPED",
            font=("Arial", 11, "bold"),
            fg="#e74c3c",
            bg="#34495e"
        )
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        self.threat_label = tk.Label(
            status_frame,
            text="THREATS: 0",
            font=("Arial", 11, "bold"),
            fg="#f39c12",
            bg="#34495e"
        )
        self.threat_label.pack(side=tk.RIGHT, padx=20)
        
        # Control Panel
        control_frame = tk.Frame(self.root, bg="#ecf0f1", pady=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        btn_style = {"font": ("Arial", 11, "bold"), "padx": 20, "pady": 8}
        
        self.start_btn = tk.Button(
            control_frame,
            text="▶ START MONITORING",
            command=self.start_monitoring,
            bg="#27ae60",
            fg="white",
            **btn_style
        )
        self.start_btn.grid(row=0, column=0, padx=5)
        
        self.stop_btn = tk.Button(
            control_frame,
            text="⏹ STOP",
            command=self.stop_monitoring,
            bg="#e74c3c",
            fg="white",
            **btn_style,
            state=tk.DISABLED
        )
        self.stop_btn.grid(row=0, column=1, padx=5)
        
        self.view_btn = tk.Button(
            control_frame,
            text="📊 VIEW LOGS",
            command=self.view_logs,
            bg="#3498db",
            fg="white",
            **btn_style
        )
        self.view_btn.grid(row=0, column=2, padx=5)
        
        self.clear_btn = tk.Button(
            control_frame,
            text="🗑️ CLEAR LOGS",
            command=self.clear_logs,
            bg="#95a5a6",
            fg="white",
            **btn_style
        )
        self.clear_btn.grid(row=0, column=3, padx=5)
        
        # Main Content Area
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left Panel - Live Logs
        left_frame = tk.LabelFrame(main_frame, text="📝 LIVE DETECTION LOGS", font=("Arial", 12, "bold"))
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.log_text = scrolledtext.ScrolledText(
            left_frame,
            font=("Consolas", 10),
            bg="#2c3e50",
            fg="#ecf0f1"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Right Panel - Statistics
        right_frame = tk.LabelFrame(main_frame, text="📈 SYSTEM STATISTICS", font=("Arial", 12, "bold"), width=300)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(5, 0))
        right_frame.pack_propagate(False)
        
        # Stats Labels
        stats_bg = "#34495e"
        stats_fg = "#ecf0f1"
        
        stats_content = tk.Frame(right_frame, bg=stats_bg)
        stats_content.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.cpu_label = self.create_stat_label(stats_content, "CPU USAGE:", "--%", 0)
        self.mem_label = self.create_stat_label(stats_content, "MEMORY USAGE:", "--%", 1)
        self.disk_label = self.create_stat_label(stats_content, "DISK USAGE:", "--%", 2)
        
        tk.Frame(stats_content, height=20, bg=stats_bg).grid(row=3, column=0, pady=10)
        
        self.conn_label = self.create_stat_label(stats_content, "ACTIVE CONNECTIONS:", "--", 4)
        self.process_label = self.create_stat_label(stats_content, "RUNNING PROCESSES:", "--", 5)
        
        tk.Frame(stats_content, height=20, bg=stats_bg).grid(row=6, column=0, pady=10)
        
        # Threat Level
        threat_frame = tk.Frame(stats_content, bg=stats_bg)
        threat_frame.grid(row=7, column=0, sticky="ew", pady=10)
        
        tk.Label(threat_frame, text="THREAT LEVEL:", font=("Arial", 11, "bold"), 
                fg=stats_fg, bg=stats_bg).pack(side=tk.LEFT)
        
        self.threat_level = tk.Label(threat_frame, text="LOW", font=("Arial", 14, "bold"),
                                    fg="#27ae60", bg=stats_bg)
        self.threat_level.pack(side=tk.RIGHT, padx=10)
        
        # Recent Threats
        recent_frame = tk.Frame(stats_content, bg=stats_bg)
        recent_frame.grid(row=8, column=0, sticky="ew", pady=(20, 0))
        
        tk.Label(recent_frame, text="RECENT THREATS:", font=("Arial", 11, "bold"),
                fg=stats_fg, bg=stats_bg).pack(anchor="w")
        
        self.recent_threats = scrolledtext.ScrolledText(
            recent_frame,
            height=8,
            font=("Consolas", 9),
            bg="#2c3e50",
            fg="#ecf0f1"
        )
        self.recent_threats.pack(fill=tk.X, pady=5)
        self.recent_threats.config(state=tk.DISABLED)
        
    def create_stat_label(self, parent, text, value, row):
        frame = tk.Frame(parent, bg=parent["bg"])
        frame.grid(row=row, column=0, sticky="ew", pady=5)
        
        tk.Label(frame, text=text, font=("Arial", 10), 
                fg="#bdc3c7", bg=parent["bg"]).pack(side=tk.LEFT)
        
        label = tk.Label(frame, text=value, font=("Arial", 11, "bold"), 
                        fg="#ecf0f1", bg=parent["bg"])
        label.pack(side=tk.RIGHT)
        return label
    
    def load_existing_logs(self):
        """Existing logs load karein"""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
                    self.threat_count = len(logs)
                    self.threat_label.config(text=f"THREATS: {self.threat_count}")
            except:
                pass
    
    def start_monitoring(self):
        """Monitoring shuru karein"""
        self.monitoring = True
        self.status_label.config(text="STATUS: MONITORING", fg="#2ecc71")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring started...")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_system)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Monitoring band karein"""
        self.monitoring = False
        self.status_label.config(text="STATUS: STOPPED", fg="#e74c3c")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring stopped.")
    
    def monitor_system(self):
        """System monitoring loop"""
        import psutil
        import random
        
        while self.monitoring:
            try:
                # Update system stats
                self.update_system_stats()
                
                # Simulate threat detection (demo ke liye)
                if random.random() > 0.7:  # 30% chance threat
                    self.simulate_threat_detection()
                
                # Update recent threats
                self.update_recent_threats()
                
                time.sleep(10)  # 10 seconds delay
                
            except Exception as e:
                self.log(f"Error: {str(e)}")
                time.sleep(5)
    
    def update_system_stats(self):
        """System statistics update karein"""
        import psutil
        
        self.root.after(0, self.cpu_label.config, 
                       {"text": f"{psutil.cpu_percent():.1f}%"})
        self.root.after(0, self.mem_label.config,
                       {"text": f"{psutil.virtual_memory().percent:.1f}%"})
        
        try:
            disk_usage = psutil.disk_usage('C:/').percent
            self.root.after(0, self.disk_label.config,
                          {"text": f"{disk_usage:.1f}%"})
        except:
            pass
        
        # Connection count
        try:
            connections = len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
            self.root.after(0, self.conn_label.config,
                          {"text": f"{connections}"})
        except:
            pass
        
        # Process count
        process_count = len(list(psutil.process_iter()))
        self.root.after(0, self.process_label.config,
                       {"text": f"{process_count}"})
    
    def simulate_threat_detection(self):
        """Demo threats generate karein"""
        import random
        from datetime import datetime
        
        threat_types = [
            {
                "type": "Port Scan",
                "ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "port": random.choice([22, 23, 3389, 445, 8080]),
                "severity": "HIGH"
            },
            {
                "type": "Malicious Process",
                "process": random.choice(["crypto_miner.exe", "keylogger.dll", "backdoor.sys"]),
                "severity": "CRITICAL"
            },
            {
                "type": "Brute Force Attempt",
                "ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                "port": 22,
                "severity": "MEDIUM"
            }
        ]
        
        threat = random.choice(threat_types)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Update threat count
        self.threat_count += 1
        self.root.after(0, self.threat_label.config,
                       {"text": f"THREATS: {self.threat_count}"})
        
        # Update threat level
        if threat["severity"] in ["CRITICAL", "HIGH"]:
            self.root.after(0, self.threat_level.config,
                          {"text": "HIGH", "fg": "#e74c3c"})
        
        # Log threat
        log_msg = f"[{timestamp}] 🚨 {threat['type']} detected"
        if "ip" in threat:
            log_msg += f" from {threat['ip']}"
        if "port" in threat:
            log_msg += f" on port {threat['port']}"
        
        self.log(log_msg)
        
        # Save to log file
        self.save_threat(threat, timestamp)
    
    def save_threat(self, threat, timestamp):
        """Threat save karein log file me"""
        try:
            # Existing logs load karein
            logs = []
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    try:
                        logs = json.load(f)
                    except:
                        logs = []
            
            # New log entry
            log_entry = {
                "timestamp": f"{datetime.now().strftime('%Y-%m-%d')} {timestamp}",
                "type": threat["type"],
                "severity": threat["severity"],
                "detected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            if "ip" in threat:
                log_entry["ip_address"] = threat["ip"]
            if "port" in threat:
                log_entry["port"] = threat["port"]
            if "process" in threat:
                log_entry["process"] = threat["process"]
            
            logs.append(log_entry)
            
            # Save logs
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=4)
                
        except Exception as e:
            self.log(f"Error saving log: {str(e)}")
    
    def update_recent_threats(self):
        """Recent threats display karein"""
        if not os.path.exists(self.log_file):
            return
        
        try:
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
            
            # Last 5 threats
            recent = logs[-5:] if len(logs) > 5 else logs
            
            self.recent_threats.config(state=tk.NORMAL)
            self.recent_threats.delete(1.0, tk.END)
            
            for log in recent:
                time_str = log.get("timestamp", "").split()[-1]
                threat_type = log.get("type", "Unknown")
                severity = log.get("severity", "LOW")
                
                # Color coding based on severity
                if severity == "CRITICAL":
                    color = "red"
                elif severity == "HIGH":
                    color = "orange"
                elif severity == "MEDIUM":
                    color = "yellow"
                else:
                    color = "green"
                
                line = f"[{time_str}] {threat_type} ({severity})\n"
                self.recent_threats.insert(tk.END, line)
            
            self.recent_threats.config(state=tk.DISABLED)
            
        except:
            pass
    
    def log(self, message):
        """Message log karein"""
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        
        # Auto-scroll
        self.log_text.see(tk.END)
    
    def view_logs(self):
        """Logs display karein separate window me"""
        if not os.path.exists(self.log_file):
            messagebox.showinfo("No Logs", "No logs found. Start monitoring first.")
            return
        
        try:
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
            
            # Create log viewer window
            log_window = tk.Toplevel(self.root)
            log_window.title("Intrusion Logs Viewer")
            log_window.geometry("900x600")
            
            # Toolbar
            toolbar = tk.Frame(log_window)
            toolbar.pack(fill=tk.X, padx=5, pady=5)
            
            tk.Label(toolbar, text=f"Total Logs: {len(logs)}", 
                    font=("Arial", 10)).pack(side=tk.LEFT)
            
            # Text area
            text_area = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
            text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Display logs
            for i, log in enumerate(logs, 1):
                text_area.insert(tk.END, f"\n{'='*60}\n")
                text_area.insert(tk.END, f"LOG ENTRY #{i}\n")
                text_area.insert(tk.END, f"{'='*60}\n")
                
                for key, value in log.items():
                    text_area.insert(tk.END, f"{key}: {value}\n")
            
            text_area.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not load logs: {str(e)}")
    
    def clear_logs(self):
        """Logs clear karein"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all logs?"):
            try:
                with open(self.log_file, 'w') as f:
                    json.dump([], f)
                
                self.threat_count = 0
                self.threat_label.config(text="THREATS: 0")
                self.threat_level.config(text="LOW", fg="#27ae60")
                self.recent_threats.config(state=tk.NORMAL)
                self.recent_threats.delete(1.0, tk.END)
                self.recent_threats.config(state=tk.DISABLED)
                
                self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Logs cleared.")
                messagebox.showinfo("Success", "Logs cleared successfully.")
                
            except Exception as e:
                messagebox.showerror("Error", f"Could not clear logs: {str(e)}")

def main():
    root = tk.Tk()
    app = EnhancedMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()