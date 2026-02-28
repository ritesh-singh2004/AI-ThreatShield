import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from ids_detector import IntrusionDetectionSystem
import json

class RealTimeMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Security IDS - Real Time Monitor")
        self.root.geometry("900x700")
        
        self.ids = IntrusionDetectionSystem()
        self.monitoring = False
        
        self.setup_ui()
    
    def setup_ui(self):
        # Title
        title_label = tk.Label(
            self.root, 
            text="🔒 CYBER SECURITY INTRUSION DETECTION SYSTEM",
            font=("Arial", 16, "bold"),
            fg="white",
            bg="#2c3e50"
        )
        title_label.pack(fill=tk.X, padx=10, pady=10)
        
        # Status Frame
        status_frame = tk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = tk.Label(
            status_frame,
            text="Status: STOPPED",
            font=("Arial", 12),
            fg="red"
        )
        self.status_label.pack(side=tk.LEFT)
        
        self.threat_count_label = tk.Label(
            status_frame,
            text="Threats Detected: 0",
            font=("Arial", 12)
        )
        self.threat_count_label.pack(side=tk.RIGHT)
        
        # Control Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_btn = tk.Button(
            button_frame,
            text="▶ START MONITORING",
            command=self.start_monitoring,
            bg="#27ae60",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=20,
            pady=10
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(
            button_frame,
            text="⏹ STOP MONITORING",
            command=self.stop_monitoring,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=20,
            pady=10,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.view_logs_btn = tk.Button(
            button_frame,
            text="📊 VIEW LOGS",
            command=self.view_logs,
            bg="#3498db",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=20,
            pady=10
        )
        self.view_logs_btn.pack(side=tk.RIGHT, padx=5)
        
        # Log Display Area
        log_frame = tk.LabelFrame(self.root, text="Real-time Logs", font=("Arial", 12, "bold"))
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=20,
            width=100,
            font=("Consolas", 10)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Statistics Frame
        stats_frame = tk.Frame(self.root)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(stats_frame, text="System Stats:", font=("Arial", 11, "bold")).pack(side=tk.LEFT)
        
        self.cpu_label = tk.Label(stats_frame, text="CPU: --%")
        self.cpu_label.pack(side=tk.LEFT, padx=10)
        
        self.memory_label = tk.Label(stats_frame, text="Memory: --%")
        self.memory_label.pack(side=tk.LEFT, padx=10)
        
        self.connection_label = tk.Label(stats_frame, text="Connections: --")
        self.connection_label.pack(side=tk.LEFT, padx=10)
        
        # Threat Level Indicator
        threat_frame = tk.Frame(self.root)
        threat_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(threat_frame, text="Threat Level:", font=("Arial", 11, "bold")).pack(side=tk.LEFT)
        
        self.threat_indicator = tk.Label(
            threat_frame,
            text="LOW",
            font=("Arial", 12, "bold"),
            fg="green"
        )
        self.threat_indicator.pack(side=tk.LEFT, padx=10)
    
    def start_monitoring(self):
        self.monitoring = True
        self.status_label.config(text="Status: MONITORING", fg="green")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Start monitoring in separate thread
        self.monitor_thread = threading.Thread(target=self.monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.log("Monitoring started...")
    
    def stop_monitoring(self):
        self.monitoring = False
        self.status_label.config(text="Status: STOPPED", fg="red")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self.log("Monitoring stopped.")
    
    def monitor_loop(self):
        threat_count = 0
        
        while self.monitoring:
            try:
                # Run detection
                threats = self.ids.run_detection()
                
                # Update threat count
                threat_count += threats
                self.root.after(0, self.update_threat_count, threat_count)
                
                # Update system stats
                system_info = self.ids.get_system_info()
                self.root.after(0, self.update_stats, system_info)
                
                # Update threat level
                if threats > 0:
                    self.root.after(0, self.update_threat_level, "HIGH", "red")
                else:
                    self.root.after(0, self.update_threat_level, "LOW", "green")
                
                # Wait before next scan
                for _ in range(30):  # 30 seconds
                    if not self.monitoring:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.log(f"Error: {str(e)}")
                time.sleep(10)
    
    def update_threat_count(self, count):
        self.threat_count_label.config(text=f"Threats Detected: {count}")
    
    def update_stats(self, system_info):
        self.cpu_label.config(text=f"CPU: {system_info['cpu_usage']:.1f}%")
        self.memory_label.config(text=f"Memory: {system_info['memory_usage']:.1f}%")
    
    def update_threat_level(self, level, color):
        self.threat_indicator.config(text=level, fg=color)
    
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
    
    def view_logs(self):
        try:
            with open("intrusion_logs.json", 'r') as f:
                logs = json.load(f)
            
            # Create new window for logs
            log_window = tk.Toplevel(self.root)
            log_window.title("Intrusion Logs")
            log_window.geometry("800x600")
            
            text_area = scrolledtext.ScrolledText(log_window, width=90, height=30)
            text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            
            text_area.insert(tk.END, json.dumps(logs, indent=4))
            text_area.config(state=tk.DISABLED)
            
        except FileNotFoundError:
            self.log("No logs found.")
        except Exception as e:
            self.log(f"Error viewing logs: {str(e)}")

def main():
    root = tk.Tk()
    app = RealTimeMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()