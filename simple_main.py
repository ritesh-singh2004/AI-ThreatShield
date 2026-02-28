"""
SIMPLE MAIN LAUNCHER - No Unicode, No Encoding Issues
"""

import os
import sys
import subprocess
import tkinter as tk
from tkinter import messagebox
import json

class SimpleLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Security Launcher")
        self.root.geometry("600x500")
        
        self.create_widgets()
    
    def create_widgets(self):
        # Title
        title = tk.Label(self.root, text="CYBER SECURITY TOOLS", 
                        font=("Arial", 18, "bold"))
        title.pack(pady=20)
        
        # Buttons
        buttons = [
            ("Run IDS System", self.run_ids),
            ("Analyze Logs", self.analyze_logs),
            ("Real-time Monitor", self.run_monitor),
            ("Fix JSON Files", self.fix_json),
            ("View Reports", self.view_reports),
            ("Quick Scan", self.quick_scan),
            ("Exit", self.root.quit)
        ]
        
        for text, command in buttons:
            btn = tk.Button(self.root, text=text, command=command,
                          font=("Arial", 12), width=25, height=2)
            btn.pack(pady=5)
        
        # Status
        self.status = tk.Label(self.root, text="Ready", font=("Arial", 10))
        self.status.pack(pady=20)
    
    def update_status(self, message):
        self.status.config(text=message)
        self.root.update()
    
    def run_ids(self):
        if os.path.exists("ids_detector.py"):
            self.update_status("Starting IDS...")
            subprocess.Popen([sys.executable, "ids_detector.py"])
            messagebox.showinfo("Info", "IDS started in new window")
        else:
            messagebox.showerror("Error", "ids_detector.py not found")
    
    def analyze_logs(self):
        if os.path.exists("log_analyzer.py"):
            self.update_status("Starting Log Analyzer...")
            subprocess.Popen([sys.executable, "log_analyzer.py"])
        else:
            messagebox.showerror("Error", "log_analyzer.py not found")
    
    def run_monitor(self):
        files = ["enhanced_monitor.py", "real_time_monitor.py", "enhance_monitor.py"]
        for file in files:
            if os.path.exists(file):
                self.update_status(f"Starting {file}...")
                subprocess.Popen([sys.executable, file])
                return
        
        messagebox.showerror("Error", "No monitor file found")
    
    def fix_json(self):
        self.update_status("Fixing JSON files...")
        # Simple JSON fix
        try:
            if os.path.exists("intrusion_logs.json"):
                with open("intrusion_logs.json", "r", encoding="utf-8") as f:
                    data = json.load(f)
                with open("intrusion_logs.json", "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                messagebox.showinfo("Success", "JSON file fixed")
        except Exception as e:
            messagebox.showerror("Error", f"Could not fix: {str(e)}")
    
    def view_reports(self):
        files = ["intrusion_logs.json", "analysis_report.json"]
        for file in files:
            if os.path.exists(file):
                os.startfile(file)
    
    def quick_scan(self):
        self.update_status("Running quick scan...")
        # Simple scan
        import psutil
        
        result = "=== QUICK SCAN RESULTS ===\n"
        result += f"CPU Usage: {psutil.cpu_percent()}%\n"
        result += f"Memory Usage: {psutil.virtual_memory().percent}%\n"
        result += f"Processes: {len(list(psutil.process_iter()))}\n"
        
        messagebox.showinfo("Scan Results", result)

if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleLauncher(root)
    root.mainloop()