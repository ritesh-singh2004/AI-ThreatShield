"""
SUPER SIMPLE LAUNCHER - 100% Working on Windows
"""

import os
import sys
import tkinter as tk
from tkinter import messagebox
import subprocess

class SimpleLauncher:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Cyber Security Tools")
        self.window.geometry("600x500")
        self.window.configure(bg="#2c3e50")
        
        self.create_widgets()
    
    def create_widgets(self):
        # Title
        title = tk.Label(self.window, text="CYBER SECURITY TOOLS", 
                        font=("Arial", 20, "bold"),
                        fg="white", bg="#2c3e50")
        title.pack(pady=20)
        
        # Status
        self.status = tk.Label(self.window, text="Ready", 
                              font=("Arial", 10), fg="yellow", bg="#2c3e50")
        self.status.pack()
        
        # Buttons Frame
        button_frame = tk.Frame(self.window, bg="#2c3e50")
        button_frame.pack(pady=20)
        
        # Button definitions
        buttons = [
            ("Run Intrusion Detection", self.run_ids),
            ("Analyze Logs", self.analyze_logs),
            ("Real-time Monitor", self.run_monitor),
            ("Quick Security Scan", self.quick_scan),
            ("View Logs", self.view_logs),
            ("Fix JSON Files", self.fix_json),
            ("Exit", self.window.quit)
        ]
        
        # Create buttons
        for text, command in buttons:
            btn = tk.Button(button_frame, text=text, command=command,
                          font=("Arial", 12), width=30, height=2,
                          bg="#3498db", fg="white", relief=tk.RAISED)
            btn.pack(pady=5)
    
    def update_status(self, msg):
        self.status.config(text=msg)
        self.window.update()
    
    def run_ids(self):
        self.update_status("Starting IDS...")
        if os.path.exists("ids_detector.py"):
            try:
                subprocess.Popen([sys.executable, "ids_detector.py"])
                messagebox.showinfo("Success", "IDS started in terminal")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "ids_detector.py not found")
    
    def analyze_logs(self):
        self.update_status("Analyzing logs...")
        if os.path.exists("log_analyzer.py"):
            try:
                subprocess.Popen([sys.executable, "log_analyzer.py"])
                messagebox.showinfo("Success", "Log analyzer started")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "log_analyzer.py not found")
    
    def run_monitor(self):
        self.update_status("Starting monitor...")
        files = ["enhanced_monitor.py", "real_time_monitor.py"]
        for file in files:
            if os.path.exists(file):
                try:
                    subprocess.Popen([sys.executable, file])
                    messagebox.showinfo("Success", f"{file} started")
                    return
                except:
                    pass
        messagebox.showerror("Error", "No monitor file found")
    
    def quick_scan(self):
        self.update_status("Scanning...")
        try:
            import psutil
            result = f"CPU Usage: {psutil.cpu_percent()}%\n"
            result += f"Memory Usage: {psutil.virtual_memory().percent}%\n"
            result += f"Running Processes: {len(list(psutil.process_iter()))}\n"
            messagebox.showinfo("Scan Results", result)
        except ImportError:
            messagebox.showinfo("Info", "Install psutil: pip install psutil")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def view_logs(self):
        self.update_status("Opening logs...")
        if os.path.exists("intrusion_logs.json"):
            try:
                os.startfile("intrusion_logs.json")
            except:
                messagebox.showinfo("Info", "Log file: intrusion_logs.json")
        else:
            messagebox.showinfo("Info", "No logs found")
    
    def fix_json(self):
        self.update_status("Fixing JSON...")
        import json
        try:
            if os.path.exists("intrusion_logs.json"):
                with open("intrusion_logs.json", "r", encoding="utf-8") as f:
                    data = json.load(f)
                with open("intrusion_logs.json", "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                messagebox.showinfo("Success", "JSON file fixed")
            else:
                messagebox.showinfo("Info", "No JSON file to fix")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    launcher = SimpleLauncher()
    launcher.run()