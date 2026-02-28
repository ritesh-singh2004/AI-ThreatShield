"""
Organize Cyber Security Project Files
"""

import os
import shutil
from pathlib import Path

def organize_project():
    print("📁 Organizing Cyber Security Project...")
    
    # Create directories
    directories = {
        'src': 'Source Code',
        'logs': 'Log Files',
        'reports': 'Analysis Reports',
        'utils': 'Utilities',
        'docs': 'Documentation'
    }
    
    for dir_name, dir_desc in directories.items():
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
            print(f"✅ Created {dir_name}/ ({dir_desc})")
    
    # Move files to appropriate directories
    file_mapping = {
        'src': [
            'ids_detector.py',
            'ids_detector_enhanced.py',
            'log_analyzer.py',
            'real_time_monitor.py',
            'enhanced_monitor.py',
            'main.py'
        ],
        'utils': [
            'setup_ids.py',
            'fix_json_issue.py',
            'firewall_manager.py',
            'alert_system.py',
            'organize_project.py'
        ],
        'logs': [
            'intrusion_logs.json'
        ],
        'reports': [
            'analysis_report.json',
            'security_analysis.png'
        ]
    }
    
    moved_files = 0
    for target_dir, files in file_mapping.items():
        for file in files:
            if os.path.exists(file):
                try:
                    shutil.move(file, os.path.join(target_dir, file))
                    print(f"📂 Moved {file} → {target_dir}/")
                    moved_files += 1
                except:
                    print(f"⚠️ Could not move {file}")
    
    print(f"\n✅ Organization complete! Moved {moved_files} files.")
    
   