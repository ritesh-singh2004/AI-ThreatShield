import json
from datetime import datetime

def fix_logs_file():
    """intrusion_logs.json file fix karein"""
    try:
        with open('intrusion_logs.json', 'r', encoding='utf-8') as f:
            logs = json.load(f)
        
        fixed_logs = []
        for log in logs:
            fixed_log = {}
            for key, value in log.items():
                # Convert datetime objects to string
                if isinstance(value, datetime):
                    fixed_log[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                # Convert date objects to string
                elif hasattr(value, 'strftime'):
                    try:
                        fixed_log[key] = value.strftime("%Y-%m-%d")
                    except:
                        fixed_log[key] = str(value)
                else:
                    fixed_log[key] = value
            fixed_logs.append(fixed_log)
        
        # Save fixed logs
        with open('intrusion_logs_fixed.json', 'w', encoding='utf-8') as f:
            json.dump(fixed_logs, f, indent=4, ensure_ascii=False)
        
        # Also update original
        with open('intrusion_logs.json', 'w', encoding='utf-8') as f:
            json.dump(fixed_logs, f, indent=4, ensure_ascii=False)
        
        print(f"✅ Fixed {len(fixed_logs)} log entries")
        print(f"✅ Saved to: intrusion_logs_fixed.json")
        print(f"✅ Original file also updated")
        
    except FileNotFoundError:
        print("❌ intrusion_logs.json file not found")
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def create_sample_logs():
    """Sample logs create karein agar file nahi hai to"""
    sample_logs = [
        {
            "timestamp": "2026-02-09 19:37:19",
            "reason": "Suspicious port 3389 used - RDP Attack",
            "remote_address": "103.216.154.205:3389",
            "geolocation": {
                "city": "Beijing",
                "region": "Beijing",
                "country": "China",
                "isp": "China Telecom"
            }
        },
        {
            "timestamp": "2026-02-09 19:37:19",
            "reason": "Suspicious port 445 used - SMB Exploit",
            "remote_address": "45.67.89.123:445",
            "geolocation": {
                "city": "Moscow",
                "region": "Moscow Oblast",
                "country": "Russia",
                "isp": "Russian Telecom"
            }
        },
        {
            "timestamp": "2026-02-09 19:37:19",
            "reason": "High resource usage detected - Possible Miner",
            "process_name": "crypto_miner.exe",
            "cpu": 85.5,
            "memory": 45.2
        }
    ]
    
    with open('intrusion_logs.json', 'w', encoding='utf-8') as f:
        json.dump(sample_logs, f, indent=4)
    
    print("✅ Created sample logs with 3 entries")
    print("✅ File: intrusion_logs.json")

def check_current_logs():
    """Current logs check karein"""
    try:
        with open('intrusion_logs.json', 'r', encoding='utf-8') as f:
            content = f.read()
            print("Current file content preview:")
            print("-" * 50)
            print(content[:500] + "..." if len(content) > 500 else content)
            print("-" * 50)
    except FileNotFoundError:
        print("❌ File not found")

if __name__ == "__main__":
    print("=" * 60)
    print("JSON FIX UTILITY")
    print("=" * 60)
    
    print("\n1. Check current logs")
    print("2. Fix JSON date issues")
    print("3. Create sample logs")
    
    choice = input("\nEnter choice (1-3): ")
    
    if choice == '1':
        check_current_logs()
    elif choice == '2':
        fix_logs_file()
    elif choice == '3':
        create_sample_logs()
    else:
        print("Invalid choice")