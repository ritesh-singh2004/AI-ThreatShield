import json
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt
import os

class LogAnalyzer:
    def __init__(self, log_file="intrusion_logs.json"):
        self.log_file = log_file
    
    def load_logs(self):
        """Logs load kare"""
        try:
            if not os.path.exists(self.log_file):
                print(f"Log file '{self.log_file}' not found.")
                return []
                
            with open(self.log_file, 'r', encoding='utf-8') as f:
                logs = json.load(f)
            
            print(f"[OK] Successfully loaded {len(logs)} log entries")
            return logs
            
        except FileNotFoundError:
            print("[ERROR] No logs found. Run the IDS first.")
            return []
        except json.JSONDecodeError as e:
            print(f"[ERROR] Error reading logs file: {e}")
            return []
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return []
    
    def analyze_logs(self):
        """Logs analyze kare"""
        logs = self.load_logs()
        
        if not logs:
            print("No logs to analyze.")
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(logs)
        
        print("=" * 60)
        print("INTRUSION LOG ANALYSIS REPORT")
        print("=" * 60)
        
        # Basic statistics
        print(f"\n[CHART] Total Events Recorded: {len(df)}")
        
        # Event types
        if 'reason' in df.columns and len(df) > 0:
            print("\n[GRAPH] Event Types:")
            event_counts = df['reason'].value_counts()
            for event, count in event_counts.items():
                print(f"   {event}: {count} times")
        
        # Time-based analysis
        if 'timestamp' in df.columns and len(df) > 0:
            print("\n⏰ Time Analysis:")
            
            # Convert timestamp to datetime
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.dropna(subset=['timestamp'])
                
                if len(df) > 0:
                    print(f"   First Event: {df['timestamp'].min()}")
                    print(f"   Last Event: {df['timestamp'].max()}")
                    
                    # Group by date - convert date to string for JSON
                    df['date_str'] = df['timestamp'].dt.date.astype(str)
                    daily_counts = df['date_str'].value_counts().sort_index()
                    
                    if len(daily_counts) > 0:
                        print("\n📅 Daily Events:")
                        for date_str, count in daily_counts.items():
                            print(f"   {date_str}: {count} events")
            except Exception as e:
                print(f"   Error in time analysis: {e}")
        
        # Location analysis
        if 'geolocation' in df.columns and len(df) > 0:
            print("\n🌍 Attack Locations:")
            locations = []
            for geo in df['geolocation']:
                if isinstance(geo, dict):
                    country = geo.get('country', 'Unknown')
                    city = geo.get('city', 'Unknown')
                    if country != 'N/A' and country != 'Unknown':
                        locations.append(f"{city}, {country}")
            
            if locations:
                from collections import Counter
                location_counts = Counter(locations)
                print(f"   Total unique locations: {len(location_counts)}")
                for loc, count in location_counts.most_common(10):
                    print(f"   {loc}: {count} attacks")
            else:
                print("   No location data available")
        
        # IP Address analysis
        print("\n[SEARCH] IP Address Analysis:")
        if 'remote_address' in df.columns and len(df) > 0:
            ips = []
            for addr in df['remote_address']:
                if isinstance(addr, str) and ':' in addr:
                    ip = addr.split(':')[0]
                    if ip not in ['127.0.0.1', 'localhost', '']:
                        ips.append(ip)
            
            if ips:
                from collections import Counter
                ip_counts = Counter(ips)
                print(f"   Total unique IPs: {len(ip_counts)}")
                for ip, count in ip_counts.most_common(5):
                    print(f"   {ip}: {count} connections")
            else:
                print("   No external IPs found")
        
        # Save report - FIXED JSON SERIALIZATION ISSUE
        try:
            report = {
                "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_events": int(len(df)),
                "event_types": {},
                "daily_summary": {},
                "top_locations": [],
                "top_ips": []
            }
            
            # Convert event_counts to dict
            if 'reason' in df.columns and len(df) > 0:
                report["event_types"] = df['reason'].value_counts().to_dict()
            
            # Convert daily_counts to dict with string keys
            if 'timestamp' in df.columns and len(df) > 0:
                daily_counts_dict = {}
                if 'date_str' in df.columns:
                    for date_str, count in df['date_str'].value_counts().items():
                        daily_counts_dict[str(date_str)] = int(count)
                report["daily_summary"] = daily_counts_dict
            
            # Add location data
            if locations:
                from collections import Counter
                location_counts = Counter(locations)
                report["top_locations"] = [
                    {"location": loc, "count": count} 
                    for loc, count in location_counts.most_common(10)
                ]
            
            # Add IP data
            if 'remote_address' in df.columns and len(df) > 0:
                ips = []
                for addr in df['remote_address']:
                    if isinstance(addr, str) and ':' in addr:
                        ip = addr.split(':')[0]
                        if ip not in ['127.0.0.1', 'localhost', '']:
                            ips.append(ip)
                
                if ips:
                    from collections import Counter
                    ip_counts = Counter(ips)
                    report["top_ips"] = [
                        {"ip": ip, "count": count}
                        for ip, count in ip_counts.most_common(10)
                    ]
            
            # Save report
            with open("analysis_report.json", 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
            
            print(f"\n[OK] Analysis report saved to: analysis_report.json")
            
            # Show report summary
            print(f"\n📋 REPORT SUMMARY:")
            print(f"   Saved at: {report['analysis_time']}")
            print(f"   Total events: {report['total_events']}")
            print(f"   Event types: {len(report['event_types'])}")
            print(f"   Days covered: {len(report['daily_summary'])}")
            
        except Exception as e:
            print(f"\n[ERROR] Error saving report: {e}")
    
    def visualize_data(self):
        """Data visualization create kare"""
        logs = self.load_logs()
        
        if not logs:
            print("No logs to visualize.")
            return
        
        df = pd.DataFrame(logs)
        
        if len(df) == 0:
            print("No data to visualize.")
            return
        
        # Create visualization
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        fig.suptitle('Security Analysis Dashboard', fontsize=16)
        
        # 1. Event types pie chart
        if 'reason' in df.columns and len(df) > 0:
            event_counts = df['reason'].value_counts()
            if len(event_counts) > 0:
                axes[0, 0].pie(event_counts.values, labels=event_counts.index, autopct='%1.1f%%')
                axes[0, 0].set_title('Types of Security Events')
            else:
                axes[0, 0].text(0.5, 0.5, 'No event data', 
                               ha='center', va='center')
                axes[0, 0].set_title('Types of Security Events')
        
        # 2. Daily events line chart
        if 'timestamp' in df.columns and len(df) > 0:
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.dropna(subset=['timestamp'])
                df['date'] = df['timestamp'].dt.date
                daily_counts = df['date'].value_counts().sort_index()
                
                if len(daily_counts) > 0:
                    axes[0, 1].plot(daily_counts.index.astype(str), daily_counts.values, marker='o')
                    axes[0, 1].set_title('Events Over Time')
                    axes[0, 1].set_xlabel('Date')
                    axes[0, 1].set_ylabel('Number of Events')
                    plt.setp(axes[0, 1].xaxis.get_majorticklabels(), rotation=45)
                else:
                    axes[0, 1].text(0.5, 0.5, 'No time data', 
                                   ha='center', va='center')
                    axes[0, 1].set_title('Events Over Time')
            except:
                axes[0, 1].text(0.5, 0.5, 'Error in time data', 
                               ha='center', va='center')
                axes[0, 1].set_title('Events Over Time')
        
        # 3. Location bar chart
        if 'geolocation' in df.columns and len(df) > 0:
            locations = []
            for geo in df['geolocation']:
                if isinstance(geo, dict):
                    country = geo.get('country', 'Unknown')
                    if country not in ['N/A', 'Unknown']:
                        locations.append(country)
            
            if locations:
                from collections import Counter
                location_counts = Counter(locations)
                
                countries = list(location_counts.keys())[:5]  # Top 5
                counts = list(location_counts.values())[:5]
                
                if countries:
                    axes[1, 0].barh(countries, counts)
                    axes[1, 0].set_title('Top Attack Locations')
                    axes[1, 0].set_xlabel('Number of Attacks')
                else:
                    axes[1, 0].text(0.5, 0.5, 'No location data', 
                                   ha='center', va='center')
                    axes[1, 0].set_title('Top Attack Locations')
            else:
                axes[1, 0].text(0.5, 0.5, 'No location data', 
                               ha='center', va='center')
                axes[1, 0].set_title('Top Attack Locations')
        
        # 4. Resource usage scatter plot
        if 'cpu' in df.columns and 'memory' in df.columns and len(df) > 0:
            # Filter numeric values
            df_numeric = df.copy()
            df_numeric['cpu'] = pd.to_numeric(df_numeric['cpu'], errors='coerce')
            df_numeric['memory'] = pd.to_numeric(df_numeric['memory'], errors='coerce')
            df_numeric = df_numeric.dropna(subset=['cpu', 'memory'])
            
            if len(df_numeric) > 0:
                axes[1, 1].scatter(df_numeric['cpu'], df_numeric['memory'], alpha=0.6)
                axes[1, 1].set_title('Process Resource Usage')
                axes[1, 1].set_xlabel('CPU Usage (%)')
                axes[1, 1].set_ylabel('Memory Usage (%)')
            else:
                axes[1, 1].text(0.5, 0.5, 'No resource data', 
                               ha='center', va='center')
                axes[1, 1].set_title('Process Resource Usage')
        else:
            # Show logs summary
            try:
                summary_text = f"Logs Summary:\n"
                summary_text += f"Total Entries: {len(df)}\n"
                if 'timestamp' in df.columns:
                    summary_text += f"Time Range: {df['timestamp'].min()} to {df['timestamp'].max()}\n"
                if 'reason' in df.columns:
                    summary_text += f"Event Types: {len(df['reason'].unique())}"
                
                axes[1, 1].text(0.5, 0.5, summary_text, 
                               ha='center', va='center', fontsize=10)
                axes[1, 1].set_title('Logs Summary')
            except:
                axes[1, 1].text(0.5, 0.5, 'No data available', 
                               ha='center', va='center')
                axes[1, 1].set_title('Logs Summary')
        
        plt.tight_layout()
        
        # Save figure
        try:
            plt.savefig('security_analysis.png', dpi=300, bbox_inches='tight')
            print(f"\n[CHART] Visualization saved as: security_analysis.png")
        except Exception as e:
            print(f"\n[WARNING]  Could not save image: {e}")
        
        plt.show()
    
    def print_detailed_logs(self):
        """Detailed logs print kare"""
        logs = self.load_logs()
        
        if not logs:
            print("No logs to display.")
            return
        
        print("\n" + "="*80)
        print("DETAILED LOG ENTRIES")
        print("="*80)
        
        for i, log in enumerate(logs, 1):
            print(f"\n[DOCUMENT] ENTRY #{i}:")
            print("-"*40)
            
            for key, value in log.items():
                if key == 'geolocation' and isinstance(value, dict):
                    print(f"  {key}:")
                    for geo_key, geo_value in value.items():
                        print(f"    {geo_key}: {geo_value}")
                else:
                    print(f"  {key}: {value}")
            
            if i >= 10:  # Limit to 10 entries
                print(f"\n... and {len(logs) - 10} more entries")
                break

def main():
    analyzer = LogAnalyzer()
    
    print("="*60)
    print("CYBER SECURITY LOG ANALYZER")
    print("="*60)
    
    while True:
        print("\nOPTIONS:")
        print("1. Analyze Logs")
        print("2. Generate Visualization")
        print("3. View Detailed Logs")
        print("4. Check Log File")
        print("5. Exit")
        
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == '1':
                analyzer.analyze_logs()
            elif choice == '2':
                analyzer.visualize_data()
            elif choice == '3':
                analyzer.print_detailed_logs()
            elif choice == '4':
                logs = analyzer.load_logs()
                print(f"\nLog file status:")
                print(f"  File exists: {os.path.exists('intrusion_logs.json')}")
                print(f"  Entries loaded: {len(logs)}")
                if logs:
                    print(f"  First entry time: {logs[0].get('timestamp', 'N/A')}")
                    print(f"  Last entry time: {logs[-1].get('timestamp', 'N/A')}")
            elif choice == '5':
                print("\n👋 Exiting Log Analyzer. Stay Secure!")
                break
            else:
                print("Invalid choice. Please enter 1-5.")
                
        except KeyboardInterrupt:
            print("\n\n[WARNING]  Operation cancelled by user.")
            break
        except Exception as e:
            print(f"\n[ERROR] Error: {e}")

if __name__ == "__main__":
    main()