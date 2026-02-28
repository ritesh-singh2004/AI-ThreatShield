# scan.py - Advanced Security Scanner
"""
Advanced Security Scanner for System Analysis and Vulnerability Detection
Version: 2.0
Author: Security Team
"""

import os
import json
import time
from datetime import datetime
import subprocess
import platform
import hashlib
import socket
import re
import sys
from typing import List, Dict, Any, Optional

class SecurityScanner:
    """Advanced security scanner for system analysis and vulnerability detection."""
    
    def __init__(self):
        """Initialize the security scanner with default configurations."""
        self.scan_results = {
            "scan_timestamp": datetime.now().isoformat(),
            "system_info": {},
            "files_scanned": [],
            "vulnerabilities_found": [],
            "recommendations": [],
            "network_info": {},
            "file_hashes": {},
            "scan_summary": {}
        }
        
        # Configuration
        self.suspicious_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.sh', '.pyc', '.dll', '.so']
        self.sensitive_keywords = ['password', 'secret', 'api_key', 'token', 'private_key', 'ssh-rsa']
        self.dangerous_functions = ['eval(', 'exec(', '__import__', 'pickle.loads', 'yaml.load']
        
    def get_system_info(self) -> Dict[str, Any]:
        """
        Collect comprehensive system information.
        
        Returns:
            Dictionary containing system information
        """
        system_info = {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "hostname": socket.gethostname(),
            "working_directory": os.getcwd(),
            "user": os.getenv('USER', os.getenv('USERNAME', 'Unknown')),
            "timestamp": datetime.now().isoformat()
        }
        
        # Add additional system info based on platform
        if platform.system() == "Linux":
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if 'PRETTY_NAME' in line:
                            system_info['os_name'] = line.split('=')[1].strip().strip('"')
                            break
            except:
                system_info['os_name'] = "Linux"
        
        self.scan_results["system_info"] = system_info
        return system_info
    
    def scan_directory(self, directory: str = ".", max_depth: int = 10) -> List[Dict[str, Any]]:
        """
        Recursively scan directory for files and collect metadata.
        
        Args:
            directory: Path to scan (default: current directory)
            max_depth: Maximum recursion depth
            
        Returns:
            List of file information dictionaries
        """
        print(f"[INFO] Starting directory scan: {directory}")
        
        file_count = 0
        total_size = 0
        scanned_files = []
        
        for root, dirs, files in os.walk(directory):
            # Calculate current depth
            current_depth = root[len(directory):].count(os.sep)
            if current_depth >= max_depth:
                dirs[:] = []  # Don't recurse deeper
                continue
            
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                # Skip hidden files
                if file.startswith('.'):
                    continue
                    
                file_path = os.path.join(root, file)
                
                try:
                    file_stat = os.stat(file_path)
                    file_info = {
                        "path": file_path,
                        "name": file,
                        "size_bytes": file_stat.st_size,
                        "size_human": self._format_bytes(file_stat.st_size),
                        "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                        "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                        "permissions": oct(file_stat.st_mode)[-3:],
                        "is_directory": os.path.isdir(file_path),
                        "is_file": os.path.isfile(file_path),
                        "depth": current_depth
                    }
                    
                    # Calculate file hash for small files
                    if file_stat.st_size < 5 * 1024 * 1024:  # 5MB limit
                        file_hash = self._calculate_file_hash(file_path)
                        if file_hash:
                            file_info['md5_hash'] = file_hash
                            self.scan_results["file_hashes"][file_path] = file_hash
                    
                    scanned_files.append(file_info)
                    total_size += file_stat.st_size
                    file_count += 1
                    
                    # Progress indicator for large scans
                    if file_count % 100 == 0:
                        print(f"[INFO] Scanned {file_count} files...")
                        
                except PermissionError:
                    print(f"[WARNING] Permission denied: {file_path}")
                except Exception as e:
                    print(f"[ERROR] Failed to scan {file_path}: {str(e)}")
        
        self.scan_results["files_scanned"] = scanned_files
        self.scan_results["scan_summary"]["total_files"] = file_count
        self.scan_results["scan_summary"]["total_size_bytes"] = total_size
        self.scan_results["scan_summary"]["total_size_human"] = self._format_bytes(total_size)
        
        print(f"[INFO] Directory scan complete: {file_count} files ({self._format_bytes(total_size)})")
        return scanned_files
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = "md5") -> Optional[str]:
        """
        Calculate hash of a file using specified algorithm.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            Hexadecimal hash string or None if failed
        """
        try:
            if algorithm == "md5":
                hash_obj = hashlib.md5()
            elif algorithm == "sha1":
                hash_obj = hashlib.sha1()
            elif algorithm == "sha256":
                hash_obj = hashlib.sha256()
            else:
                hash_obj = hashlib.md5()
            
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            print(f"[ERROR] Failed to calculate hash for {file_path}: {str(e)}")
            return None
    
    def _format_bytes(self, size_bytes: int) -> str:
        """
        Convert bytes to human-readable format.
        
        Args:
            size_bytes: Size in bytes
            
        Returns:
            Human readable size string
        """
        if size_bytes == 0:
            return "0B"
        
        size_units = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_units) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.2f} {size_units[i]}"
    
    def detect_suspicious_files(self) -> List[Dict[str, Any]]:
        """
        Detect suspicious files based on patterns and content analysis.
        
        Returns:
            List of detected suspicious files with details
        """
        print("[INFO] Starting suspicious file detection...")
        
        vulnerabilities = []
        
        # Pattern definitions for suspicious files
        suspicious_patterns = [
            (r'\.(exe|bat|cmd|ps1|vbs|js)$', "Executable/Script file", "HIGH"),
            (r'\.(pem|key|ppk|pfx)$', "Certificate/Key file", "HIGH"),
            (r'/(\.git|\.svn|\.env|\.ssh)', "Hidden configuration directory", "MEDIUM"),
            (r'/(backup|temp|tmp)/', "Temporary/Backup directory", "LOW"),
        ]
        
        for file_info in self.scan_results["files_scanned"]:
            file_path = file_info["path"]
            
            # Check file extension patterns
            for pattern, reason, severity in suspicious_patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": "SUSPICIOUS_FILE",
                        "file": file_path,
                        "reason": reason,
                        "severity": severity,
                        "details": f"Pattern match: {pattern}"
                    })
            
            # Check for sensitive content in text files
            if file_info["size_bytes"] < 1024 * 1024:  # 1MB limit
                self._check_file_content(file_path, vulnerabilities)
        
        # Add findings to results
        self.scan_results["vulnerabilities_found"].extend(vulnerabilities)
        
        print(f"[INFO] Suspicious file detection complete: {len(vulnerabilities)} findings")
        return vulnerabilities
    
    def _check_file_content(self, file_path: str, vulnerabilities: List[Dict[str, Any]]) -> None:
        """
        Check file content for sensitive information.
        
        Args:
            file_path: Path to the file
            vulnerabilities: List to append findings to
        """
        # Skip binary files
        text_extensions = ['.txt', '.py', '.js', '.json', '.yml', '.yaml', '.xml', '.html', '.md']
        if not any(file_path.endswith(ext) for ext in text_extensions):
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Check for sensitive patterns
                sensitive_patterns = [
                    (r'(?i)password\s*[:=]\s*[\'"][^\'"]+[\'"]', "Hardcoded password", "CRITICAL"),
                    (r'(?i)api[_-]?key\s*[:=]\s*[\'"][^\'"]+[\'"]', "API key exposure", "CRITICAL"),
                    (r'(?i)secret[_-]?key\s*[:=]\s*[\'"][^\'"]+[\'"]', "Secret key exposure", "CRITICAL"),
                    (r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----', "Private key exposure", "CRITICAL"),
                    (r'ssh-rsa\s+[A-Za-z0-9+/]+={0,3}', "SSH key exposure", "HIGH"),
                ]
                
                for pattern, reason, severity in sensitive_patterns:
                    if re.search(pattern, content):
                        vulnerabilities.append({
                            "type": "SENSITIVE_DATA_EXPOSURE",
                            "file": file_path,
                            "reason": reason,
                            "severity": severity,
                            "details": "Sensitive data found in file"
                        })
                        
        except Exception as e:
            # Skip files that can't be read
            pass
    
    def check_file_permissions(self) -> List[Dict[str, Any]]:
        """
        Check file permissions for security issues.
        
        Returns:
            List of permission recommendations
        """
        print("[INFO] Checking file permissions...")
        
        recommendations = []
        
        if platform.system() == "Windows":
            print("[INFO] File permission checks limited on Windows systems")
            return recommendations
        
        # Define expected permissions for sensitive files
        permission_rules = {
            # File pattern: (recommended_permissions, description)
            r'.*\.py$': ('644', 'Python scripts should not be world-writable'),
            r'.*\.(sh|bash)$': ('755', 'Executable scripts should have execute permission'),
            r'.*\.(key|pem|ppk)$': ('600', 'Private keys should be owner-readable only'),
            r'.*password.*': ('600', 'Password files should be restricted'),
            r'.*config\.(json|yaml|yml)$': ('644', 'Configuration files should not be world-writable'),
        }
        
        for file_info in self.scan_results["files_scanned"]:
            file_path = file_info["path"]
            current_perm = file_info.get("permissions", "000")
            
            # Apply permission rules
            for pattern, (expected_perm, description) in permission_rules.items():
                if re.match(pattern, file_path):
                    if current_perm != expected_perm:
                        recommendations.append({
                            "file": file_path,
                            "type": "PERMISSION_ISSUE",
                            "current_permissions": current_perm,
                            "recommended_permissions": expected_perm,
                            "description": description,
                            "severity": "MEDIUM"
                        })
        
        self.scan_results["recommendations"].extend(recommendations)
        print(f"[INFO] Permission check complete: {len(recommendations)} recommendations")
        return recommendations
    
    def check_network_security(self) -> Dict[str, Any]:
        """
        Perform basic network security checks.
        
        Returns:
            Dictionary containing network security information
        """
        print("[INFO] Performing network security checks...")
        
        network_info = {
            "hostname": socket.gethostname(),
            "timestamp": datetime.now().isoformat(),
            "local_services": []
        }
        
        try:
            # Get IP addresses
            network_info["ip_address"] = socket.gethostbyname(network_info["hostname"])
            
            # Check local services
            services_to_check = [
                (22, "SSH"),
                (80, "HTTP"),
                (443, "HTTPS"),
                (3306, "MySQL"),
                (5432, "PostgreSQL"),
                (6379, "Redis"),
                (8080, "HTTP-Alt"),
                (9000, "PHP-FPM")
            ]
            
            for port, service in services_to_check:
                if self._check_port("127.0.0.1", port):
                    network_info["local_services"].append({
                        "port": port,
                        "service": service,
                        "status": "OPEN"
                    })
                    
                    # Add vulnerability if risky service is open
                    if port in [22, 3306, 5432, 6379]:
                        self.scan_results["vulnerabilities_found"].append({
                            "type": "NETWORK_SERVICE",
                            "reason": f"{service} service running on port {port}",
                            "severity": "MEDIUM",
                            "details": "Consider securing or disabling unnecessary services"
                        })
        
        except Exception as e:
            network_info["error"] = str(e)
            print(f"[ERROR] Network check failed: {str(e)}")
        
        self.scan_results["network_info"] = network_info
        return network_info
    
    def _check_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """
        Check if a port is open on the specified host.
        
        Args:
            host: Hostname or IP address
            port: Port number to check
            timeout: Connection timeout in seconds
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def analyze_code_security(self) -> List[Dict[str, Any]]:
        """
        Analyze Python code for security vulnerabilities.
        
        Returns:
            List of code security findings
        """
        print("[INFO] Analyzing code for security vulnerabilities...")
        
        vulnerabilities = []
        
        # Security anti-patterns to detect
        security_patterns = [
            (r'eval\s*\(', 'eval() function usage', 'CRITICAL'),
            (r'exec\s*\(', 'exec() function usage', 'CRITICAL'),
            (r'__import__\s*\(', 'Dynamic import usage', 'HIGH'),
            (r'pickle\.loads\s*\(', 'Unsafe pickle deserialization', 'CRITICAL'),
            (r'yaml\.load\s*\(', 'Unsafe YAML loading', 'HIGH'),
            (r'subprocess\.(Popen|call|run).*shell\s*=\s*True', 'Shell injection risk', 'HIGH'),
            (r'os\.system\s*\(', 'Command injection risk', 'HIGH'),
            (r'input\s*\(', 'User input without validation', 'MEDIUM'),
            (r'(?i)debug\s*=\s*True', 'Debug mode enabled', 'LOW'),
        ]
        
        for file_info in self.scan_results["files_scanned"]:
            file_path = file_info["path"]
            
            if not file_path.endswith('.py'):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    for line_num, line in enumerate(lines, 1):
                        # Skip comments and empty lines
                        line_text = line.strip()
                        if not line_text or line_text.startswith('#'):
                            continue
                        
                        # Check for security patterns
                        for pattern, description, severity in security_patterns:
                            if re.search(pattern, line_text):
                                vulnerabilities.append({
                                    "type": "CODE_SECURITY",
                                    "file": file_path,
                                    "line": line_num,
                                    "code_snippet": line_text[:100],
                                    "description": description,
                                    "severity": severity,
                                    "pattern": pattern
                                })
                                
            except Exception as e:
                print(f"[WARNING] Failed to analyze {file_path}: {str(e)}")
        
        self.scan_results["vulnerabilities_found"].extend(vulnerabilities)
        print(f"[INFO] Code analysis complete: {len(vulnerabilities)} findings")
        return vulnerabilities
    
    def check_dependencies(self) -> List[Dict[str, Any]]:
        """
        Check Python dependencies for security issues.
        
        Returns:
            List of dependency security findings
        """
        print("[INFO] Checking Python dependencies...")
        
        recommendations = []
        dependency_files = ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py']
        
        for dep_file in dependency_files:
            if not os.path.exists(dep_file):
                continue
            
            try:
                with open(dep_file, 'r') as f:
                    content = f.read()
                    
                    # Check for insecure package patterns
                    insecure_patterns = [
                        (r'([a-zA-Z0-9_-]+)==(\d+)\.(\d+)\.(\d+)', 
                         "Pinned version detected - consider version ranges for security updates"),
                        (r'django[<>=!]', "Check Django version for security patches"),
                        (r'flask[<>=!]', "Check Flask version for security patches"),
                        (r'requests[<>=!]', "Check Requests version for security patches"),
                    ]
                    
                    for pattern, description in insecure_patterns:
                        if re.search(pattern, content):
                            recommendations.append({
                                "file": dep_file,
                                "type": "DEPENDENCY_SECURITY",
                                "description": description,
                                "severity": "LOW"
                            })
                            
            except Exception as e:
                print(f"[WARNING] Failed to check {dep_file}: {str(e)}")
        
        self.scan_results["recommendations"].extend(recommendations)
        print(f"[INFO] Dependency check complete: {len(recommendations)} recommendations")
        return recommendations
    
    def generate_security_report(self, output_format: str = "json") -> None:
        """
        Generate comprehensive security report.
        
        Args:
            output_format: Output format ('json', 'txt', or 'both')
        """
        print("\n" + "="*70)
        print("SECURITY SCAN REPORT")
        print("="*70)
        
        # Summary statistics
        total_files = len(self.scan_results["files_scanned"])
        total_size = self.scan_results["scan_summary"].get("total_size_human", "0B")
        vulnerabilities = len(self.scan_results["vulnerabilities_found"])
        recommendations = len(self.scan_results["recommendations"])
        
        print(f"\n📊 SCAN SUMMARY")
        print(f"   Scan Timestamp: {self.scan_results['scan_timestamp']}")
        print(f"   System: {self.scan_results['system_info'].get('platform', 'Unknown')}")
        print(f"   Files Scanned: {total_files}")
        print(f"   Total Size: {total_size}")
        print(f"   Vulnerabilities Found: {vulnerabilities}")
        print(f"   Recommendations: {recommendations}")
        
        # Vulnerability breakdown
        if vulnerabilities > 0:
            print(f"\n⚠️  VULNERABILITIES")
            
            # Group by severity
            severity_counts = {}
            for vuln in self.scan_results["vulnerabilities_found"]:
                severity = vuln.get("severity", "UNKNOWN")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    print(f"   {severity}: {count}")
            
            # Show critical findings
            critical_findings = [v for v in self.scan_results["vulnerabilities_found"] 
                               if v.get("severity") == "CRITICAL"]
            
            if critical_findings:
                print(f"\n   🔴 CRITICAL FINDINGS:")
                for i, vuln in enumerate(critical_findings[:3], 1):
                    print(f"      {i}. {vuln.get('type', 'Unknown')}")
                    print(f"         File: {vuln.get('file', 'N/A')}")
                    print(f"         Reason: {vuln.get('reason', vuln.get('description', 'N/A'))}")
        
        # Recommendations
        if recommendations > 0:
            print(f"\n💡 RECOMMENDATIONS")
            for i, rec in enumerate(self.scan_results["recommendations"][:5], 1):
                print(f"   {i}. {rec.get('description', 'No description')}")
                if 'file' in rec:
                    print(f"      File: {rec['file']}")
        
        # Save reports
        self._save_reports(output_format)
    
    def _save_reports(self, output_format: str = "json") -> None:
        """
        Save scan reports to files.
        
        Args:
            output_format: Output format ('json', 'txt', or 'both')
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format in ["json", "both"]:
            json_file = f"security_scan_{timestamp}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
            print(f"\n📄 JSON report saved: {json_file}")
        
        if output_format in ["txt", "both"]:
            txt_file = f"security_scan_{timestamp}.txt"
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write("SECURITY SCAN REPORT\n")
                f.write("="*70 + "\n\n")
                
                # Write summary
                f.write("SUMMARY\n")
                f.write("-"*70 + "\n")
                f.write(f"Scan Time: {self.scan_results['scan_timestamp']}\n")
                f.write(f"System: {self.scan_results['system_info'].get('platform', 'Unknown')}\n")
                f.write(f"Files Scanned: {len(self.scan_results['files_scanned'])}\n")
                f.write(f"Vulnerabilities: {len(self.scan_results['vulnerabilities_found'])}\n\n")
                
                # Write vulnerabilities
                if self.scan_results["vulnerabilities_found"]:
                    f.write("VULNERABILITIES\n")
                    f.write("-"*70 + "\n")
                    for vuln in self.scan_results["vulnerabilities_found"]:
                        f.write(f"[{vuln.get('severity', 'UNKNOWN')}] {vuln.get('type', 'Unknown')}\n")
                        f.write(f"File: {vuln.get('file', 'N/A')}\n")
                        f.write(f"Reason: {vuln.get('reason', vuln.get('description', 'N/A'))}\n")
                        if 'line' in vuln:
                            f.write(f"Line: {vuln['line']}\n")
                        f.write("\n")
            
            print(f"📄 TXT report saved: {txt_file}")
    
    def quick_scan(self) -> None:
        """Perform a quick security scan."""
        print("[INFO] Starting quick security scan...")
        self.get_system_info()
        self.scan_directory(max_depth=3)
        self.detect_suspicious_files()
        self.analyze_code_security()
        self.generate_security_report("both")
    
    def comprehensive_scan(self) -> None:
        """Perform a comprehensive security scan."""
        print("[INFO] Starting comprehensive security scan...")
        self.get_system_info()
        self.scan_directory(max_depth=10)
        self.detect_suspicious_files()
        self.check_file_permissions()
        self.check_network_security()
        self.analyze_code_security()
        self.check_dependencies()
        self.generate_security_report("both")
    
    def custom_scan(self, modules: List[str]) -> None:
        """
        Perform a custom scan with specified modules.
        
        Args:
            modules: List of module names to run
        """
        print(f"[INFO] Starting custom scan with modules: {modules}")
        
        if "system" in modules:
            self.get_system_info()
        
        if "files" in modules:
            self.scan_directory()
        
        if "suspicious" in modules:
            self.detect_suspicious_files()
        
        if "permissions" in modules:
            self.check_file_permissions()
        
        if "network" in modules:
            self.check_network_security()
        
        if "code" in modules:
            self.analyze_code_security()
        
        if "dependencies" in modules:
            self.check_dependencies()
        
        self.generate_security_report("both")

def print_banner():
    """Print the scanner banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║               ADVANCED SECURITY SCANNER v2.0             ║
    ║                  Professional Edition                    ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    """Main entry point for the security scanner."""
    print_banner()
    
    scanner = SecurityScanner()
    
    print("🔍 SECURITY SCAN MODES:")
    print("   1. Quick Scan (Fast, surface-level analysis)")
    print("   2. Comprehensive Scan (Full system analysis)")
    print("   3. Custom Scan (Select specific modules)")
    print("   4. File System Analysis Only")
    print("   5. Network Security Check")
    print("   6. Code Security Analysis")
    
    try:
        choice = input("\nSelect mode (1-6): ").strip()
        
        if choice == '1':
            scanner.quick_scan()
        elif choice == '2':
            scanner.comprehensive_scan()
        elif choice == '3':
            print("\nAvailable modules: system, files, suspicious, permissions, network, code, dependencies")
            modules_input = input("Enter modules (comma-separated): ").strip()
            modules = [m.strip() for m in modules_input.split(',')]
            scanner.custom_scan(modules)
        elif choice == '4':
            scanner.scan_directory()
            scanner.detect_suspicious_files()
            scanner.check_file_permissions()
            scanner.generate_security_report()
        elif choice == '5':
            scanner.get_system_info()
            scanner.check_network_security()
            scanner.generate_security_report()
        elif choice == '6':
            scanner.scan_directory()
            scanner.analyze_code_security()
            scanner.generate_security_report()
        else:
            print("[ERROR] Invalid selection. Please choose 1-6.")
            return 1
        
        print("\n" + "="*70)
        print("✅ SCAN COMPLETED SUCCESSFULLY")
        print("="*70)
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n[INFO] Scan interrupted by user.")
        return 130
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())