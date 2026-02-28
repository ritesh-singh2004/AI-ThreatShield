"""
Fix encoding issues for Windows
Run this script before main.py
"""

import sys
import os

def fix_windows_encoding():
    """Fix Windows encoding issues"""
    print("Fixing Windows encoding issues...")
    
    if sys.platform == "win32":
        # Set environment variables
        os.environ['PYTHONIOENCODING'] = 'utf-8'
        
        # Fix stdout encoding
        try:
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
            print("✅ Fixed stdout/stderr encoding")
        except:
            print("⚠️ Could not fix stdout encoding")
        
        # Fix file encoding in existing files
        files_to_fix = ['main.py', 'log_analyzer.py', 'ids_detector.py']
        
        for filename in files_to_fix:
            if os.path.exists(filename):
                try:
                    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Remove problematic Unicode characters
                    safe_content = content.replace('🚨', '[ALERT]')
                    safe_content = safe_content.replace('🔒', '[LOCK]')
                    safe_content = safe_content.replace('📊', '[CHART]')
                    safe_content = safe_content.replace('⚠️', '[WARNING]')
                    safe_content = safe_content.replace('✅', '[OK]')
                    safe_content = safe_content.replace('❌', '[ERROR]')
                    safe_content = safe_content.replace('🔍', '[SEARCH]')
                    safe_content = safe_content.replace('📁', '[FOLDER]')
                    safe_content = safe_content.replace('🎯', '[TARGET]')
                    safe_content = safe_content.replace('👉', '[POINT]')
                    safe_content = safe_content.replace('🛡️', '[SHIELD]')
                    safe_content = safe_content.replace('🔄', '[REFRESH]')
                    safe_content = safe_content.replace('⚡', '[FLASH]')
                    safe_content = safe_content.replace('📈', '[GRAPH]')
                    safe_content = safe_content.replace('📝', '[NOTE]')
                    safe_content = safe_content.replace('🔐', '[KEY]')
                    safe_content = safe_content.replace('🧹', '[CLEAN]')
                    safe_content = safe_content.replace('📦', '[PACKAGE]')
                    safe_content = safe_content.replace('📄', '[DOCUMENT]')
                    safe_content = safe_content.replace('🎨', '[ART]')
                    safe_content = safe_content.replace('🚀', '[ROCKET]')
                    
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(safe_content)
                    
                    print(f"✅ Fixed {filename}")
                except Exception as e:
                    print(f"⚠️ Could not fix {filename}: {e}")
    
    print("\n✅ Encoding fix completed!")
    print("Now run: python main.py")

if __name__ == "__main__":
    fix_windows_encoding()