import subprocess

class FirewallManager:
    def block_ip(self, ip_address):
        # Windows Firewall rule add karein
        cmd = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
        subprocess.run(cmd, shell=True)
    
    def block_port(self, port):
        cmd = f'netsh advfirewall firewall add rule name="Block Port {port}" dir=in action=block protocol=TCP localport={port}'
        subprocess.run(cmd, shell=True)