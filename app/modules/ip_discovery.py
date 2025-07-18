# ip_discovery.py - Lägg till denna fil i app/modules/

import os
import socket
import subprocess
import requests
from typing import Optional

class IPDiscovery:
    """Hjälpklass för att upptäcka rätt IP-adresser i Docker-miljö"""
    
    def __init__(self):
        self.host_ip = None
        self.external_ip = None
        self._discover_ips()
    
    def _discover_ips(self):
        """Upptäck både host IP och extern IP"""
        self.host_ip = self._get_host_ip()
        self.external_ip = self._get_external_ip()
    
    def _get_host_ip(self) -> Optional[str]:
        """Hämta host IP-adress från miljövariabel eller auto-upptäck"""
        
        # 1. Kolla miljövariabel först
        host_ip = os.getenv('HOST_IP')
        if host_ip and host_ip != 'auto':
            return host_ip
        
        # 2. Försök hitta Docker host IP via gateway
        try:
            gateway_ip = subprocess.check_output([
                'ip', 'route', 'show', 'default'
            ], text=True).split()[2]
            
            # Testa om gateway är tillgänglig
            if self._test_ip_connectivity(gateway_ip):
                return gateway_ip
        except:
            pass
        
        # 3. Försök hitta via Docker container networking
        try:
            # Kolla om host.docker.internal fungerar
            socket.gethostbyname('host.docker.internal')
            return 'host.docker.internal'
        except:
            pass
        
        # 4. Försök hitta via /proc/net/route
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f:
                    fields = line.strip().split()
                    if fields[1] == '00000000':  # Default route
                        gateway = int(fields[2], 16)
                        return socket.inet_ntoa(gateway.to_bytes(4, 'little'))
        except:
            pass
        
        # 5. Fallback: försök hämta från externa API
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except:
            pass
        
        return None
    
    def _get_external_ip(self) -> Optional[str]:
        """Hämta extern IP-adress"""
        
        # 1. Kolla miljövariabel först
        external_ip = os.getenv('EXTERNAL_IP')
        if external_ip and external_ip != 'auto':
            return external_ip
        
        # 2. Använd host IP om tillgänglig
        if self.host_ip and self.host_ip != 'host.docker.internal':
            return self.host_ip
        
        # 3. Försök hämta från externa tjänster
        services = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://icanhazip.com',
            'https://ident.me'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if self._is_valid_ip(ip):
                        return ip
            except:
                continue
        
        return None
    
    def _test_ip_connectivity(self, ip: str, port: int = 80) -> bool:
        """Testa om IP är tillgänglig"""
        try:
            socket.setdefaulttimeout(3)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, port))
            return True
        except:
            return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validera IP-adress format"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False
    
    def get_proxy_url(self, port: int = 8090) -> str:
        """Hämta proxy URL för ZAP"""
        if self.host_ip:
            return f"http://{self.host_ip}:{port}"
        return f"http://localhost:{port}"
    
    def get_zap_url(self, port: int = 8080) -> str:
        """Hämta ZAP UI URL"""
        if self.host_ip:
            return f"http://{self.host_ip}:{port}"
        return f"http://localhost:{port}"
    
    def get_app_url(self, port: int = 5001) -> str:
        """Hämta applikations-URL"""
        if self.external_ip:
            return f"http://{self.external_ip}:{port}"
        elif self.host_ip:
            return f"http://{self.host_ip}:{port}"
        return f"http://localhost:{port}"
    
    def get_info(self) -> dict:
        """Hämta all IP-information"""
        return {
            'host_ip': self.host_ip,
            'external_ip': self.external_ip,
            'proxy_url': self.get_proxy_url(),
            'zap_url': self.get_zap_url(),
            'app_url': self.get_app_url()
        }

# Singleton instans
ip_discovery = IPDiscovery()

# Convenience functions
def get_host_ip():
    return ip_discovery.host_ip

def get_external_ip():
    return ip_discovery.external_ip

def get_proxy_url(port=8090):
    return ip_discovery.get_proxy_url(port)

def get_zap_url(port=8080):
    return ip_discovery.get_zap_url(port)

def get_app_url(port=5001):
    return ip_discovery.get_app_url(port)