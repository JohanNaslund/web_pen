# ip_config.py - Enkel IP-konfigurationshantering

import os
import json
from typing import Optional, Dict

class IPConfigManager:
    """Hantera IP-konfiguration via fil"""
    
    def __init__(self, config_file: str = '/app/results/ip_config.json'):
        self.config_file = config_file
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Ladda IP-konfiguration från fil"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"[IPConfig] Fel vid laddning av konfiguration: {e}")
        
        return {}
    
    def _save_config(self) -> bool:
        """Spara IP-konfiguration till fil"""
        try:
            # Skapa mapp om den inte finns
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"[IPConfig] Fel vid sparande av konfiguration: {e}")
            return False
    
    def get_exposed_ip(self) -> Optional[str]:
        """Hämta den exponerade IP-adressen"""
        return self.config.get('exposed_ip')
    
    def set_exposed_ip(self, ip: str) -> bool:
        """Sätt den exponerade IP-adressen"""
        self.config['exposed_ip'] = ip
        self.config['last_updated'] = str(os.times().elapsed)
        return self._save_config()
    
    def is_configured(self) -> bool:
        """Kontrollera om IP är konfigurerad"""
        return bool(self.get_exposed_ip())
    
    def get_urls(self) -> Dict[str, str]:
        """Hämta alla URL:er baserat på konfigurerad IP"""
        ip = self.get_exposed_ip()
        if not ip:
            return {
                'app_url': 'http://localhost:5001',
                'zap_url': 'http://localhost:8080', 
                'proxy_url': 'http://localhost:8090'
            }
        
        return {
            'app_url': f'http://{ip}:5001',
            'zap_url': f'http://{ip}:8080',
            'proxy_url': f'http://{ip}:8090'
        }
    
    def get_config_info(self) -> Dict:
        """Hämta all konfigurationsinformation"""
        return {
            'exposed_ip': self.get_exposed_ip(),
            'is_configured': self.is_configured(),
            'config_file': self.config_file,
            'urls': self.get_urls()
        }
    
    def reset_config(self) -> bool:
        """Rensa IP-konfiguration"""
        self.config = {}
        return self._save_config()

# Global instans
ip_config = IPConfigManager()

# Convenience functions
def get_exposed_ip():
    return ip_config.get_exposed_ip()

def set_exposed_ip(ip: str):
    return ip_config.set_exposed_ip(ip)

def is_ip_configured():
    return ip_config.is_configured()

def get_app_urls():
    return ip_config.get_urls()