import json
import os
import time
from pathlib import Path

class SessionManager:
    def __init__(self, storage_path):
        self.storage_path = storage_path
        # Skapa katalogen om den inte finns
        os.makedirs(storage_path, exist_ok=True)
        
    def save_cookies(self, session_name, url, cookies):
        """Spara cookies från en webbsession"""
        session_data = {
            'target_url': url,
            'cookies': cookies,
            'timestamp': time.time()
        }
        
        with open(f"{self.storage_path}/{session_name}.json", 'w') as f:
            json.dump(session_data, f)
        
        return True
    
    def load_cookies(self, session_name):
        """Ladda cookies för en sparad session"""
        try:
            with open(f"{self.storage_path}/{session_name}.json", 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return None
    
    def list_sessions(self):
        """Lista alla tillgängliga sessioner"""
        sessions = []
        for file in os.listdir(self.storage_path):
            if file.endswith('.json'):
                session_name = file[:-5]  # Ta bort .json
                session_data = self.load_cookies(session_name)
                sessions.append({
                    'name': session_name,
                    'url': session_data.get('target_url'),
                    'timestamp': session_data.get('timestamp')
                })
        return sessions
    
    def replay_session(self, session_name, new_session_name):
        """Spela upp en session med en ny användare"""
        # Här skulle du implementera logiken för att spela upp en session
        # Detta kräver mer komplex implementation
        pass