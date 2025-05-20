#!/usr/bin/env python3
# zap_maintenance.py

import time
import sys
import os
import psutil
from zapv2 import ZAPv2

def main():
    """Huvudfunktion för ZAP-underhåll"""
    # Konfiguration
    ZAP_API_KEY = os.environ.get('ZAP_API_KEY', 'changeme123')
    ZAP_HOST = os.environ.get('ZAP_HOST', 'localhost')
    ZAP_PORT = int(os.environ.get('ZAP_PORT', 8080))
    MAX_MEMORY_PERCENT = float(os.environ.get('ZAP_MAX_MEMORY', 50.0))
    
    try:
        # Anslut till ZAP
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={
            'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
            'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
        })
        
        print(f"Connected to ZAP {zap.core.version}")
        
        # Kontrollera processer
        java_processes = []
        firefox_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            if 'java' in proc.info['name'].lower():
                java_processes.append(proc.info)
            elif 'firefox' in proc.info['name'].lower():
                firefox_processes.append(proc.info)
        
        java_mem = sum(p.get('memory_percent', 0) for p in java_processes)
        firefox_mem = sum(p.get('memory_percent', 0) for p in firefox_processes)
        
        print(f"Java processes: {len(java_processes)}, Memory: {java_mem:.1f}%")
        print(f"Firefox processes: {len(firefox_processes)}, Memory: {firefox_mem:.1f}%")
        
        # Underhållsåtgärder
        if java_mem > MAX_MEMORY_PERCENT or firefox_mem > MAX_MEMORY_PERCENT:
            print("Memory usage too high, performing maintenance...")
            
            # 1. Stoppa alla pågående skanningar
            try:
                for scan in zap.ascan.scan_progress():
                    scan_id = scan.get('id')
                    if scan_id and int(zap.ascan.status(scan_id)) < 100:
                        print(f"Stopping scan {scan_id}")
                        zap.ascan.stop(scan_id)
            except Exception as e:
                print(f"Error stopping scans: {str(e)}")
            
            # 2. Rensa historik och alerts
            try:
                alerts_count = len(zap.core.alerts())
                if alerts_count > 1000:
                    print(f"Clearing {alerts_count} alerts")
                    zap.core.delete_all_alerts()
            except Exception as e:
                print(f"Error clearing alerts: {str(e)}")
            
            # 3. Kör garbage collection
            try:
                print("Triggering Java garbage collection")
                zap.core.run_garbage_collection()
            except Exception as e:
                print(f"Error running GC: {str(e)}")
            
            # 4. Om systemet fortfarande har för högt minnesanvändning, försök starta om ZAP
            total_mem = java_mem + firefox_mem
            if total_mem > 80.0:  # Över 80% är kritiskt
                print("WARNING: Memory usage critical. Consider restarting ZAP.")
                # Här skulle du kunna implementera logik för att starta om ZAP
        
        else:
            print("System resources within acceptable limits.")
            
        return 0
    
    except Exception as e:
        print(f"Error in ZAP maintenance: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())