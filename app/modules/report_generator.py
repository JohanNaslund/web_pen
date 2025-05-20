import json
import time
import os
import uuid
from pathlib import Path

class ReportGenerator:
    def __init__(self, storage_path):
        self.storage_path = storage_path
        Path(storage_path).mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, target_url, zap_alerts, sqlmap_results):
        """Generera en rapport baserad på scanningsresultat"""
        report_id = str(uuid.uuid4())
        timestamp = time.time()
        
        # Strukturera rapporten
        report = {
            'id': report_id,
            'timestamp': timestamp,
            'target_url': target_url,
            'summary': {
                'zap_alerts_count': len(zap_alerts),
                'sqlmap_findings_count': len(sqlmap_results),
                'severity_counts': self._count_severity(zap_alerts)
            },
            'zap_findings': zap_alerts,
            'sqlmap_findings': sqlmap_results,
            'report_date': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
        }
        
        # Spara rapporten
        with open(f"{self.storage_path}/{report_id}.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_id
    
    def get_report_path(self, report_id):
        """Få sökvägen till en rapport"""
        return f"{self.storage_path}/{report_id}.json"
    
    def _count_severity(self, alerts):
        """Räkna förekomster av olika allvarlighetsgrader"""
        counts = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'informational': 0
        }
        
        for alert in alerts:
            risk = alert.get('risk', '').lower()
            if risk in counts:
                counts[risk] += 1
        
        return counts
    

    # Add this function to ReportGenerator class in report_generator.py
    def add_ajax_spider_results(self, report_data, ajax_spider_results):
        """Add Ajax Spider results to the report"""
        if not ajax_spider_results:
            return
        
        # Create a dedicated section for Ajax Spider results
        ajax_spider_section = {
            'total_urls': len(ajax_spider_results),
            'urls_with_params': sum(1 for url in ajax_spider_results if 'url' in url and '?' in url['url']),
            'interesting_findings': []
        }
        
        # Analyze results to find interesting URLs
        for result in ajax_spider_results:
            url = result.get('url', '')
            method = result.get('method', 'GET')
            status_code = result.get('statusCode', 0)
            
            # Check if URL has parameters (potential injection points)
            if '?' in url:
                # Extract parameters
                params_part = url.split('?', 1)[1]
                params = params_part.split('&')
                
                ajax_spider_section['interesting_findings'].append({
                    'url': url,
                    'method': method,
                    'status_code': status_code,
                    'params': params,
                    'reason': 'URL with parameters (potential injection points)'
                })
            
            # Check for interesting status codes
            elif status_code >= 400:
                ajax_spider_section['interesting_findings'].append({
                    'url': url,
                    'method': method,
                    'status_code': status_code,
                    'reason': f'Error status code ({status_code})'
                })
            
            # Check for interesting paths
            elif any(pattern in url.lower() for pattern in ['/admin', '/login', '/user', '/account', '/dashboard']):
                ajax_spider_section['interesting_findings'].append({
                    'url': url,
                    'method': method,
                    'status_code': status_code,
                    'reason': 'Potentially sensitive path'
                })
        
        # Only include interesting findings in the report
        report_data['ajax_spider_findings'] = ajax_spider_section
        
        # Update summary statistics
        report_data['summary']['ajax_spider_urls_count'] = ajax_spider_section['total_urls']
        report_data['summary']['ajax_spider_interesting_count'] = len(ajax_spider_section['interesting_findings'])    