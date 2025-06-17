# app/modules/access_control_manager.py
import os
import json
import time
import requests
from pathlib import Path

class AccessControlManager:
    def __init__(self, zap_controller, storage_path='./data/access_control'):
        self.zap = zap_controller
        self.storage_path = storage_path
        Path(storage_path).mkdir(parents=True, exist_ok=True)
        
        # Separate storage för olika sessioner
        self.sessions_dir = os.path.join(storage_path, 'sessions')
        self.tests_dir = os.path.join(storage_path, 'tests')
        self.reports_dir = os.path.join(storage_path, 'reports')
        
        for dir_path in [self.sessions_dir, self.tests_dir, self.reports_dir]:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    def reset_for_new_test(self):
        """Nollställ ZAP för access control testing"""
        try:
            # Samma reset som för säkerhetstestning
            alerts_result = self.zap._direct_api_call('core/action/deleteAllAlerts')
            
            zap_reset_result = self.zap._direct_api_call('core/action/newSession', {
                'name': 'access_control_session',
                'overwrite': 'true'
            }, timeout=20)
            
            if zap_reset_result['success']:
                return {
                    'success': True,
                    'message': 'ZAP reset successful for Access Control Testing'
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to reset ZAP session'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def collect_session_urls(self, session_label, target_url):
        """Samla URL:er från nuvarande ZAP-session"""
        try:
            # Hämta alla meddelanden från ZAP
            messages_result = self.zap._direct_api_call('core/view/messages', {
                'baseurl': '',
                'start': '0',
                'count': '2000'  # Öka för att få fler URL:er
            })
            
            if not messages_result['success']:
                raise Exception("Failed to fetch messages from ZAP")
            
            collected_urls = []
            messages = messages_result['data'].get('messages', [])
            
            # Filtrera och bearbeta meddelanden
            unique_urls = set()  # Undvik dubbletter
            
            for message in messages:
                url = message.get('url', '')
                method = message.get('method', 'GET')
                
                # Skippa om URL redan finns
                url_key = f"{method}:{url}"
                if url_key in unique_urls:
                    continue
                unique_urls.add(url_key)
                
                # Extrahera status kod
                status_code = self._extract_status_code(message.get('responseHeader', ''))
                
                # Bara behåll URL:er som gav 200-svar (lyckade requests)
                if status_code not in [200, 201, 202, 204]:
                    continue
                
                url_data = {
                    'url': url,
                    'method': method,
                    'request_body': message.get('requestBody', ''),
                    'status_code': status_code,
                    'session_label': session_label,
                    'target_url': target_url,
                    'timestamp': time.time(),
                    'request_header': message.get('requestHeader', ''),
                    'cookies_used': self._extract_cookies(message.get('requestHeader', ''))
                }
                
                # Kategorisera URL:er
                url_data['category'] = self._categorize_url(url)
                collected_urls.append(url_data)
            
            # Spara sessionsdata
            session_data = {
                'session_label': session_label,
                'target_url': target_url,
                'collection_time': time.time(),
                'url_count': len(collected_urls),
                'urls': collected_urls
            }
            
            filename = f"session_{session_label}_{int(time.time())}.json"
            filepath = os.path.join(self.sessions_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(session_data, f, indent=2)
            
            return {
                'success': True,
                'filename': filename,
                'session_label': session_label,
                'url_count': len(collected_urls),
                'categories': self._get_url_categories(collected_urls),
                'preview_urls': collected_urls[:10]  # Första 10 för preview
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_collected_sessions(self):
        """Lista alla insamlade sessioner"""
        sessions = []
        
        try:
            for filename in os.listdir(self.sessions_dir):
                if filename.startswith('session_') and filename.endswith('.json'):
                    filepath = os.path.join(self.sessions_dir, filename)
                    
                    with open(filepath, 'r') as f:
                        session_data = json.load(f)
                    
                    sessions.append({
                        'filename': filename,
                        'session_label': session_data.get('session_label', 'Unknown'),
                        'target_url': session_data.get('target_url', ''),
                        'url_count': session_data.get('url_count', 0),
                        'collection_time': session_data.get('collection_time', 0),
                        'categories': self._get_url_categories(session_data.get('urls', []))
                    })
            
            # Sortera efter tid (nyast först)
            sessions.sort(key=lambda x: x['collection_time'], reverse=True)
            return sessions
            
        except Exception as e:
            print(f"Error listing sessions: {str(e)}")
            return []
    
    def get_session_urls(self, session_filename):
        """Hämta URL:er från en specifik session"""
        try:
            filepath = os.path.join(self.sessions_dir, session_filename)
            
            with open(filepath, 'r') as f:
                session_data = json.load(f)
            
            return {
                'success': True,
                'session_data': session_data
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def test_access_control(self, source_session_file, test_cookies, test_label, selected_urls=None):
        """Testa access control mellan sessioner"""
        try:
            # Ladda käll-sessionen
            source_result = self.get_session_urls(source_session_file)
            if not source_result['success']:
                raise Exception(f"Failed to load source session: {source_result['error']}")
            
            source_urls = source_result['session_data']['urls']
            
            # Filtrera URL:er om specifika URL:er valts
            if selected_urls:
                source_urls = [url for url in source_urls if url['url'] in selected_urls]
            
            test_results = []
            
            print(f"Testing {len(source_urls)} URLs with {test_label} credentials")
            
            for i, url_data in enumerate(source_urls):
                try:
                    print(f"Testing {i+1}/{len(source_urls)}: {url_data['method']} {url_data['url']}")
                    
                    # Testa URL:en med nya credentials
                    result = self._test_single_url(
                        url_data['url'],
                        url_data['method'],
                        url_data['request_body'],
                        test_cookies
                    )
                    
                    # Analysera resultatet
                    analysis = self._analyze_access_result(url_data, result, test_label)
                    test_results.append(analysis)
                    
                    # Lägg till delay för att inte överbelasta servern
                    time.sleep(0.3)
                    
                except Exception as e:
                    print(f"Error testing URL {url_data['url']}: {str(e)}")
                    test_results.append({
                        'url': url_data['url'],
                        'method': url_data['method'],
                        'error': str(e),
                        'risk_level': 'ERROR',
                        'finding': 'TEST_ERROR'
                    })
            
            # Spara testresultat
            test_data = {
                'source_session_file': source_session_file,
                'source_session_label': source_result['session_data']['session_label'],
                'test_label': test_label,
                'test_time': time.time(),
                'total_tested': len(test_results),
                'results': test_results
            }
            
            test_filename = f"test_{test_label}_{int(time.time())}.json"
            test_filepath = os.path.join(self.tests_dir, test_filename)
            
            with open(test_filepath, 'w') as f:
                json.dump(test_data, f, indent=2)
            
            # Analysera resultat
            analysis = self._analyze_test_results(test_results)
            
            return {
                'success': True,
                'test_filename': test_filename,
                'total_tested': len(test_results),
                'analysis': analysis,
                'high_risk_findings': [r for r in test_results if r.get('risk_level') == 'HIGH']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _test_single_url(self, url, method, body, cookies):
        """Testa en enskild URL med nya credentials"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        if cookies:
            headers['Cookie'] = cookies
        
        try:
            if method.upper() == 'POST':
                # Hantera både form-data och JSON
                if body.startswith('{'):
                    headers['Content-Type'] = 'application/json'
                    response = requests.post(url, json=json.loads(body), headers=headers, timeout=10, allow_redirects=False)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    response = requests.post(url, data=body, headers=headers, timeout=10, allow_redirects=False)
            elif method.upper() == 'PUT':
                response = requests.put(url, data=body, headers=headers, timeout=10, allow_redirects=False)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10, allow_redirects=False)
            else:
                response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
            
            return {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'response_headers': dict(response.headers),
                'is_redirect': response.is_redirect,
                'content_preview': response.text[:200] if response.text else ''
            }
            
        except requests.exceptions.Timeout:
            return {'status_code': 'TIMEOUT', 'error': 'Request timeout'}
        except requests.exceptions.ConnectionError:
            return {'status_code': 'CONNECTION_ERROR', 'error': 'Connection failed'}
        except Exception as e:
            return {'status_code': 'ERROR', 'error': str(e)}
    
    def _analyze_access_result(self, original_url_data, test_result, test_label):
        """Analysera access control resultat"""
        original_status = original_url_data.get('status_code', 200)
        test_status = test_result.get('status_code', 0)
        
        analysis = {
            'url': original_url_data['url'],
            'method': original_url_data['method'],
            'category': original_url_data.get('category', 'other'),
            'original_session': original_url_data['session_label'],
            'test_session': test_label,
            'original_status_code': original_status,
            'test_status_code': test_status,
            'content_length': test_result.get('content_length', 0),
            'timestamp': time.time()
        }
        
        # Risk-analys baserat på URL-kategori och svar
        if test_status in [200, 201, 202, 204]:
            # Framgångsrik åtkomst
            category = original_url_data.get('category', 'other')
            
            if category in ['admin', 'management', 'config']:
                analysis['risk_level'] = 'CRITICAL'
                analysis['finding'] = 'ADMIN_ACCESS_VIOLATION'
                analysis['description'] = f"KRITISK: {test_label} har åtkomst till admin-funktionalitet: {original_url_data['url']}"
            elif category in ['user_data', 'profile', 'account']:
                analysis['risk_level'] = 'HIGH'
                analysis['finding'] = 'USER_DATA_ACCESS'
                analysis['description'] = f"HÖG RISK: {test_label} har åtkomst till användardata: {original_url_data['url']}"
            else:
                analysis['risk_level'] = 'MEDIUM'
                analysis['finding'] = 'UNAUTHORIZED_ACCESS'
                analysis['description'] = f"Obehörig åtkomst till: {original_url_data['url']}"
                
        elif test_status in [401, 403]:
            analysis['risk_level'] = 'LOW'
            analysis['finding'] = 'ACCESS_CORRECTLY_DENIED'
            analysis['description'] = "Åtkomst korrekt nekad"
        elif test_status == 404:
            analysis['risk_level'] = 'LOW'
            analysis['finding'] = 'RESOURCE_NOT_FOUND'
            analysis['description'] = "Resurs inte tillgänglig"
        elif test_status in [302, 301]:
            analysis['risk_level'] = 'MEDIUM'
            analysis['finding'] = 'REDIRECT_RESPONSE'
            analysis['description'] = "Omdirigering - behöver manuell kontroll"
        else:
            analysis['risk_level'] = 'MEDIUM'
            analysis['finding'] = 'UNEXPECTED_RESPONSE'
            analysis['description'] = f"Oväntat svar: {test_status}"
        
        return analysis
    
    def _categorize_url(self, url):
        """Kategorisera URL baserat på dess innehåll"""
        url_lower = url.lower()
        
        # Admin/Management URLs
        if any(keyword in url_lower for keyword in ['admin', 'management', 'manager', 'control', 'config', 'settings']):
            return 'admin'
        
        # User data URLs
        elif any(keyword in url_lower for keyword in ['user', 'profile', 'account', 'dashboard', 'personal']):
            return 'user_data'
        
        # API endpoints
        elif '/api/' in url_lower or url_lower.endswith('.json') or url_lower.endswith('.xml'):
            return 'api'
        
        # File operations
        elif any(keyword in url_lower for keyword in ['upload', 'download', 'file', 'document']):
            return 'file_operations'
        
        # Authentication
        elif any(keyword in url_lower for keyword in ['login', 'logout', 'auth', 'signin', 'signout']):
            return 'authentication'
        
        # Reports/Data
        elif any(keyword in url_lower for keyword in ['report', 'export', 'data', 'analytics']):
            return 'reports'
        
        else:
            return 'other'
    
    def _get_url_categories(self, urls):
        """Räkna URL:er per kategori"""
        categories = {}
        for url_data in urls:
            category = url_data.get('category', 'other')
            categories[category] = categories.get(category, 0) + 1
        return categories
    
    def _analyze_test_results(self, test_results):
        """Analysera alla testresultat"""
        analysis = {
            'total_tested': len(test_results),
            'by_risk_level': {},
            'by_finding': {},
            'by_category': {},
            'summary': ''
        }
        
        for result in test_results:
            risk = result.get('risk_level', 'UNKNOWN')
            finding = result.get('finding', 'UNKNOWN')
            category = result.get('category', 'other')
            
            analysis['by_risk_level'][risk] = analysis['by_risk_level'].get(risk, 0) + 1
            analysis['by_finding'][finding] = analysis['by_finding'].get(finding, 0) + 1
            analysis['by_category'][category] = analysis['by_category'].get(category, 0) + 1
        
        # Skapa sammanfattning
        critical_count = analysis['by_risk_level'].get('CRITICAL', 0)
        high_count = analysis['by_risk_level'].get('HIGH', 0)
        
        if critical_count > 0:
            analysis['summary'] = f"KRITISK: {critical_count} allvarliga access control-brott upptäckta!"
        elif high_count > 0:
            analysis['summary'] = f"VARNING: {high_count} högrisk access control-problem upptäckta"
        else:
            analysis['summary'] = "Inga kritiska access control-problem upptäckta"
        
        return analysis
    
    def _extract_status_code(self, response_header):
        """Extrahera statuskod från response header"""
        try:
            first_line = response_header.split('\n')[0].strip()
            parts = first_line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
        except:
            pass
        return 200
    
    def _extract_cookies(self, request_header):
        """Extrahera cookies från request header"""
        for line in request_header.split('\n'):
            line = line.strip()
            if line.lower().startswith('cookie:'):
                return line[7:].strip()
        return ""