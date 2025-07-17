# Förbättrad AccessControlManager - ersätt i access_control_manager.py

import os
import json
import time
import requests
import re
from pathlib import Path
from urllib.parse import urlparse

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
    
# Uppdaterad AccessControlManager - ersätt reset_for_new_test() metoden i access_control_manager.py

    def reset_for_new_test(self):
        """Nollställ ZAP för access control testing och sätt Safe mode"""
        try:
            # Steg 1: Rensa alerts
            alerts_result = self.zap._direct_api_call('core/action/deleteAllAlerts')
            
            # Steg 2: Skapa ny session
            zap_reset_result = self.zap._direct_api_call('core/action/newSession', {
                'name': 'access_control_session',
                'overwrite': 'true'
            }, timeout=20)
            
            if not zap_reset_result['success']:
                return {
                    'success': False,
                    'error': 'Failed to reset ZAP session'
                }
            
            # Steg 3: Sätt ZAP till Safe mode för Access Control testing
            safe_mode_result = self.zap.set_mode('safe')
            
            if safe_mode_result:
                return {
                    'success': True,
                    'message': 'ZAP reset successful för Access Control Testing. ZAP är nu i Safe mode - inga attacker kommer att utföras.',
                    'zap_mode': 'safe'
                }
            else:
                # Om Safe mode misslyckades, ge varning men tillåt fortsättning
                return {
                    'success': True,
                    'message': 'ZAP reset successful för Access Control Testing. Varning: Kunde inte sätta Safe mode - var försiktig med POST/PUT-operationer.',
                    'warning': 'Failed to set Safe mode',
                    'zap_mode': 'unknown'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }    
    def collect_session_urls(self, session_label, target_url):
        """Samla URL:er från nuvarande ZAP-session med förbättrad scope-hantering"""
        try:
            print(f"[AccessControl] Collecting URLs for session '{session_label}' with target '{target_url}'")
            
            # Steg 1: Sätt upp context och scope för denna session
            context_name = f"AccessControl_{session_label}_{int(time.time())}"
            domain = self._extract_domain_or_ip(target_url)
            
            # Skapa context
            context_result = self.zap._direct_api_call('context/action/newContext', {
                'contextName': context_name
            })
            
            if context_result['success']:
                print(f"[AccessControl] Created context: {context_name}")
                
                # Sätt scope för hela domänen
                include_pattern = f".*{re.escape(domain)}.*"
                include_result = self.zap._direct_api_call('context/action/includeInContext', {
                    'contextName': context_name,
                    'regex': include_pattern
                })
                
                if include_result['success']:
                    print(f"[AccessControl] Set scope to include: {include_pattern}")
                else:
                    print(f"[AccessControl] Warning: Could not set scope: {include_result.get('response', 'Unknown error')}")
            else:
                print(f"[AccessControl] Warning: Could not create context: {context_result.get('response', 'Unknown error')}")
            
            # Steg 2: Hämta alla meddelanden från ZAP med ökad gräns
            messages_result = self.zap._direct_api_call('core/view/messages', {
                'baseurl': '',  # Hämta alla meddelanden
                'start': '0',
                'count': '5000'  # Öka antalet för att få fler URL:er
            })
            
            if not messages_result['success']:
                raise Exception(f"Failed to fetch messages from ZAP: {messages_result.get('error', 'Unknown error')}")
            
            messages = messages_result['data'].get('messages', [])
            print(f"[AccessControl] Found {len(messages)} total messages in ZAP")
            
            # Steg 3: Filtrera meddelanden för vår måldomän
            collected_urls = []
            unique_urls = set()  # Undvik dubbletter
            filtered_count = 0
            
            for message in messages:
                try:
                    # Extrahera URL från request header istället för message.url
                    url = self._extract_url_from_request_header(message.get('requestHeader', ''))
                    method = self._extract_method_from_request_header(message.get('requestHeader', ''))
                    
                    if not url or not method:
                        continue
                    
                    # Filtrera på måldomän
                    if domain not in url:
                        continue
                    
                    filtered_count += 1
                    
                    # Skapa unik nyckel
                    url_key = f"{method}:{url}"
                    if url_key in unique_urls:
                        continue
                    unique_urls.add(url_key)
                    
                    # Extrahera status kod
                    status_code = self._extract_status_code(message.get('responseHeader', ''))
                    
                    # Bara behåll framgångsrika requests (men inklusive redirects)
                    if status_code not in [200, 201, 202, 204, 301, 302, 304]:
                        continue
                    
                    # Skippa tekniska URL:er som inte är intressanta för access control
                    if self._should_skip_url(url):
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
                    
                except Exception as e:
                    print(f"[AccessControl] Error processing message: {str(e)}")
                    continue
            
            print(f"[AccessControl] Filtered {filtered_count} messages for domain {domain}")
            print(f"[AccessControl] Collected {len(collected_urls)} unique URLs after deduplication and filtering")
            
            # Steg 4: Om vi inte hittat många URL:er, försök med alternativ metod
            if len(collected_urls) < 5:
                print(f"[AccessControl] Few URLs found ({len(collected_urls)}), trying alternative collection method...")
                alternative_urls = self._collect_urls_alternative_method(target_url, domain)
                print(f"[AccessControl] Alternative method found {len(alternative_urls)} additional URLs")
                
                # Lägg till alternativa URL:er om de inte redan finns
                for alt_url in alternative_urls:
                    alt_key = f"{alt_url.get('method', 'GET')}:{alt_url.get('url', '')}"
                    if alt_key not in unique_urls:
                        alt_url['session_label'] = session_label
                        alt_url['target_url'] = target_url
                        alt_url['timestamp'] = time.time()
                        collected_urls.append(alt_url)
            
            # Steg 5: Spara sessionsdata
            session_data = {
                'session_label': session_label,
                'target_url': target_url,
                'collection_time': time.time(),
                'url_count': len(collected_urls),
                'urls': collected_urls,
                'context_name': context_name,
                'domain': domain,
                'scope_pattern': f".*{re.escape(domain)}.*"
            }
            
            filename = f"session_{session_label}_{int(time.time())}.json"
            filepath = os.path.join(self.sessions_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(session_data, f, indent=2)
            
            print(f"[AccessControl] Saved session data to {filename}")
            
            return {
                'success': True,
                'filename': filename,
                'session_label': session_label,
                'url_count': len(collected_urls),
                'categories': self._get_url_categories(collected_urls),
                'preview_urls': collected_urls[:10],  # Första 10 för preview
                'context_created': context_name,
                'scope_set': f".*{re.escape(domain)}.*"
            }
            
        except Exception as e:
            print(f"[AccessControl] Error in collect_session_urls: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _extract_url_from_request_header(self, request_header):
        """Extrahera URL från request header"""
        try:
            if not request_header:
                return None
            
            # Första raden innehåller HTTP-metoden och URL:en
            first_line = request_header.split('\r\n')[0].strip()
            if not first_line:
                first_line = request_header.split('\n')[0].strip()
            
            # Format: "GET /path HTTP/1.1" eller "GET http://full.url HTTP/1.1"
            parts = first_line.split()
            if len(parts) >= 2:
                url_part = parts[1]
                
                # Om det är en full URL, returnera den
                if url_part.startswith(('http://', 'https://')):
                    return url_part
                
                # Om det är en relativ path, konstruera full URL från Host header
                host = self._extract_host_from_request_header(request_header)
                if host and url_part.startswith('/'):
                    # Gissa protokoll baserat på port
                    protocol = 'https' if ':443' in host else 'http'
                    return f"{protocol}://{host}{url_part}"
            
            return None
        except Exception as e:
            print(f"[AccessControl] Error extracting URL from header: {str(e)}")
            return None
    
    def _extract_method_from_request_header(self, request_header):
        """Extrahera HTTP-metod från request header"""
        try:
            if not request_header:
                return None
            
            first_line = request_header.split('\r\n')[0].strip()
            if not first_line:
                first_line = request_header.split('\n')[0].strip()
            
            parts = first_line.split()
            if len(parts) >= 1:
                return parts[0].upper()
            
            return None
        except Exception:
            return None
    
    def _extract_host_from_request_header(self, request_header):
        """Extrahera Host från request header"""
        try:
            lines = request_header.split('\r\n')
            for line in lines:
                if line.lower().startswith('host:'):
                    return line.split(':', 1)[1].strip()
            return None
        except Exception:
            return None
    
    def _should_skip_url(self, url):
        """Avgör om en URL ska skippas från access control testing"""
        skip_patterns = [
            '/socket.io/',
            '.js',
            '.css',
            '.png',
            '.jpg',
            '.jpeg',
            '.gif',
            '.ico',
            '.woff',
            '.ttf',
            '/favicon',
            '/health',
            '/ping',
            '/metrics'
        ]
        
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in skip_patterns)
    
    def _collect_urls_alternative_method(self, target_url, domain):
        """Alternativ metod för att samla URL:er om primary method inte hittar mycket"""
        alternative_urls = []
        
        try:
            # Metod 1: Försök hämta från spider results om det finns
            spider_results = self.zap._direct_api_call('spider/view/results')
            if spider_results['success']:
                results = spider_results['data'].get('results', [])
                for result in results:
                    if isinstance(result, str) and domain in result:
                        alternative_urls.append({
                            'url': result,
                            'method': 'GET',
                            'request_body': '',
                            'status_code': 200,
                            'request_header': f'GET {result} HTTP/1.1\r\nHost: {domain}',
                            'cookies_used': '',
                            'category': self._categorize_url(result)
                        })
            
            # Metod 2: Generera vanliga URL:er för testing
            common_paths = [
                '/',
                '/admin',
                '/admin/',
                '/user',
                '/profile',
                '/dashboard',
                '/settings',
                '/api',
                '/login',
                '/logout'
            ]
            
            for path in common_paths:
                full_url = target_url.rstrip('/') + path
                alternative_urls.append({
                    'url': full_url,
                    'method': 'GET',
                    'request_body': '',
                    'status_code': 200,  # Antag framgång för testning
                    'request_header': f'GET {path} HTTP/1.1\r\nHost: {domain}',
                    'cookies_used': '',
                    'category': self._categorize_url(full_url)
                })
                
        except Exception as e:
            print(f"[AccessControl] Error in alternative URL collection: {str(e)}")
        
        return alternative_urls
    
    def _extract_domain_or_ip(self, url):
        """Extrahera domännamn eller IP från en URL"""
        try:
            parsed_url = urlparse(url)
            return parsed_url.netloc
        except Exception as e:
            print(f"[AccessControl] Error extracting domain from {url}: {str(e)}")
            return url
    
    def get_cookies_from_messages(self, target_url):
        """Förbättrad cookie-extraktion som läser direkt från request headers"""
        try:
            domain = self._extract_domain_or_ip(target_url)
            print(f"[AccessControl] Looking for cookies for domain: {domain}")
            
            # Hämta meddelanden
            messages_result = self.zap._direct_api_call('core/view/messages', {
                'baseurl': '',
                'start': '0',
                'count': '1000'
            })
            
            if not messages_result['success']:
                return ""
            
            messages = messages_result['data'].get('messages', [])
            print(f"[AccessControl] Checking {len(messages)} messages for cookies")
            
            # Leta igenom meddelanden efter cookies för vår domän
            for message in messages:
                request_header = message.get('requestHeader', '')
                
                # Kontrollera om detta meddelande är för vår måldomän
                if domain not in request_header:
                    continue
                
                # Extrahera cookies från request header
                cookies = self._extract_cookies(request_header)
                if cookies:
                    print(f"[AccessControl] Found cookies: {cookies[:50]}...")
                    return cookies
            
            print(f"[AccessControl] No cookies found for domain {domain}")
            return ""
            
        except Exception as e:
            print(f"[AccessControl] Error extracting cookies: {str(e)}")
            return ""
    
    # Resten av metoderna behålls som de var...
    def _extract_cookies(self, request_header):
        """Extrahera cookies från request header"""
        for line in request_header.split('\n'):
            line = line.strip()
            if line.lower().startswith('cookie:'):
                return line[7:].strip()
        return ""
    
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
        """Förenklad analys - fokuserar på access control-brott"""
        analysis = {
            'total_tested': len(test_results),
            'unauthorized_access_count': 0,
            'access_denied_count': 0,
            'redirect_count': 0,
            'other_count': 0,
            'by_finding': {},
            'unauthorized_urls': [],  # Lista över URLs med unauthorized access
            'summary': ''
        }
        
        for result in test_results:
            finding = result.get('finding', 'UNKNOWN')
            analysis['by_finding'][finding] = analysis['by_finding'].get(finding, 0) + 1
            
            # Räkna olika typer av resultat
            if finding == 'UNAUTHORIZED_ACCESS':
                analysis['unauthorized_access_count'] += 1
                analysis['unauthorized_urls'].append({
                    'url': result.get('url'),
                    'method': result.get('method'),
                    'status_code': result.get('status_code'),
                    'description': result.get('description')
                })
            elif finding == 'ACCESS_DENIED':
                analysis['access_denied_count'] += 1
            elif finding == 'REDIRECT_RESPONSE':
                analysis['redirect_count'] += 1
            else:
                analysis['other_count'] += 1
        
        # Skapa sammanfattning baserat på unauthorized access
        unauthorized_count = analysis['unauthorized_access_count']
        
        if unauthorized_count > 0:
            analysis['summary'] = f"⚠️  {unauthorized_count} obehöriga åtkomster upptäckta! Kräver manuell bedömning."
            analysis['risk_level'] = 'REQUIRES_REVIEW'
        elif analysis['redirect_count'] > 0:
            analysis['summary'] = f"ℹ️  {analysis['redirect_count']} omdirigeringar upptäckta. Kontrollera destinations."
            analysis['risk_level'] = 'MANUAL_REVIEW'
        else:
            analysis['summary'] = "✅ Inga obehöriga åtkomster upptäckta. Access control fungerar korrekt."
            analysis['risk_level'] = 'OK'
        
        return analysis

    def _determine_overall_result(self, analysis):
        """Avgör övergripande testresultat"""
        unauthorized_count = analysis.get('unauthorized_access_count', 0)
        
        if unauthorized_count > 0:
            return 'REQUIRES_REVIEW'  # Kräver manuell bedömning
        elif analysis.get('redirect_count', 0) > 0:
            return 'MANUAL_REVIEW'    # Kontrollera omdirigeringar
        else:
            return 'PASSED'           # Access control fungerar

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
    

    def list_collected_sessions(self):
        """Lista alla insamlade sessioner"""
        sessions = []
        
        try:
            for filename in os.listdir(self.sessions_dir):
                if filename.startswith('session_') and filename.endswith('.json'):
                    filepath = os.path.join(self.sessions_dir, filename)
                    
                    with open(filepath, 'r') as f:
                        session_data = json.load(f)
                    
                    # Hantera både gamla 'collection_time' och nya 'timestamp' fält
                    timestamp = session_data.get('timestamp') or session_data.get('collection_time', 0)
                    
                    # Om ingen timestamp finns, försök extrahera från filnamnet
                    if not timestamp:
                        try:
                            # Extrahera timestamp från filnamn: session_label_TIMESTAMP.json
                            import re
                            match = re.search(r'session_.*_(\d+)\.json$', filename)
                            if match:
                                timestamp = int(match.group(1))
                        except:
                            timestamp = 0
                    
                    # Kontrollera om sessionen har cookies
                    has_cookies = False
                    cookies = session_data.get('cookies', '')
                    if isinstance(cookies, str):
                        has_cookies = bool(cookies.strip())
                    elif isinstance(cookies, dict):
                        has_cookies = bool(cookies)
                    
                    sessions.append({
                        'filename': filename,
                        'session_label': session_data.get('session_label', 'Unknown'),
                        'target_url': session_data.get('target_url', ''),
                        'url_count': session_data.get('url_count', 0),
                        'timestamp': timestamp,  # Konsekvent använd 'timestamp'
                        'collection_time': timestamp,  # Bakåtkompatibilitet
                        'has_cookies': has_cookies,  # Lägg till has_cookies för JavaScript
                        'categories': self._get_url_categories(session_data.get('urls', [])),
                        'context_name': session_data.get('context_name', ''),
                        'scope_pattern': session_data.get('scope_pattern', '')
                    })
            
            # Sortera efter tid (nyast först)
            sessions.sort(key=lambda x: x['timestamp'], reverse=True)
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
            print(f"[AccessControl] Starting access control test")
            print(f"[AccessControl] Source session: {source_session_file}")
            print(f"[AccessControl] Test label: {test_label}")
            print(f"[AccessControl] Has cookies: {bool(test_cookies)}")
            
            # Ladda käll-sessionen
            source_result = self.get_session_urls(source_session_file)
            if not source_result['success']:
                raise Exception(f"Failed to load source session: {source_result['error']}")
            
            source_urls = source_result['session_data']['urls']
            
            # Filtrera URL:er om specifika URL:er valts
            if selected_urls:
                source_urls = [url for url in source_urls if url['url'] in selected_urls]
            
            print(f"[AccessControl] Testing {len(source_urls)} URLs")
            
            test_results = []
            
            for i, url_data in enumerate(source_urls):
                try:
                    url = url_data['url']
                    method = url_data['method']
                    request_body = url_data['request_body']
                    
                    if not url:  # Skippa tomma URL:er
                        continue
                        
                    print(f"[AccessControl] Testing {i+1}/{len(source_urls)}: {method} {url}")
                    
                    # Testa URL:en med nya credentials
                    result = self._test_single_url(url, method, request_body, test_cookies)
                    
                    # Analysera resultatet
                    analysis = self._analyze_access_result(url_data, result, test_label)
                    test_results.append(analysis)
                    
                    # Lägg till delay för att inte överbelasta servern
                    time.sleep(0.3)
                    
                except Exception as e:
                    print(f"[AccessControl] Error testing URL {url_data.get('url', 'unknown')}: {str(e)}")
                    test_results.append({
                        'url': url_data.get('url', 'unknown'),
                        'method': url_data.get('method', 'GET'),
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
            
            print(f"[AccessControl] Test completed. Found {len([r for r in test_results if r.get('risk_level') in ['HIGH', 'CRITICAL']])} high-risk findings")
            
            return {
                'success': True,
                'test_filename': test_filename,
                'total_tested': len(test_results),
                'analysis': analysis,
                'high_risk_findings': [r for r in test_results if r.get('risk_level') in ['HIGH', 'CRITICAL']]
            }
            
        except Exception as e:
            print(f"[AccessControl] Error in test_access_control: {str(e)}")
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
    

    def collect_session_data_by_timeframe(self, session_label, target_url, start_timestamp, stop_timestamp, start_message_count=0):
        """Samla URL:er och cookies från en specifik tidsperiod i ZAP"""
        try:
            print(f"[AccessControl] Collecting session data for timeframe: {start_timestamp} - {stop_timestamp}")
            
            domain = self._extract_domain_or_ip(target_url)
            if not domain:
                return {
                    'success': False,
                    'error': 'Kunde inte extrahera domän från target URL'
                }
            
            # Hämta alla meddelanden från ZAP
            all_messages_result = self.zap._direct_api_call('core/view/messages', {
                'baseurl': '',
                'start': str(start_message_count),  # Börja från baseline
                'count': '10000'  # Stort antal för att få alla nya meddelanden
            })
            
            if not all_messages_result['success']:
                return {
                    'success': False,
                    'error': 'Kunde inte hämta meddelanden från ZAP'
                }
            
            all_messages = all_messages_result['data'].get('messages', [])
            print(f"[AccessControl] Got {len(all_messages)} messages from ZAP")
            
            # Filtrera meddelanden baserat på tid och domän
            timeframe_messages = []
            for msg in all_messages:
                try:
                    # ZAP timestamp är i millisekunder
                    msg_timestamp = int(msg.get('timestamp', 0)) / 1000.0
                    msg_url = msg.get('requestHeader', '').split('\n')[0].split(' ')[1] if msg.get('requestHeader') else ''
                    
                    # Kontrollera om meddelandet är inom tidsramen och från rätt domän
                    if (start_timestamp <= msg_timestamp <= stop_timestamp and 
                        domain in msg_url):
                        timeframe_messages.append(msg)
                except (ValueError, IndexError, AttributeError) as e:
                    continue
            
            print(f"[AccessControl] Found {len(timeframe_messages)} messages in timeframe for domain {domain}")
            
            # Bearbeta meddelanden för att extrahera URLs och cookies
            urls_data = []
            session_cookies = set()
            
            for msg in timeframe_messages:
                try:
                    request_header = msg.get('requestHeader', '')
                    response_header = msg.get('responseHeader', '')
                    request_body = msg.get('requestBody', '')
                    response_body = msg.get('responseBody', '')
                    
                    # Extrahera URL från request header
                    url = self._extract_url_from_request_header(request_header)
                    if not url or self._should_skip_url(url):
                        continue
                    
                    # Extrahera HTTP-metod
                    method = self._extract_method_from_request_header(request_header)
                    
                    # Extrahera status kod från response
                    status_code = self._extract_status_code_from_response_header(response_header)
                    
                    # Extrahera cookies från request headers
                    cookies_from_request = self._extract_cookies_from_request_header(request_header)
                    if cookies_from_request:
                        session_cookies.add(cookies_from_request)
                    
                    # Extrahera Set-Cookie från response headers för framtida användning
                    set_cookies = self._extract_set_cookies_from_response_header(response_header)
                    if set_cookies:
                        session_cookies.add(set_cookies)
                    
                    # Lägg till URL data
                    url_data = {
                        'url': url,
                        'method': method,
                        'request_body': request_body,
                        'status_code': status_code,
                        'request_header': request_header,
                        'response_header': response_header,
                        'cookies_used': cookies_from_request,
                        'category': self._categorize_url(url),
                        'timestamp': msg.get('timestamp', 0)
                    }
                    urls_data.append(url_data)
                    
                except Exception as e:
                    print(f"[AccessControl] Error processing message: {e}")
                    continue
            
            # Ta bort dubbletter baserat på URL och metod
            unique_urls = {}
            for url_data in urls_data:
                key = f"{url_data['method']}:{url_data['url']}"
                if key not in unique_urls:
                    unique_urls[key] = url_data
            
            final_urls = list(unique_urls.values())
            
            # Kombinera alla cookies till en sträng
            combined_cookies = '; '.join(session_cookies) if session_cookies else ''
            
            # Spara session-data
            session_filename = f"session_{session_label}_{int(stop_timestamp)}.json"
            session_file_path = os.path.join(self.sessions_dir, session_filename)
            
            session_data = {
                'session_label': session_label,
                'target_url': target_url,
                'timestamp': stop_timestamp,
                'start_timestamp': start_timestamp,
                'duration': stop_timestamp - start_timestamp,
                'url_count': len(final_urls),
                'urls': final_urls,
                'cookies': combined_cookies,
                'has_cookies': bool(combined_cookies.strip()),
                'categories': self._get_url_categories(final_urls),
                'collection_method': 'timeframe_recording'
            }
            
            with open(session_file_path, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)
            
            print(f"[AccessControl] Saved session to {session_file_path}")
            
            return {
                'success': True,
                'filename': session_filename,
                'session_label': session_label,
                'url_count': len(final_urls),
                'cookies_found': bool(combined_cookies.strip()),
                'categories': session_data['categories'],
                'duration': session_data['duration']
            }
            
        except Exception as e:
            print(f"[AccessControl] Error in collect_session_data_by_timeframe: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def test_access_control_with_separate_sessions(self, urls_session_file, credentials_session_file, test_description=''):
        """Testa access control med URL:er från en session och credentials från en annan"""
        try:
            print(f"[AccessControl] Starting test with URLs from {urls_session_file} and credentials from {credentials_session_file}")
            
            # Ladda URL-session
            urls_session_path = os.path.join(self.sessions_dir, urls_session_file)
            if not os.path.exists(urls_session_path):
                return {
                    'success': False,
                    'error': f'URL-session filen hittades inte: {urls_session_file}'
                }
            
            with open(urls_session_path, 'r', encoding='utf-8') as f:
                urls_session_data = json.load(f)
            
            # Ladda credentials-session
            credentials_session_path = os.path.join(self.sessions_dir, credentials_session_file)
            if not os.path.exists(credentials_session_path):
                return {
                    'success': False,
                    'error': f'Credentials-session filen hittades inte: {credentials_session_file}'
                }
            
            with open(credentials_session_path, 'r', encoding='utf-8') as f:
                credentials_session_data = json.load(f)
            
            # Hämta data
            urls_to_test = urls_session_data.get('urls', [])
            test_cookies = credentials_session_data.get('cookies', '')
            
            if not urls_to_test:
                return {
                    'success': False,
                    'error': 'Inga URL:er att testa från den valda sessionen'
                }
            
            print(f"[AccessControl] Testing {len(urls_to_test)} URLs with cookies from {credentials_session_data.get('session_label', 'unknown')}")
            
            # Genomför access control tester
            test_results = []
            test_id = f"test_{int(time.time())}"
            
            for url_data in urls_to_test:
                url = url_data.get('url', '')
                original_method = url_data.get('method', 'GET')
                original_cookies = url_data.get('cookies_used', '')
                
                if self._should_skip_url(url):
                    continue
                
                # Testa URL med de nya credentials
                test_result = self._perform_access_control_test(
                    url=url,
                    method=original_method,
                    test_cookies=test_cookies,
                    original_cookies=original_cookies,
                    category=url_data.get('category', 'other')
                )
                
                if test_result:
                    test_results.append(test_result)
            
            # Analysera resultat
            analysis = self._analyze_test_results(test_results)
            
            # Spara testresultat
            test_report = {
                'test_id': test_id,
                'test_description': test_description,
                'timestamp': time.time(),
                'urls_session': urls_session_data.get('session_label', urls_session_file),
                'credentials_session': credentials_session_data.get('session_label', credentials_session_file),
                'urls_session_file': urls_session_file,
                'credentials_session_file': credentials_session_file,
                'total_tests': len(test_results),
                'test_results': test_results,
                'analysis': analysis,
                'risk_level': self._determine_overall_risk(analysis),
                'potential_issues': analysis.get('by_risk_level', {}).get('HIGH', 0) + analysis.get('by_risk_level', {}).get('CRITICAL', 0)
            }
            
            # Spara rapport
            report_filename = f"test_report_{test_id}.json"
            report_path = os.path.join(self.tests_dir, report_filename)
            
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(test_report, f, indent=2, ensure_ascii=False)
            
            print(f"[AccessControl] Test completed. {len(test_results)} URLs tested, saved to {report_filename}")
            
            return {
                'success': True,
                'test_id': test_id,
                'test_count': len(test_results),
                'report_filename': report_filename,
                'risk_level': test_report['risk_level'],
                'potential_issues': test_report['potential_issues']
            }
            
        except Exception as e:
            print(f"[AccessControl] Error in test_access_control_with_separate_sessions: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_test_results(self):
        """Hämta alla sparade testresultat"""
        try:
            results = []
            
            # Läs alla testrapporter från tests_dir
            if os.path.exists(self.tests_dir):
                for filename in os.listdir(self.tests_dir):
                    if filename.startswith('test_report_') and filename.endswith('.json'):
                        file_path = os.path.join(self.tests_dir, filename)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                test_data = json.load(f)
                            
                            # Skapa sammanfattning för visning - INKLUDERA FULLSTÄNDIG ANALYSIS!
                            summary = {
                                'test_id': test_data.get('test_id', 'unknown'),
                                'test_description': test_data.get('test_description', ''),
                                'timestamp': test_data.get('timestamp', 0),
                                'urls_session': test_data.get('urls_session', 'unknown'),
                                'credentials_session': test_data.get('credentials_session', 'unknown'),
                                'total_tests': test_data.get('total_tests', 0),
                                'risk_level': test_data.get('risk_level', 'UNKNOWN'),
                                'analysis': test_data.get('analysis', {}),  # FULLSTÄNDIG ANALYSIS DATA
                                'filename': filename,
                                
                                # Beräkna problem baserat på analysis.by_finding (som rapporten)
                                'unauthorized_count': 0,
                                'redirect_count': 0,
                                'access_denied_count': 0,
                                'potential_issues': 0  # Behåll för bakåtkompatibilitet
                            }
                            
                            # Hämta counts från analysis.by_finding om tillgängligt
                            if test_data.get('analysis') and test_data['analysis'].get('by_finding'):
                                by_finding = test_data['analysis']['by_finding']
                                summary['unauthorized_count'] = by_finding.get('UNAUTHORIZED_ACCESS', 0)
                                summary['redirect_count'] = by_finding.get('REDIRECT_RESPONSE', 0)
                                summary['access_denied_count'] = by_finding.get('ACCESS_DENIED', 0)
                                
                                # Sätt potential_issues = unauthorized_count för konsistens
                                summary['potential_issues'] = summary['unauthorized_count']
                            else:
                                # Fallback till gamla potential_issues om analysis saknas
                                summary['potential_issues'] = test_data.get('potential_issues', 0)
                            
                            # Extrahera specifika problem för visning
                            summary['issues'] = []
                            test_results = test_data.get('test_results', [])
                            for result in test_results:
                                if result.get('finding') == 'UNAUTHORIZED_ACCESS':
                                    summary['issues'].append({
                                        'url': result.get('url', ''),
                                        'description': result.get('description', ''),
                                        'severity': 'UNAUTHORIZED_ACCESS',
                                        'finding': result.get('finding', ''),
                                        'status_code': result.get('status_code', '')
                                    })
                            
                            results.append(summary)
                            
                        except Exception as e:
                            print(f"[AccessControl] Error reading test report {filename}: {e}")
                            continue
            
            # Sortera efter timestamp (nyast först)
            results.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
            
            return results
            
        except Exception as e:
            print(f"[AccessControl] Error getting test results: {e}")
            return []
        
    def _perform_access_control_test(self, url, method, test_cookies, original_cookies, category='other'):
        """Genomför en enskild access control test"""
        try:
            # Gör HTTP-anrop med test-cookies
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            if test_cookies:
                headers['Cookie'] = test_cookies
            
            # Genomför request (allow_redirects=False för att fånga 302)
            if method.upper() == 'POST':
                response = requests.post(url, headers=headers, timeout=10, allow_redirects=False, verify=False)
            else:
                response = requests.get(url, headers=headers, timeout=10, allow_redirects=False, verify=False)
            
            # Analysera svar
            status_code = response.status_code
            response_length = len(response.content)
            
            # Extrahera redirect-destination för 302/301 svar
            redirect_location = None
            if status_code in [301, 302, 303, 307, 308]:
                redirect_location = response.headers.get('Location', '')
                print(f"[AccessControl] {status_code} redirect from {url} to {redirect_location}")
            
            # Avgör risk-nivå baserat på status kod och innehåll
            risk_level, finding, description = self._analyze_access_control_response(
                url, status_code, response_length, test_cookies, original_cookies, category, redirect_location
            )
            
            return {
                'url': url,
                'method': method,
                'test_cookies': test_cookies[:100] + '...' if len(test_cookies) > 100 else test_cookies,
                'original_cookies': original_cookies[:100] + '...' if len(original_cookies) > 100 else original_cookies,
                'status_code': status_code,
                'response_length': response_length,
                'redirect_location': redirect_location,  # Ny field!
                'risk_level': risk_level,
                'finding': finding,
                'description': description,
                'category': category,
                'timestamp': time.time()
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'method': method,
                'test_cookies': test_cookies[:100] + '...' if len(test_cookies) > 100 else test_cookies,
                'status_code': 0,
                'response_length': 0,
                'redirect_location': None,
                'risk_level': 'ERROR',
                'finding': 'REQUEST_FAILED',
                'description': f'Request misslyckades: {str(e)}',
                'category': category,
                'timestamp': time.time()
            }


    def _analyze_access_control_response(self, url, status_code, response_length, test_cookies, original_cookies, category=None, redirect_location=None):
        """Förenklad access control-analys - fokuserar på unauthorized access"""
        
        # Om samma cookies används, ingen access control-överträdelse
        if test_cookies == original_cookies:
            return 'INFO', 'SAME_CREDENTIALS', 'Samma credentials används - förväntat resultat'
        
        # Analysera baserat på status kod
        if status_code in [200, 201, 202, 204]:
            # Framgångsrik åtkomst = potentiellt problem
            return 'UNAUTHORIZED_ACCESS', 'UNAUTHORIZED_ACCESS', f'Obehörig åtkomst upptäckt: {url}'
            
        elif status_code in [401, 403]:
            # Korrekt beteende - åtkomst nekad
            return 'ACCESS_DENIED', 'ACCESS_DENIED', f'Åtkomst korrekt nekad (HTTP {status_code}): {url}'
        
        elif status_code in [302, 301]:
            # Omdirigering - inkludera destination om tillgänglig
            description = f'Omdirigering (HTTP {status_code}): {url}'
            if redirect_location:
                description += f' → {redirect_location}'
                
                # Analysera om redirecten är till login (bra) eller annan sida (behöver kontroll)
                if any(keyword in redirect_location.lower() for keyword in ['login', 'signin', 'auth']):
                    description += ' (troligen till login - bra säkerhet)'
                else:
                    description += ' (kontrollera destination)'
            else:
                description += ' (kontrollera destination)'
                
            return 'REDIRECT', 'REDIRECT_RESPONSE', description
        
        elif status_code in [404, 405]:
            # Inte hittat eller metod ej tillåten
            return 'NOT_FOUND', 'NOT_FOUND', f'Resurs inte hittad eller metod ej tillåten (HTTP {status_code}): {url}'
        
        elif status_code >= 500:
            # Serverfel
            return 'SERVER_ERROR', 'SERVER_ERROR', f'Serverfel (HTTP {status_code}): {url}'
        
        else:
            # Andra status koder
            return 'UNEXPECTED', 'UNEXPECTED_RESPONSE', f'Oväntat svar (HTTP {status_code}): {url}'

    def _determine_overall_risk(self, analysis):
        """Avgör övergripande testresultat"""
        unauthorized_count = analysis.get('unauthorized_access_count', 0)
        
        if unauthorized_count > 0:
            return 'REQUIRES_REVIEW'  # Kräver manuell bedömning
        elif analysis.get('redirect_count', 0) > 0:
            return 'MANUAL_REVIEW'    # Kontrollera omdirigeringar
        else:
            return 'PASSED'           # Access control fungerar

    # Hjälpmetoder för att extrahera data från HTTP headers

    def _extract_url_from_request_header(self, request_header):
        """Extrahera URL från request header"""
        try:
            lines = request_header.split('\n')
            if lines:
                first_line = lines[0].strip()
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    return parts[1]
        except Exception:
            pass
        return None

    def _extract_method_from_request_header(self, request_header):
        """Extrahera HTTP-metod från request header"""
        try:
            lines = request_header.split('\n')
            if lines:
                first_line = lines[0].strip()
                parts = first_line.split(' ')
                if parts:
                    return parts[0].upper()
        except Exception:
            pass
        return 'GET'

    def _extract_status_code_from_response_header(self, response_header):
        """Extrahera status kod från response header"""
        try:
            lines = response_header.split('\n')
            if lines:
                first_line = lines[0].strip()
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    return int(parts[1])
        except Exception:
            pass
        return 200

    def _extract_cookies_from_request_header(self, request_header):
        """Extrahera cookies från request header"""
        try:
            lines = request_header.split('\n')
            for line in lines:
                if line.lower().startswith('cookie:'):
                    return line.split(':', 1)[1].strip()
        except Exception:
            pass
        return ''

    def _extract_set_cookies_from_response_header(self, response_header):
        """Extrahera Set-Cookie från response header"""
        try:
            lines = response_header.split('\n')
            cookies = []
            for line in lines:
                if line.lower().startswith('set-cookie:'):
                    cookie_value = line.split(':', 1)[1].strip()
                    # Ta bara cookie-namnet och värdet, inte attributes
                    if '=' in cookie_value:
                        cookie_part = cookie_value.split(';')[0]
                        cookies.append(cookie_part)
            return '; '.join(cookies) if cookies else ''
        except Exception:
            pass
        return ''