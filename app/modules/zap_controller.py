import time
import logging
import threading
from urllib.parse import urlparse
import requests
import re
from functools import wraps


# Konfigurera loggning
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("zap_controller.log"),
        logging.StreamHandler()
    ]
)

# Cache för cookies
cookie_cache = {}
cookie_cache_lock = threading.Lock()

def retry_on_exception(max_retries=3, delay=1):
    """Decorator för att försöka igen vid fel"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    logger = logging.getLogger('ZAPController')
                    logger.warning(f"Retry {retries}/{max_retries} after error: {str(e)}")
                    if retries == max_retries:
                        raise
                    time.sleep(delay)
        return wrapper
    return decorator

class ZAPController:
    def __init__(self, api_key, host='localhost', port=8080):
        import requests
        self.logger = logging.getLogger('ZAPController')
        self.api_key = api_key
        self.host = host
        self.port = port
        self.proxies = {
            'http': f'http://{host}:{port}',
            'https': f'http://{host}:{port}'
        }
        self.session = requests.Session() 
        try:
            from zapv2 import ZAPv2
            self.zap = ZAPv2(apikey=api_key, proxies=self.proxies)
            version = self.zap.core.version
            self.logger.info(f"Successfully connected to ZAP API at {host}:{port} (version {version})")
            self.available = True
        except Exception as e:
            self.logger.error(f"Failed to connect to ZAP API: {str(e)}")
            self.available = False

        import requests
        self.session = requests.Session()  # Återanvändbar session för HTTP-anrop
        
        # Kontrollera att ZAP API är tillgängligt
        try:
            if self.is_available():
                self.logger.info(f"Successfully connected to ZAP API at {host}:{port}")
            else:
                self.logger.error(f"Failed to connect to ZAP API at {host}:{port}")
        except Exception as e:
            self.logger.error(f"Error initializing ZAP controller: {str(e)}")
            self.available = False


    def set_mode(self, mode):
        """Set ZAP mode (safe, protect, standard, attack)"""
        try:
            # Validate the mode
            if mode not in ['safe', 'protect', 'standard', 'attack']:
                self.logger.error(f"Invalid ZAP mode: {mode}")
                return False
                
            # Direct API call to set the mode
            result = self._direct_api_call('core/action/setMode', {'mode': mode})
            
            if result['success']:
                self.logger.info(f"ZAP mode set to: {mode}")
                return True
            else:
                self.logger.error(f"Failed to set ZAP mode: {result.get('error', 'Unknown error')}")
                return False
        except Exception as e:
            self.logger.error(f"Error setting ZAP mode: {str(e)}")
            return False

    def get_mode(self):
        """Get current ZAP mode"""
        try:
            # Direct API call to get the mode
            result = self._direct_api_call('core/view/mode')
            
            if result['success']:
                mode = result['data'].get('mode', 'unknown')
                self.logger.info(f"Current ZAP mode: {mode}")
                return mode
            else:
                self.logger.error(f"Failed to get ZAP mode: {result.get('error', 'Unknown error')}")
                return 'unknown'
        except Exception as e:
            self.logger.error(f"Error getting ZAP mode: {str(e)}")
            return 'unknown'


    def _direct_api_call(self, endpoint, params=None, timeout=10):
        """Utför ett direkt HTTP-anrop till ZAP API"""
        try:
            import requests
            
            if params is None:
                params = {}
                
            # Lägg alltid till API-nyckeln
            params['apikey'] = self.api_key
            
            # Konstruera fullständig URL
            url = f"http://{self.host}:{self.port}/JSON/{endpoint}/"
            
            self.logger.debug(f"Making direct API call to: {url}")
            
            # Gör HTTP-anropet
            response = requests.get(url, params=params, timeout=timeout)
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'data': response.json()
                }
            else:
                self.logger.warning(f"API call to {endpoint} failed with status {response.status_code}")
                return {
                    'success': False,
                    'status_code': response.status_code,
                    'response': response.text
                }
        except Exception as e:
            self.logger.error(f"Error in direct API call to {endpoint}: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def is_available(self):
        """Kontrollera om ZAP är tillgänglig endast med direkta HTTP-anrop"""
        try:
            import requests
            
            api_url = f"http://{self.host}:{self.port}/JSON/core/view/version/"
            self.logger.info(f"Trying direct HTTP call to: {api_url}")
            
            response = requests.get(
                api_url,
                params={'apikey': self.api_key},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                version = data.get('version', 'unknown')
                self.logger.info(f"ZAP is available via direct HTTP, version: {version}")
                
                # Sätt success-flaggan
                self.available = True
                return True
                
            self.logger.warning(f"ZAP API check failed, status code: {response.status_code}")
            self.available = False
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking ZAP availability: {str(e)}")
            self.available = False
            return False
    




    @retry_on_exception(max_retries=2)
    def get_cookies(self, target_url):
        """Hämta cookies för en specifik URL med endast direkta HTTP-anrop"""
        if not target_url:
            self.logger.warning("No target URL provided")
            return ""
        
        # Kontrollera tillgänglighet först
        if not self.is_available():
            self.logger.warning("ZAP is not available")
            return ""
        
        self.logger.info(f"Looking for cookies for URL: {target_url}")
        
        # Extrahera domän från URL:en
        domain = self._extract_domain_or_ip(target_url)
        self.logger.info(f"Extracted domain: {domain}")
        
        # Steg 1: Hämta alla sites
        
        sites_result = self._direct_api_call('core/view/sites')
        if not sites_result['success']:
            self.logger.warning("Failed to get sites from ZAP")
            return ""
        
        sites = sites_result['data'].get('sites', [])
        self.logger.info(f"Found {len(sites)} sites in ZAP")
        
        # Hitta matchande sites (webbplatser som innehåller vår domän)
        matching_sites = []
        for site in sites:
            site_domain = self._extract_domain_or_ip(site)
            if domain == site_domain:
                matching_sites.append(site)
                self.logger.info(f"Found exact domain match: {site}")
            elif domain in site:
                matching_sites.append(site)
                self.logger.info(f"Found partial domain match: {site}")
        
        if not matching_sites:
            self.logger.warning(f"No matching sites found for domain {domain}")
            return ""
        
        # Steg 2: För varje matchande site, hämta meddelanden
        for site in matching_sites:
            self.logger.info(f"Checking messages for site: {site}")
            params={"count":100}
            messages_result = self._direct_api_call('core/view/messages', {'baseurl': site}, params)
            if not messages_result['success']:
                self.logger.warning(f"Failed to get messages for site {site}")
                continue
            
            messages = messages_result['data'].get('messages', [])
            self.logger.info(f"Found {len(messages)} messages for site {site}")
            
            # Leta efter cookies i meddelandena
            for message in messages:
                req_header = message.get('requestHeader', '')
                if 'Cookie:' in req_header:
                    lines = req_header.split('\n')
                    for line in lines:
                        if line.strip().startswith('Cookie:'):
                            cookie_str = line.replace('Cookie:', '').strip()
                            self.logger.info(f"Found cookies in message: {cookie_str[:30]}...")
                            return cookie_str
            
            # Steg 3: Försök med HTTP Sessions API
            self.logger.info(f"No cookies found in messages, trying HTTP Sessions for site: {site}")
            
            sessions_result = self._direct_api_call('httpSessions/view/sessions', {'site': site})
            if not sessions_result['success']:
                self.logger.warning(f"Failed to get HTTP sessions for site {site}")
                continue
            
            sessions = sessions_result['data'].get('sessions', [])
            self.logger.info(f"Found {len(sessions)} HTTP sessions for site {site}")
            
            # Leta efter aktiva sessioner med tokens
            for session in sessions:
                if session.get('active') and 'tokens' in session:
                    tokens = session.get('tokens', {})
                    cookie_parts = []
                    
                    for name, value in tokens.items():
                        cookie_parts.append(f"{name}={value}")
                    
                    if cookie_parts:
                        cookie_str = '; '.join(cookie_parts)
                        self.logger.info(f"Found cookies in HTTP session: {cookie_str[:30]}...")
                        return cookie_str
        
        self.logger.warning(f"No cookies found for {target_url}")
        return ""


    def _get_cookies_from_httpsessions(self, target_url, domain):
        """Hämta cookies från HTTP Sessions"""
        try:
            # Hitta matchande site
            sites = self.zap.core.sites
            matching_sites = [s for s in sites if domain in s]
            
            if not matching_sites:
                return ""
                
            for site in matching_sites:
                try:
                    # Försök hämta sessioner
                    sessions_response = self.zap.httpsessions.sessions(site)
                    
                    # Hantera olika svarsformat
                    if isinstance(sessions_response, list):
                        for session in sessions_response:
                            if session.get('active') and 'tokens' in session:
                                cookie_parts = []
                                for name, value in session['tokens'].items():
                                    cookie_parts.append(f"{name}={value}")
                                if cookie_parts:
                                    return '; '.join(cookie_parts)
                    elif isinstance(sessions_response, dict) and 'sessions' in sessions_response:
                        for session in sessions_response['sessions']:
                            if session.get('active') and 'tokens' in session:
                                cookie_parts = []
                                for name, value in session['tokens'].items():
                                    cookie_parts.append(f"{name}={value}")
                                if cookie_parts:
                                    return '; '.join(cookie_parts)
                except Exception as e:
                    self.logger.warning(f"Error getting sessions for {site}: {str(e)}")
                    continue
        except Exception as e:
            self.logger.warning(f"Error in _get_cookies_from_httpsessions: {str(e)}")
            
        return ""

    def _get_cookies_from_messages(self, target_url, domain):
        """Hämta cookies från meddelanden"""
        try:
            # Hitta matchande site
            sites = self.zap.core.sites
            matching_sites = [s for s in sites if domain in s]
            
            if not matching_sites:
                return ""
                
            for site in matching_sites:
                try:
                    # Hämta meddelanden
                    messages_response = self.zap.core.messages(baseurl=site)
                    
                    # Hantera olika svarsformat
                    if isinstance(messages_response, list):
                        messages = messages_response
                    elif isinstance(messages_response, dict) and 'messages' in messages_response:
                        messages = messages_response['messages']
                    else:
                        continue
                        
                    # Sök efter cookies i headers
                    for msg in messages:
                        if not isinstance(msg, dict):
                            continue
                            
                        req_header = msg.get('requestHeader', '')
                        if 'Cookie:' in req_header:
                            for line in req_header.split('\r\n'):
                                if line.strip().startswith('Cookie:'):
                                    cookie_str = line.replace('Cookie:', '').strip()
                                    if cookie_str:
                                        return cookie_str
                except Exception as e:
                    self.logger.warning(f"Error getting messages for {site}: {str(e)}")
                    continue
        except Exception as e:
            self.logger.warning(f"Error in _get_cookies_from_messages: {str(e)}")
            
        return ""

    def _get_cookies_from_direct_api(self, target_url, domain):
        """Hämta cookies direkt från ZAP API"""
        try:
            # Anropa API:et direkt med den återanvändbara sessionen
            api_url = f"http://{self.host}:{self.port}/JSON/core/view/allSites/"
            response = self.session.get(api_url, params={'apikey': self.api_key}, timeout=5)
            
            if response.status_code != 200:
                self.logger.warning(f"API call failed with status {response.status_code}")
                return ""
                
            sites_data = response.json()
            
            if 'sites' not in sites_data:
                return ""
                
            # Hitta matchande site
            target_site = None
            for site in sites_data['sites']:
                if domain in site:
                    target_site = site
                    break
                    
            if not target_site:
                return ""
                
            # Hämta meddelanden för den här platsen
            api_url = f"http://{self.host}:{self.port}/JSON/core/view/messages/"
            response = self.session.get(
                api_url, 
                params={'baseurl': target_site, 'apikey': self.api_key},
                timeout=5
            )
            
            if response.status_code != 200:
                self.logger.warning(f"Messages API call failed with status {response.status_code}")
                return ""
                
            messages_data = response.json()
            
            if 'messages' not in messages_data:
                return ""
                
            # Sök efter cookies i headers
            for message in messages_data['messages']:
                req_header = message.get('requestHeader', '')
                if 'Cookie:' in req_header:
                    for line in req_header.split('\n'):
                        if line.strip().startswith('Cookie:'):
                            return line.replace('Cookie:', '').strip()
        except Exception as e:
            self.logger.warning(f"Error in _get_cookies_from_direct_api: {str(e)}")
            
        return ""

    def _get_cookies_from_history(self, target_url, domain):
        """Hämta cookies från historik-items"""
        try:
            # Anropa History API om tillgängligt
            if hasattr(self.zap, 'history'):
                try:
                    history_items = self.zap.history.view_history()
                    
                    # Hantera olika format
                    if isinstance(history_items, list):
                        items = history_items
                    elif isinstance(history_items, dict) and 'historyItems' in history_items:
                        items = history_items.get('historyItems', [])
                    else:
                        return ""
                    
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                            
                        url = item.get('url', '')
                        if domain not in url:
                            continue
                            
                        if 'requestHeader' in item:
                            req_header = item['requestHeader']
                            if 'Cookie:' in req_header:
                                for line in req_header.split('\n'):
                                    if line.strip().startswith('Cookie:'):
                                        return line.replace('Cookie:', '').strip()
                except Exception as e:
                    self.logger.warning(f"Error in history view: {str(e)}")
                    
            # Alternativ strategi om history API inte finns
            api_url = f"http://{self.host}:{self.port}/JSON/search/view/urlsByUrlRegex/"
            response = self.session.get(
                api_url, 
                params={'regex': domain, 'apikey': self.api_key},
                timeout=5
            )
            
            if response.status_code == 200:
                urls_data = response.json()
                if 'urlsByUrlRegex' in urls_data and urls_data['urlsByUrlRegex']:
                    # För varje matchande URL, försök hitta cookies
                    for url in urls_data['urlsByUrlRegex']:
                        api_url = f"http://{self.host}:{self.port}/JSON/core/view/messages/"
                        response = self.session.get(
                            api_url, 
                            params={'url': url, 'apikey': self.api_key},
                            timeout=5
                        )
                        
                        if response.status_code == 200:
                            messages_data = response.json()
                            if 'messages' in messages_data:
                                for message in messages_data['messages']:
                                    req_header = message.get('requestHeader', '')
                                    if 'Cookie:' in req_header:
                                        for line in req_header.split('\n'):
                                            if line.strip().startswith('Cookie:'):
                                                return line.replace('Cookie:', '').strip()
        except Exception as e:
            self.logger.warning(f"Error in _get_cookies_from_history: {str(e)}")
            
        return ""



    def start_spider(self, target_url, session_cookies=None):
        """Starta ZAP spider mot målwebbplatsen via direkt API-anrop med stöd för cookies"""
        try:
            print(f'Spidering target: {target_url}')
            
            # Om vi har cookies, behöver vi skapa en kontext
            context_id = None
            if session_cookies:
                context_id = self._create_context_with_session(target_url, session_cookies)
                print(f"Created context with ID: {context_id} for Spider")
            
            # Skapa URL för API-anrop
            api_url = f"http://{self.host}:{self.port}/JSON/spider/action/scan/"
            params = {
                'url': target_url,
                'apikey': self.api_key
            }
            
            # Lägg till kontext-ID om vi har skapat en kontext
            if context_id:
                params['contextId'] = context_id
            
            # Gör API-anrop via HTTP
            response = self.session.get(api_url, params=params)
            if response.status_code != 200:
                raise Exception(f"API call failed with status {response.status_code}: {response.text}")
            
            data = response.json()
            scan_id = data.get('scan')
            return scan_id
        except Exception as e:
            print(f'Error starting spider scan: {str(e)}')
            raise e
        
    def _cleanup_completed_scans(self):
        """Ta bort avslutade skanningar från active_scans"""
        completed = []
        for scan_id, scan_info in self.active_scans.items():
            if scan_info['type'] == 'spider':
                status = self.zap.spider.status(scan_id)
                if status == "100":  # Skanning klar
                    completed.append(scan_id)
            elif scan_info['type'] == 'ascan':
                status = self.zap.ascan.status(scan_id)
                if status == "100":  # Skanning klar
                    completed.append(scan_id)
                    
        for scan_id in completed:
            del self.active_scans[scan_id]


    def is_available(self):
        """Kontrollera om ZAP är tillgänglig med fallback till direkta HTTP-anrop"""
        # Försök med ZAPv2-biblioteket först
        try:
            if hasattr(self, 'zap') and self.zap:
                version = self.zap.core.version
                self.logger.info(f"ZAP is available via ZAPv2 library, version: {version}")
                self.available = True
                return True
        except Exception as zap_error:
            self.logger.warning(f"ZAPv2 library failed: {str(zap_error)}")
            
        # Om ZAPv2 misslyckas, försök med direkt HTTP-anrop
        try:
            import requests
            
            api_url = f"http://{self.host}:{self.port}/JSON/core/view/version/"
            self.logger.info(f"Trying direct HTTP call to: {api_url}")
            
            response = requests.get(
                api_url,
                params={'apikey': self.api_key},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                version = data.get('version', 'unknown')
                self.logger.info(f"ZAP is available via direct HTTP, version: {version}")
                
                # Sätt success-flaggan
                self.available = True
                return True
        except Exception as http_error:
            self.logger.error(f"Direct HTTP call also failed: {str(http_error)}")
        
        # Om båda metoderna misslyckas
        self.available = False
        return False
    

 
    
    def _create_context_with_session(self, target_url, session_cookies):
        """Create a ZAP context with session cookies"""
        try:
            # Extract domain from URL properly
            from urllib.parse import urlparse
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            
            # Create a unique context name
            context_name = f"auth-context-{int(time.time())}"
            
            print(f"Creating context for domain: {domain}, URL: {target_url}")
            
            # Create context
            create_context_result = self._direct_api_call('context/action/newContext', 
                                                        {'contextName': context_name})
            
            if not create_context_result['success']:
                print(f"Failed to create context: {create_context_result.get('response', 'Unknown error')}")
                return '1'  # Return default context if we can't create a new one
            
            # Get context ID
            context_result = self._direct_api_call('context/view/context', 
                                                {'contextName': context_name})
            
            if not context_result['success']:
                print(f"Failed to get context ID: {context_result.get('response', 'Unknown error')}")
                return '1'
                
            context_data = context_result['data'].get('context', {})
            context_id = context_data.get('id', '1')
            
            print(f"Successfully created context with ID: {context_id}")
            
            # CRITICAL FIX: Use the precise parameter format required by ZAP API
            include_pattern = f".*{re.escape(domain)}.*"
            print(f"Including URL in context with regex: {include_pattern}")
            
            # Include the target domain in the context - NOTICE THE 'contextName' parameter!
            include_result = self._direct_api_call('context/action/includeInContext', {
                'contextName': context_name,  # Use name instead of ID
                'regex': include_pattern
            })
            
            if not include_result['success']:
                print(f"Failed to include domain in context: {include_result.get('response', 'Unknown error')}")
                # Even if inclusion fails, we can try to continue with the created context
            else:
                print(f"Successfully included domain {domain} in context {context_id}")
                
            # Verify that inclusion worked by checking context details
            verify_result = self._direct_api_call('context/view/context', {'contextId': context_id})
            if verify_result['success']:
                context_details = verify_result['data'].get('context', {})
                include_regexs = context_details.get('includeRegexs', '[]')
                print(f"Context inclusion verification - includeRegexs: {include_regexs}")
            
            # Parse cookies
            cookies_dict = {}
            if isinstance(session_cookies, str):
                for cookie in session_cookies.split(';'):
                    if cookie.strip() and '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookies_dict[name.strip()] = value.strip()
            
            # If we have cookies, add them to the session
            if cookies_dict:
                try:
                    # Create a session name
                    session_name = f"auth-session-{int(time.time())}"
                    
                    # For each cookie, add it to the session
                    for name, value in cookies_dict.items():
                        # Add token to session
                        add_token_result = self._direct_api_call('httpSessions/action/addSessionToken', {
                            'site': domain,  # Use domain instead of full URL
                            'sessionToken': name
                        })
                        
                        if not add_token_result['success']:
                            print(f"Failed to add session token {name}: {add_token_result.get('response', 'Unknown error')}")
                            continue  # Continue with next token
                        
                        # Set token value
                        set_token_result = self._direct_api_call('httpSessions/action/setSessionTokenValue', {
                            'site': domain,  # Use domain instead of full URL
                            'session': session_name,
                            'sessionToken': name,
                            'tokenValue': value
                        })
                        
                        if not set_token_result['success']:
                            print(f"Failed to set token value for {name}: {set_token_result.get('response', 'Unknown error')}")
                except Exception as e:
                    print(f"Error setting up session tokens: {str(e)}")
            
            return context_id
        except Exception as e:
            print(f"Error creating context with session: {str(e)}")
            return '1'  # Return default context on error



    def reconnect_zap(self):
        try:
            print("Attempting to reconnect to ZAP...")
            # Starta om ZAP-containern via Docker API eller kommandot
            import subprocess
            subprocess.run(['docker', 'restart', 'zap'], check=True)
            
            # Vänta tills ZAP startar om
            import time
            time.sleep(20)  # Vänta 20 sekunder för att ZAP ska starta om
            
            # Återanslut ZAP API
            from zapv2 import ZAPv2
            self.zap = ZAPv2(apikey=self.api_key, proxies=self.proxies)
            version = self.zap.core.version
            self.logger.info(f"Successfully reconnected to ZAP API (version {version})")
            self.available = True
            return True
        except Exception as e:
            self.logger.error(f"Failed to reconnect to ZAP: {str(e)}")
            self.available = False
            return False



    def get_ajax_spider_results(self):
        """Hämta resultat från Ajax Spider scan med direkta HTTP-anrop"""
        import requests
        try:
            # Direkt API-anrop för att hämta Ajax Spider resultat
            result = self._direct_api_call('ajaxSpider/view/results')
            
            if result['success']:
                results = result['data'].get('results', [])
                return results
            else:
                error_msg = f"Failed to get Ajax Spider results: {result.get('response', 'Unknown error')}"
                self.logger.error(error_msg)
                raise Exception(error_msg)
        except Exception as e:
            self.logger.error(f'Error getting Ajax Spider results: {str(e)}')
            raise e
    
    def get_scan_status(self, scan_id):
        """Hämta scanning-status"""
        try:
            # Hämta status
            status_result = self._direct_api_call('ascan/view/status', {'scanId': scan_id})
            
            if not status_result['success']:
                return {
                    'id': scan_id,
                    'status': '0',
                    'error': status_result.get('response', 'Unknown error')
                }
            
            status = status_result['data'].get('status', '0')
            
            # Hämta antal alerts
            alerts_count = 0
            alerts_result = self._direct_api_call('core/view/alerts', {'baseurl': ''})
            if alerts_result['success']:
                alerts = alerts_result['data'].get('alerts', [])
                alerts_count = len(alerts)
            
            return {
                'id': scan_id,
                'status': status,
                'alerts': alerts_count
            }
        except Exception as e:
            self.logger.error(f'Error getting scan status: {str(e)}')
            return {
                'id': scan_id,
                'status': '0',
                'error': str(e)
            }
    
    def get_alerts(self):
        """Get all alerts from ZAP with timeout handling"""
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                # Increase the timeout and add a limit to prevent huge responses
                result = self._direct_api_call('core/view/alerts', 
                                            {'baseurl': '', 'start': '0', 'count': '1000'}, 
                                            timeout=30)
                
                if result['success']:
                    return result['data'].get('alerts', [])
                else:
                    print(f"Attempt {attempt+1}/{max_retries}: Failed to get alerts: {result.get('error', 'Unknown error')}")
                    if attempt < max_retries - 1:
                        # Wait a bit before retrying
                        time.sleep(2)
            except Exception as e:
                print(f"Attempt {attempt+1}/{max_retries}: Error getting alerts: {str(e)}")
                if attempt < max_retries - 1:
                    # Wait a bit before retrying
                    time.sleep(2)
        
        # If we got here, all attempts failed
        print("All attempts to get alerts failed, returning empty list")
        return []




        
    def _extract_domain_or_ip(self, url):
        """Extraherar domännamn eller IP från en URL"""
        try:
            from urllib.parse import urlparse
            
            # Normalisera URL:en genom att ta bort avslutande slash
            if url.endswith('/'):
                url = url[:-1]
                
            # Försök först med vanlig URL-parsning
            parsed_url = urlparse(url)
            
            # Om URL:en saknar schema, lägg till ett tillfälligt
            if not parsed_url.scheme and not url.startswith('//'):
                parsed_url = urlparse(f"http://{url}")
                
            # Extrahera netloc (domain:port)
            netloc = parsed_url.netloc
            
            # Om netloc är tom, kan URL:en vara en IP eller domän utan schema
            if not netloc and parsed_url.path:
                netloc = parsed_url.path.split('/')[0]
            
            # Separera domän/IP från port om det finns
            if ':' in netloc:
                domain_or_ip = netloc.split(':')[0]
            else:
                domain_or_ip = netloc
                
            return domain_or_ip
        except Exception as e:
            self.logger.warning(f"Error extracting domain from {url}: {str(e)}")
            # Returnera original om något går fel
            return url






