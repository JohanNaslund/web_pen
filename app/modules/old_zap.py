    def start_ajax_spider_with_session(self, target_url):
        """Starta ZAP Ajax Spider mot målwebbplatsen med aktiv session"""
        self.logger.info(f'Starting Ajax Spider scan for target: {target_url}')
        
        try:
            # Direct API call to start Ajax Spider
            api_url = f"http://{self.host}:{self.port}/JSON/ajaxSpider/action/scan/"
            response = requests.get(
                api_url,
                params={
                    'apikey': self.api_key,
                    'url': target_url,
                    'inScope': 'true',  # Endast skanna URLs inom scope
                    'contextName': '',  # Använd default context
                    'subtreeOnly': 'false'  # Skanna även länkar utanför subtree
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.logger.info(f'Ajax Spider scan started successfully for {target_url}')
                return {'success': True, 'data': data}
            else:
                error_msg = f"Failed to start Ajax Spider: Status code {response.status_code}, Response: {response.text}"
                self.logger.error(error_msg)
                return {'success': False, 'error': error_msg}
        except Exception as e:
            self.logger.error(f'Error starting Ajax Spider scan: {str(e)}')
            return {'success': False, 'error': str(e)}

    def reset_session_for_site(self, site_url):
        """Rensa sessioner för en specifik site"""
        try:
            domain = self._extract_domain_or_ip(site_url)
            site = f"http://{domain}"
            
            # Försök rensa sessioner
            self._direct_api_call('httpSessions/action/clearSessionTokens', {'site': site})
            return True
        except Exception as e:
            self.logger.error(f"Error resetting sessions: {str(e)}")
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



    def reset_zap(self):
        """Återställ ZAP genom att rensa historik och varningar med direkta API-anrop"""
        self.logger.info("Starting ZAP reset with direct API calls")
        results = {
            'success': True,
            'actions_performed': [],
            'errors': []
        }
        
        # 1. Rensa alla varningar
        try:
            response = requests.get(
                f"http://{self.host}:{self.port}/JSON/core/action/deleteAllAlerts/",
                params={'apikey': self.api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Successfully deleted all alerts")
                results['actions_performed'].append('delete_all_alerts')
            else:
                error_msg = f"Failed to delete alerts, status code: {response.status_code}"
                self.logger.warning(error_msg)
                results['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error deleting alerts: {str(e)}"
            self.logger.error(error_msg)
            results['errors'].append(error_msg)
        
        # 2. Skapa en ny session (detta rensar effektivt alla data)
        try:
            session_name = f"new_session_{int(time.time())}"
            response = requests.get(
                f"http://{self.host}:{self.port}/JSON/core/action/newSession/",
                params={
                    'apikey': self.api_key,
                    'name': session_name,
                    'overwrite': 'true'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Successfully created new session: {session_name}")
                results['actions_performed'].append('new_session')
                results['session_name'] = session_name
            else:
                error_msg = f"Failed to create new session, status code: {response.status_code}"
                self.logger.warning(error_msg)
                results['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error creating new session: {str(e)}"
            self.logger.error(error_msg)
            results['errors'].append(error_msg)
        
        # 3. Kör garbage collection
        try:
            response = requests.get(
                f"http://{self.host}:{self.port}/JSON/core/action/runGarbageCollection/",
                params={'apikey': self.api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Successfully ran garbage collection")
                results['actions_performed'].append('garbage_collection')
            else:
                error_msg = f"Failed to run garbage collection, status code: {response.status_code}"
                self.logger.warning(error_msg)
                results['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error running garbage collection: {str(e)}"
            self.logger.error(error_msg)
            results['errors'].append(error_msg)
        
        # 4. Verifiera resultatet genom att hämta sites
        try:
            response = requests.get(
                f"http://{self.host}:{self.port}/JSON/core/view/sites/",
                params={'apikey': self.api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                sites = data.get('sites', [])
                results['sites_remaining'] = len(sites)
                results['sites'] = sites
                self.logger.info(f"After reset, {len(sites)} sites remain")
            else:
                error_msg = f"Failed to get sites after reset, status code: {response.status_code}"
                self.logger.warning(error_msg)
                results['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error getting sites after reset: {str(e)}"
            self.logger.error(error_msg)
            results['errors'].append(error_msg)
        
        # Sammanfatta resultatet
        if not results['errors']:
            self.logger.info("ZAP reset completed successfully")
            results['message'] = "ZAP reset completed successfully"
        else:
            self.logger.warning(f"ZAP reset completed with {len(results['errors'])} errors")
            results['message'] = f"ZAP reset completed with {len(results['errors'])} errors"
            results['success'] = len(results['actions_performed']) > 0
        
        return results


    def _get_from_cache(self, target_url):
        """Hämta cookies från cache om tillgängliga och färska"""
        with cookie_cache_lock:
            if target_url in cookie_cache:
                cache_time, cookies = cookie_cache[target_url]
                # Använd cache om mindre än 5 minuter gammal
                if time.time() - cache_time < 300:
                    self.logger.info(f"Using cached cookies for {target_url}")
                    return cookies
        return None

    def _update_cache(self, target_url, cookies):
        """Uppdatera cookie-cache"""
        with cookie_cache_lock:
            cookie_cache[target_url] = (time.time(), cookies)
            self.logger.info(f"Updated cookie cache for {target_url}")

    def cleanup_cookies_cache(self):
        """Rensa cookie-cache äldre än en timme"""
        with cookie_cache_lock:
            current_time = time.time()
            to_delete = []
            
            for url, (cache_time, _) in cookie_cache.items():
                if current_time - cache_time > 3600:  # 1 timme
                    to_delete.append(url)
                    
            for url in to_delete:
                del cookie_cache[url]
                
            self.logger.info(f"Cleaned {len(to_delete)} old entries from cookie cache")
            
    def start_spider(self, target_url):
        """Starta ZAP spider mot målwebbplatsen"""
        print(f'Spidering target: {target_url}')
        scan_id = self.zap.spider.scan(target_url)
        return scan_id


    def get_ajax_spider_status(self):
        """Hämta status för Ajax Spider-scanning"""
        try:
            if not hasattr(self.zap, 'ajaxSpider'):
                return {
                    'status': 'unavailable',
                    'error': 'Ajax Spider not available'
                }
                
            # Hämta aktuell status
            status = self.zap.ajaxSpider.status
            
            # Hämta antal resultat
            num_urls = 0
            if status == 'stopped':
                # Endast hämta resultat om skanningen är slutförd
                results = self.zap.ajaxSpider.results(0, 1000)  # Hämta upp till 1000 resultat
                num_urls = len(results)
            
            return {
                'status': status,
                'is_running': status != 'stopped',
                'number_of_urls': num_urls,
                'progress': 100 if status == 'stopped' else 0  # Ajax Spider ger ingen procentuell status
            }
        except Exception as e:
            print(f'Error getting Ajax Spider status: {str(e)}')
            return {
                'status': 'error',
                'error': str(e)
            }


    
    def get_ajax_spider_status(self):
        """Hämta status för Ajax Spider-scanning"""
        try:
            # Skapa URL för status API
            status_url = f"http://{self.host}:{self.port}/JSON/ajaxSpider/view/status/"
            
            # Skapa parametrar
            params = {
                'apikey': self.api_key
            }
            
            # Gör API-anrop
            response = requests.get(status_url, params=params, timeout=30)
            
            # Kontrollera svar
            if response.status_code == 200:
                result = response.json()
                status = result.get('status', 'unknown')
                
                # Hämta resultat om skanningen är klar
                num_results = 0
                if status == 'stopped':
                    # Hämta antal resultat
                    results_url = f"http://{self.host}:{self.port}/JSON/ajaxSpider/view/results/"
                    results_response = requests.get(
                        results_url,
                        params={'apikey': self.api_key},
                        timeout=30
                    )
                    
                    if results_response.status_code == 200:
                        results_data = results_response.json()
                        results_list = results_data.get('results', [])
                        num_results = len(results_list)
                
                return {
                    'status': status,
                    'number_of_urls': num_results,
                    'is_running': status != 'stopped'
                }
            else:
                print(f"ZAP API returned status code {response.status_code}: {response.text}")
                return {
                    'status': 'error',
                    'error': f"HTTP error {response.status_code}"
                }
        except Exception as e:
            print(f'Error getting Ajax Spider status: {str(e)}')
            return {
                'status': 'error',
                'error': str(e)
            }
        

    def start_ajax_spider(self, target_url, session_cookies=None):
        """Starta ZAP Ajax Spider mot målwebbplatsen"""
        print(f'Ajax Spidering target: {target_url}')
        
        try:
            if session_cookies:
                context_id = self._create_context_with_session(target_url, session_cookies)
                return self.zap.ajaxSpider.scan(target_url, contextid=context_id)
            else:
                return self.zap.ajaxSpider.scan(target_url)
        except Exception as e:
            print(f'Error starting Ajax Spider scan: {str(e)}')
            raise e
            
   
    def start_ajax_spider(self, target_url, cookies_str=None):
        """Starta ZAP Ajax Spider mot målwebbplatsen med cookie-stöd"""
        try:
            print(f'Starting Ajax Spider scan for URL: {target_url}')
            
            # Skapa URL för Ajax Spider API
            ajax_spider_url = f"http://{self.host}:{self.port}/JSON/ajaxSpider/action/scan/"
            
            # Skapa parametrar (utan inScope)
            params = {
                'apikey': self.api_key,
                'url': target_url
            }
            
            # Hantera cookies om de finns
            headers = {}
            if cookies_str:
                headers['Cookie'] = cookies_str
                print(f"Added cookies to header: {cookies_str[:100]}...")  # Logga första 100 tecken
            
            # Gör API-anrop
            response = requests.get(ajax_spider_url, params=params, headers=headers, timeout=60)
            
            # Kontrollera svar
            if response.status_code == 200:
                result = response.json()
                if result.get('Result') == 'OK':
                    print(f"Ajax Spider scan started successfully")
                    return "ajax_spider_running"
                else:
                    print(f"ZAP API returned error: {result}")
                    raise Exception(f"ZAP API error: {result.get('message', 'Unknown error')}")
            else:
                print(f"ZAP API returned status code {response.status_code}: {response.text}")
                raise Exception(f"ZAP API returned status code {response.status_code}: {response.text}")
                
        except Exception as e:
            print(f'Error starting Ajax Spider scan: {str(e)}')
            raise e
        


    def _start_ajax_spider_direct(self, target_url, cookies_str=None):
        print("""Starta Ajax Spider med direkt HTTP-anrop""")
        try:
            print(f'Starting Ajax Spider via direct HTTP call for URL: {target_url}')
            
            # Konfigurera sessionen med cookies om tillgängliga
            if cookies_str:
                self._create_context_with_session(target_url, cookies_str)
                print(f"Added cookies to session before Ajax Spider scan")
            
            # Använd direkt HTTP-anrop UTAN inScope-parametern
            ajax_spider_url = f"http://{self.host}:{self.port}/JSON/ajaxSpider/action/scan/"
            params = {
                'apikey': self.api_key,
                'url': target_url
                # Ta bort inScope-parametern här
            }
            
            response = requests.get(ajax_spider_url, params=params)
            print(ajax_spider_url)
            print(params)

            if response.status_code == 200:
                result = response.json()
                if result.get('Result') == 'OK':
                    print(f'Ajax Spider scan started successfully via direct HTTP call')
                    return 'ajax_spider_running'
                else:
                    error_msg = result.get('message', 'Unknown error')
                    raise Exception(f'ZAP API error: {error_msg}')
            else:
                raise Exception(f'ZAP API returned status code {response.status_code}: {response.text}')
        except Exception as e:
            print(f'Error in direct Ajax Spider call: {str(e)}')
            raise e
        
    def _create_context_with_session(self, target_url, session_cookies):
        """Skapa en ZAP-kontext med sessionscookies"""
        # Extrahera basdomänen för kontexten
        domain = urlparse(target_url).netloc
        context_name = f"auth-context-{int(time.time())}"
        
        # Skapa ny kontext
        self.zap.context.new_context(context_name)
        context_id = self.zap.context.context(context_name)['id']
        
        # Lägg till måldomänen i inkluderingslistan
        self.zap.context.include_in_context(context_name, f".*{domain}.*")
        
        # För varje cookie, lägg till den i HTTP Sessions
        cookies_array = session_cookies.split(';')
        cookies_dict = {}
        for cookie in cookies_array:
            if cookie.strip() and '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies_dict[name] = value
        
        # Använd HTTPSessions för att sätta upp sessionen
        site = f"http://{domain}"
        try:
            # Skapa en ny session
            session_name = f"auth-session-{int(time.time())}"
            self.zap.httpsessions.create_empty_session(site, session_name)
            self.zap.httpsessions.set_active_session(site, session_name)
            
            # Lägg till cookies i sessionen
            for name, value in cookies_dict.items():
                self.zap.httpsessions.add_session_token(site, name)
                self.zap.httpsessions.set_session_token_value(site, session_name, name, value)
            
            print(f"Successfully created authenticated session with {len(cookies_dict)} cookies")
        except Exception as e:
            print(f"Error setting up session: {str(e)}")
        
        return context_id


    def get_cookies_simple(self, target_url=None):
        """En enklare metod för att hämta cookies från ZAP"""
        try:
            domain = urlparse(target_url).netloc if target_url else None
            
            # Metod 1: Använd direktanrop till HTTP API
            try:
                # Skapa en HTTP-förfrågan direkt till ZAP API
                import requests
                
                # Få alla cookies
                response = requests.get(
                    f"http://localhost:8080/JSON/core/view/allSites/?apikey={self.zap._ZAPv2__api_key}"
                )
                sites_data = response.json()
                
                # Kontrollera om den måldomän vi är intresserade av finns i listan
                if 'sites' in sites_data and domain:
                    target_site = None
                    for site in sites_data['sites']:
                        if domain in site:
                            target_site = site
                            break
                    
                    if target_site:
                        # Hämta alla meddelanden för den här platsen
                        response = requests.get(
                            f"http://localhost:8080/JSON/core/view/messages/?baseurl={target_site}&apikey={self.zap._ZAPv2__api_key}"
                        )
                        messages_data = response.json()
                        
                        if 'messages' in messages_data:
                            for message in messages_data['messages']:
                                req_header = message.get('requestHeader', '')
                                if 'Cookie:' in req_header:
                                    for line in req_header.split('\n'):
                                        if line.strip().startswith('Cookie:'):
                                            return line.replace('Cookie:', '').strip()
            except Exception as e:
                print(f"Direct API request for cookies failed: {str(e)}")
            
            # Fallback message
            return ""
      
        except Exception as e:
            print(f"Error in get_cookies_simple: {str(e)}")
            return ""
        
    
    def extract_cookies_as_string(self, target_url=None):
        """Hämta alla cookies som en sträng för enkel användning i HTTP-headers"""
        try:
            cookies = []
            domain = urlparse(target_url).netloc if target_url else None
            
            # Använd core.messages för att hitta cookies i headers
            if domain:
                site = f"http://{domain}"
                try:
                    # Metod 1: Hämta meddelanden direkt
                    # Notera: API kan returnera olika format i olika versioner
                    messages = self.zap.core.messages(baseurl=site)
                    
                    # Kontrollera om det är en lista (nyare versioner) eller ett objekt med 'messages'-nyckel (äldre)
                    if isinstance(messages, list):
                        message_list = messages
                    elif isinstance(messages, dict) and 'messages' in messages:
                        message_list = messages.get('messages', [])
                    else:
                        message_list = []
                    
                    # Bearbeta meddelanden för att hitta cookies
                    for message in message_list:
                        # Fortsätt bara om message är ett dictionary
                        if not isinstance(message, dict):
                            continue
                            
                        req_header = message.get('requestHeader', '') if isinstance(message, dict) else ''
                        if 'Cookie:' in req_header:
                            cookie_lines = [line.strip() for line in req_header.split('\n') if line.strip().startswith('Cookie:')]
                            if cookie_lines:
                                cookie_line = cookie_lines[0].replace('Cookie:', '').strip()
                                if cookie_line:
                                    return cookie_line
                except Exception as e:
                    print(f"Error getting cookies from messages: {str(e)}")
                    
                # Metod 2: Försök med HTTP Sessions API
                try:
                    # Hämta aktiv session för webbplatsen
                    sessions = self.zap.httpsessions.sessions(site)
                    
                    # Hantera olika responsformat
                    if isinstance(sessions, list):
                        for session in sessions:
                            if not isinstance(session, dict):
                                continue
                                
                            if session.get('active', False) and session.get('tokens'):
                                cookie_parts = []
                                for name, value in session.get('tokens').items():
                                    cookie_parts.append(f"{name}={value}")
                                if cookie_parts:
                                    return '; '.join(cookie_parts)
                    elif isinstance(sessions, dict) and 'sessions' in sessions:
                        for session in sessions.get('sessions', []):
                            if session.get('active', False) and session.get('tokens'):
                                cookie_parts = []
                                for name, value in session.get('tokens').items():
                                    cookie_parts.append(f"{name}={value}")
                                if cookie_parts:
                                    return '; '.join(cookie_parts)
                except Exception as e:
                    print(f"Error getting cookies from HTTP sessions: {str(e)}")
                
            # Metod 3: Fallback - manuell sökning i historiken
            try:
                # Använd direkt core API för att hitta cookies i historik
                sites = self.zap.core.sites
                for site in sites:
                    if domain and domain not in site:
                        continue
                        
                    # Försök hämta historik för platsen
                    try:
                        history = self.zap.core.messages(baseurl=site)
                        
                        # Kontrollera format
                        if isinstance(history, list):
                            messages = history
                        else:
                            messages = []
                            
                        # Sök igenom meddelanden
                        for msg in messages:
                            # Säkerställ att msg är ett dictionary
                            if not isinstance(msg, dict):
                                continue
                                
                            req_header = msg.get('requestHeader', '')
                            if 'Cookie:' in req_header:
                                # Hitta cookie-raden
                                lines = req_header.split('\n')
                                for line in lines:
                                    if line.strip().startswith('Cookie:'):
                                        cookie_str = line.replace('Cookie:', '').strip()
                                        if cookie_str:
                                            return cookie_str
                    except Exception as inner_e:
                        print(f"Error processing site {site}: {str(inner_e)}")
                        continue
                        
            except Exception as e:
                print(f"Error in fallback cookie extraction: {str(e)}")
                
            # Metod 4: Sista försök - sök genom historik-items direkt
            try:
                # Använd History API om tillgängligt
                if hasattr(self.zap, 'history'):
                    history_items = self.zap.history.view_history()
                    
                    # Hantera olika format
                    if isinstance(history_items, list):
                        items = history_items
                    elif isinstance(history_items, dict) and 'historyItems' in history_items:
                        items = history_items.get('historyItems', [])
                    else:
                        items = []
                    
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                            
                        if 'requestHeader' in item:
                            req_header = item['requestHeader']
                            if 'Cookie:' in req_header:
                                lines = req_header.split('\n')
                                for line in lines:
                                    if line.strip().startswith('Cookie:'):
                                        cookie_str = line.replace('Cookie:', '').strip()
                                        if cookie_str:
                                            return cookie_str
            except Exception as e:
                print(f"Error in history-based cookie extraction: {str(e)}")
                
            # Inget hittades
            return ""
                
        except Exception as e:
            print(f"Error in extract_cookies_as_string: {str(e)}")
            return ""

    def _format_cookies_from_session(self, session):
        """Formatera cookies från en session"""
        cookies = []
        for token_name, token_value in session.get('tokens', {}).items():
            cookies.append({
                'name': token_name,
                'value': token_value,
                'domain': session.get('site', '')
            })
        return cookies

    def _get_cookies_from_site(self, site):
        """Hämta cookies för en specifik plats via HTTP Sessions tokens"""
        cookies = []
        active_session = self.zap.httpsessions.active_session(site)
        if active_session:
            tokens = self.zap.httpsessions.session_tokens(site)
            for token in tokens:
                value = self.zap.httpsessions.session_token_value(site, active_session, token)
                if value:
                    cookies.append({
                        'name': token,
                        'value': value,
                        'domain': site
                    })
        return cookies

    
    def _get_all_sites_cookies(self):
        """Fallback: Hämta cookies från alla platser"""
        cookies = []
        try:
            sites = self.zap.core.sites
            for site in sites:
                site_cookies = self.zap.httpsessions.cookies(site)
                for cookie in site_cookies:
                    cookies.append({
                        'name': cookie.get('name', ''),
                        'value': cookie.get('value', ''),
                        'domain': site
                    })
        except Exception as e:
            print(f"Error getting all sites cookies: {str(e)}")
        return cookies

    def add_session_token(self, site_url, token_name, token_value):
        """Lägg till en session token för en specifik site"""
        try:
            domain = self._extract_domain_or_ip(site_url)
            site = f"http://{domain}"
            
            # Skapa en session om det inte finns någon
            sessions = self._direct_api_call('httpSessions/view/sessions', {'site': site})
            if not sessions['success'] or not sessions['data'].get('sessions'):
                # Skapa en tom session
                session_name = f"auth-session-{int(time.time())}"
                self._direct_api_call('httpSessions/action/createEmptySession', {
                    'site': site,
                    'sessionName': session_name
                })
                
                # Sätt sessionen som aktiv
                self._direct_api_call('httpSessions/action/setActiveSession', {
                    'site': site,
                    'session': session_name
                })
            
            # Lägg till token i sessionen
            active_session = self._direct_api_call('httpSessions/view/activeSession', {'site': site})
            if active_session['success']:
                session_name = active_session['data'].get('session')
                
                # Lägg till token
                self._direct_api_call('httpSessions/action/addSessionToken', {
                    'site': site,
                    'sessionToken': token_name
                })
                
                # Sätt token-värdet
                self._direct_api_call('httpSessions/action/setSessionTokenValue', {
                    'site': site,
                    'session': session_name,
                    'sessionToken': token_name,
                    'tokenValue': token_value
                })
                
                self.logger.info(f"Added session token {token_name} to site {site}")
                return True
        except Exception as e:
            self.logger.error(f"Error adding session token: {str(e)}")
            return False
        

    def _setup_session_with_cookies(self, target_url, cookies_str):
        """Set up ZAP HTTP session with cookies before starting Ajax Spider"""
        try:
            # Parse the target URL to get the domain
            domain = urlparse(target_url).netloc
            
            # Create a site-specific session in ZAP
            session_name = f"ajax_spider_session_{int(time.time())}"
            session_url = f"http://{self.host}:{self.port}/JSON/httpsessions/action/createEmptySession/"
            
            # Create empty session
            session_params = {
                'apikey': self.api_key,
                'site': target_url,
                'session': session_name
            }
            
            session_response = requests.get(session_url, params=session_params)
            if session_response.status_code != 200:
                print(f"Failed to create session: {session_response.text}")
                return False
                
            # Set this as active session
            active_url = f"http://{self.host}:{self.port}/JSON/httpsessions/action/setActiveSession/"
            active_params = {
                'apikey': self.api_key,
                'site': target_url,
                'session': session_name
            }
            
            active_response = requests.get(active_url, params=active_params)
            if active_response.status_code != 200:
                print(f"Failed to set active session: {active_response.text}")
                return False
                
            # Parse cookies string and add each cookie to the session
            cookies = cookies_str.split(';')
            for cookie in cookies:
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    
                    # Add session token to ZAP
                    token_url = f"http://{self.host}:{self.port}/JSON/httpsessions/action/addSessionToken/"
                    token_params = {
                        'apikey': self.api_key,
                        'site': target_url,
                        'sessionToken': name
                    }
                    
                    token_response = requests.get(token_url, params=token_params)
                    if token_response.status_code != 200:
                        print(f"Failed to add session token {name}: {token_response.text}")
                        continue
                    
                    # Set token value
                    value_url = f"http://{self.host}:{self.port}/JSON/httpsessions/action/setSessionTokenValue/"
                    value_params = {
                        'apikey': self.api_key,
                        'site': target_url,
                        'session': session_name,
                        'sessionToken': name,
                        'tokenValue': value
                    }
                    
                    value_response = requests.get(value_url, params=value_params)
                    if value_response.status_code != 200:
                        print(f"Failed to set token value for {name}: {value_response.text}")
                        continue
                        
            print(f"Successfully set up ZAP session with {len(cookies)} cookies")
            return True
        except Exception as e:
            print(f"Error setting up session with cookies: {str(e)}")
            return False


    def stop_ajax_spider(self):
        """Stoppa ZAP Ajax Spider scanning med direkta HTTP-anrop"""
        self.logger.info('Stopping Ajax Spider scan')
        import requests
        try:
            # Direkt API-anrop för att stoppa Ajax Spider
            result = self._direct_api_call('ajaxSpider/action/stop')
            
            if result['success']:
                self.logger.info('Ajax Spider scan stopped successfully')
                return True
            else:
                error_msg = f"Failed to stop Ajax Spider: {result.get('response', 'Unknown error')}"
                self.logger.error(error_msg)
                raise Exception(error_msg)
        except Exception as e:
            self.logger.error(f'Error stopping Ajax Spider scan: {str(e)}')
            raise e

    def enforce_resource_limits(self):
        """Begränsa resursanvändning i ZAP"""
        try:
            # 1. Avsluta alla aktiva skanningar som har kört för länge
            self._stop_long_running_scans(max_duration=1800)  # 30 minuter max
            
            # 2. Begränsa antalet samtidiga skanningar
            self._limit_concurrent_scans(max_scans=1)  # Kör endast en scanning i taget
            
            # 3. Begränsa storleken på historiken
            self._limit_history_size(max_entries_per_site=500)  # Färre historikinlägg
            
            # 4. Rensa alerts regelbundet
            alerts_count = len(self.zap.core.alerts())
            if alerts_count > 1000:
                print(f"Clearing {alerts_count} alerts to save memory")
                self.zap.core.delete_all_alerts()
            
            # 5. Kör garbage collection
            self.zap.core.run_garbage_collection()
            
            return True
        except Exception as e:
            self.logger.error(f"Error enforcing resource limits: {str(e)}")
            return False

           
    def _stop_long_running_scans(self, max_duration=900):
        """Stoppa skanningar som kört för länge"""
        try:
            # Kontrollera spider-skanningar
            try:
                scanners = self.zap.spider.scans
                current_time = time.time()
                
                for scan in scanners:
                    scan_id = scan.get('id')
                    if scan_id and int(self.zap.spider.status(scan_id)) < 100:
                        # Kontrollera hur länge den har kört
                        progress = int(self.zap.spider.status(scan_id))
                        time_running = current_time - scan.get('timeStamp', current_time) / 1000.0
                        
                        if time_running > max_duration or (progress < 50 and time_running > max_duration / 2):
                            self.logger.warning(f"Stopping long-running spider {scan_id} (running for {time_running:.1f}s)")
                            self.zap.spider.stop(scan_id)
            except Exception as e:
                self.logger.warning(f"Error checking spider scans: {str(e)}")
                
            # Kontrollera aktiva skanningar
            try:
                scanners = self.zap.ascan.scans
                current_time = time.time()
                
                for scan in scanners:
                    scan_id = scan.get('id')
                    if scan_id and int(self.zap.ascan.status(scan_id)) < 100:
                        # Kontrollera hur länge den har kört
                        progress = int(self.zap.ascan.status(scan_id))
                        time_running = current_time - scan.get('timeStamp', current_time) / 1000.0
                        
                        if time_running > max_duration or (progress < 50 and time_running > max_duration / 2):
                            self.logger.warning(f"Stopping long-running active scan {scan_id} (running for {time_running:.1f}s)")
                            self.zap.ascan.stop(scan_id)
            except Exception as e:
                self.logger.warning(f"Error checking active scans: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error in _stop_long_running_scans: {str(e)}")
            

 
    def _limit_concurrent_scans(self, max_scans=2):
        """Begränsa antalet samtidiga skanningar"""
        try:
            active_scans = 0
            
            # Räkna aktiva spider-skanningar
            try:
                scanners = self.zap.spider.scans
                for scan in scanners:
                    scan_id = scan.get('id')
                    if scan_id and int(self.zap.spider.status(scan_id)) < 100:
                        active_scans += 1
            except Exception:
                pass
                
            # Räkna aktiva scan-skanningar
            try:
                scanners = self.zap.ascan.scans
                for scan in scanners:
                    scan_id = scan.get('id')
                    if scan_id and int(self.zap.ascan.status(scan_id)) < 100:
                        active_scans += 1
            except Exception:
                pass
                
            # Om vi har för många aktiva skanningar, stoppa de nyaste tills vi är under gränsen
            if active_scans > max_scans:
                excess = active_scans - max_scans
                self.logger.warning(f"Too many active scans ({active_scans}), stopping {excess}")
                
                # Stoppa spider-skanningar först
                try:
                    scanners = self.zap.spider.scans
                    scanners.sort(key=lambda x: x.get('timeStamp', 0), reverse=True)  # Nyast först
                    
                    for scan in scanners:
                        if excess <= 0:
                            break
                            
                        scan_id = scan.get('id')
                        if scan_id and int(self.zap.spider.status(scan_id)) < 100:
                            self.logger.warning(f"Stopping spider scan {scan_id}")
                            self.zap.spider.stop(scan_id)
                            excess -= 1
                except Exception:
                    pass
                
                # Om vi fortfarande har överskott, stoppa aktiva skanningar
                if excess > 0:
                    try:
                        scanners = self.zap.ascan.scans
                        scanners.sort(key=lambda x: x.get('timeStamp', 0), reverse=True)  # Nyast först
                        
                        for scan in scanners:
                            if excess <= 0:
                                break
                                
                            scan_id = scan.get('id')
                            if scan_id and int(self.zap.ascan.status(scan_id)) < 100:
                                self.logger.warning(f"Stopping active scan {scan_id}")
                                self.zap.ascan.stop(scan_id)
                                excess -= 1
                    except Exception:
                        pass
        except Exception as e:
            self.logger.error(f"Error in _limit_concurrent_scans: {str(e)}")
            

    def _limit_history_size(self, max_entries_per_site=1000):
        """Begränsa storleken på historiken"""
        try:
            sites = self.zap.core.sites
            for site in sites:
                try:
                    # Hämta antal historik-poster för denna site
                    messages = self.zap.core.messages(baseurl=site)
                    count = len(messages)
                    
                    if count > max_entries_per_site:
                        self.logger.warning(f"Site {site} has {count} history entries, clearing history")
                        self.zap.core.delete_site_node(site, recurse=True)
                except Exception as e:
                    self.logger.warning(f"Error checking history for site {site}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error in _limit_history_size: {str(e)}")


    def monitor_zap_processes(self):
        """Övervaka ZAP-processer och deras resursanvändning"""
        try:
            import psutil
            
            java_processes = []
            firefox_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    if 'java' in proc.info['name'].lower():
                        java_processes.append(proc.info)
                    elif 'firefox' in proc.info['name'].lower():
                        firefox_processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Logga resursanvändning
            total_java_cpu = sum(p['cpu_percent'] for p in java_processes)
            total_java_mem = sum(p['memory_percent'] for p in java_processes)
            
            total_firefox_cpu = sum(p['cpu_percent'] for p in firefox_processes)
            total_firefox_mem = sum(p['memory_percent'] for p in firefox_processes)
            
            print(f"ZAP Java Processes: {len(java_processes)}, CPU: {total_java_cpu:.1f}%, Mem: {total_java_mem:.1f}%")
            print(f"Firefox Processes: {len(firefox_processes)}, CPU: {total_firefox_cpu:.1f}%, Mem: {total_firefox_mem:.1f}%")
            
            # Om för mycket resurser används, vidta åtgärder
            if len(firefox_processes) > 5 or total_firefox_mem > 50.0:
                print("Too many Firefox processes or memory usage, cleaning up...")
                self.cleanup_resources()
                
            return {
                'java_processes': len(java_processes),
                'java_cpu': total_java_cpu,
                'java_mem': total_java_mem,
                'firefox_processes': len(firefox_processes),
                'firefox_cpu': total_firefox_cpu,
                'firefox_mem': total_firefox_mem
            }
            
        except Exception as e:
            print(f"Error monitoring processes: {str(e)}")
            return {}



    def cleanup_resources(self):
        """Rensa ZAP-resurser för att frigöra minne"""
        try:
            # Stoppa alla pågående skanningar
            for scan_id in list(self.active_scans.keys()):
                scan_type = self.active_scans[scan_id]['type']
                try:
                    if scan_type == 'spider':
                        self.zap.spider.stop(scan_id)
                    elif scan_type == 'ascan':
                        self.zap.ascan.stop(scan_id)
                    print(f"Stopped scan {scan_id}")
                except Exception as e:
                    print(f"Error stopping scan {scan_id}: {str(e)}")
            
            # Rensa historiken om den blivit för stor
            try:
                sites = self.zap.core.sites
                for site in sites:
                    history_count = len(self.zap.core.messages(baseurl=site))
                    if history_count > 1000:  # Om historiken är för stor
                        print(f"Cleaning history for site: {site} ({history_count} items)")
                        self.zap.core.delete_all_alerts()
                        # Observera: detta kan påverka rapporteringen, använd med försiktighet
                
                # Meddela Java garbage collector att det är dags att städa
                self.zap.core.run_garbage_collection()
                
                # Rensa ZAP sessioner för att förhindra minnesläckor
                # Om det finns en sådan funktion i din ZAP API-version
                if hasattr(self.zap, 'users') and hasattr(self.zap.users, 'users_list'):
                    users = self.zap.users.users_list()
                    if len(users) > 20:  # Begränsa antal användare
                        print(f"Too many users ({len(users)}), cleaning up...")
                        # Ta bort äldre användare
                        
                return True
            except Exception as e:
                print(f"Error during cleanup: {str(e)}")
                return False
                
        except Exception as e:
            print(f"Error during cleanup: {str(e)}")
            return False


    
    def get_cookies(self, target_url):
        """Hämta cookies för en specifik URL med endast direkta HTTP-anrop"""
        if not target_url:
            self.logger.warning("No target URL provided")
            return ""
        
        # Kontrollera tillgänglighet först (använder den direkta HTTP-metoden)
        if not self.is_available():
            self.logger.warning("ZAP is not available")
            return ""
        
        self.logger.info(f"Looking for cookies for URL: {target_url}")
        
        # Extrahera domän från URL:en
        domain = self._extract_domain_or_ip(target_url)
        self.logger.info(f"Extracted domain: {domain}")
        
        # Steg 1: Hämta alla sites
        try:
            import requests
            
            sites_url = f"http://{self.host}:{self.port}/JSON/core/view/sites/"
            sites_response = requests.get(
                sites_url,
                params={'apikey': self.api_key},
                timeout=30
            )
            
            if sites_response.status_code != 200:
                self.logger.warning(f"API call to sites failed with status {sites_response.status_code}")
                return ""
            
            sites_data = sites_response.json()
            sites = sites_data.get('sites', [])
            
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
                
                messages_url = f"http://{self.host}:{self.port}/JSON/core/view/messages/"
                messages_response = requests.get(
                    messages_url,
                    params={
                        'apikey': self.api_key,
                        'baseurl': site
                    },
                    timeout=30
                )
                
                if messages_response.status_code != 200:
                    self.logger.warning(f"API call to messages failed with status {messages_response.status_code}")
                    continue
                
                messages_data = messages_response.json()
                messages = messages_data.get('messages', [])
                
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
                
                sessions_url = f"http://{self.host}:{self.port}/JSON/httpSessions/view/sessions/"
                sessions_response = requests.get(
                    sessions_url,
                    params={
                        'apikey': self.api_key,
                        'site': site
                    },
                    timeout=30
                )
                
                if sessions_response.status_code != 200:
                    self.logger.warning(f"API call to sessions failed with status {sessions_response.status_code}")
                    continue
                
                sessions_data = sessions_response.json()
                sessions = sessions_data.get('sessions', [])
                
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
            
        except Exception as e:
            self.logger.error(f"Error in get_cookies: {str(e)}")
            return ""
        

