import urllib.parse
import time
import json
import os
import uuid
import re
import threading
import requests
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

import logging
import os
from datetime import datetime

class SQLInjectionLogger:
    """En dedikerad logger för SQL Injection-testerna"""
    
    def __init__(self, log_dir='./logs/sql_injection'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Skapa en timestampad logfil
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = os.path.join(log_dir, f'sql_test_{timestamp}.log')
        
        # Konfigurera logger
        self.logger = logging.getLogger('SQLInjectionTester')
        self.logger.setLevel(logging.DEBUG)
        
        # Sätt upp file handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Sätt upp console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Skapa formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Lägg till handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        self.logger.info(f"SQL Injection Logger initialized, logging to {self.log_file}")
    
    def debug(self, message):
        """Logga debug-meddelande"""
        self.logger.debug(message)
    
    def info(self, message):
        """Logga info-meddelande"""
        self.logger.info(message)
    
    def warning(self, message):
        """Logga varningsmeddelande"""
        self.logger.warning(message)
    
    def error(self, message):
        """Logga felmeddelande"""
        self.logger.error(message)
    
    def critical(self, message):
        """Logga kritiskt felmeddelande"""
        self.logger.critical(message)
    
    def get_log_file_path(self):
        """Returnera sökvägen till loggfilen"""
        return self.log_file

class SQLInjectionTester:
    """En enkel SQL injection-tester som kan användas istället för SQLMap"""
    
    def __init__(self, storage_path='./data/sql_tester'):
        """Initialisera med en sökväg för att spara resultat"""
        self.storage_path = storage_path
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        os.makedirs(storage_path, exist_ok=True)
        
        # Initiera logger
        self.logger = SQLInjectionLogger()
        self.logger.info(f"SQLInjectionTester initialized with storage path: {storage_path}")
        
        # Vanliga SQL injection-payloads
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "') OR ('1'='1",
            "') OR ('1'='1' --",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "' OR 1=1",
            "admin' --",
            "admin' #",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT 1,2,3,4 --",
            "' UNION SELECT 1,2,3,4,5 --",
            "' AND (SELECT 5231 FROM (SELECT(SLEEP(1)))OQkl) AND 'MRxc'='MRxc",  # Time-based
            "' AND (SELECT 9472 FROM PG_SLEEP(1)) AND 'Nzqp'='Nzqp",  # PostgreSQL time-based
            "' WAITFOR DELAY '0:0:1' --",  # MSSQL time-based
            "1' AND SLEEP(1) AND '1'='1",  # MySQL time-based
            "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",  # Blind
            "' OR EXISTS(SELECT * FROM users) --"  # Blind
        ]
        
        # Olika tecken på SQL injection-sårbarhet
        self.error_patterns = [
            "SQL syntax",
            "mysql",
            "MySQL",
            "Oracle",
            "oracle",
            "ORA-",
            "Microsoft SQL Server",
            "SQLite",
            "sqlite",
            "PostgreSQL",
            "postgres",
            "ODBC",
            "JDBC",
            "Syntax error",
            "syntax error",
            "Unclosed quotation mark",
            "unterminated quoted string",
            "quotation mark after the character string",
            "Warning: mysql_",
            "Warning: pg_",
            "Warning: sqlsrv_",
            "Warning: oci_"
        ]
        
        self.logger.info(f"Initialized with {len(self.payloads)} payloads and {len(self.error_patterns)} error patterns")
    
    def _generate_scan_id(self):
        """Generera ett unikt scan-ID"""
        return str(uuid.uuid4())
    
    def extract_forms(self, response):
        """Extrahera alla formulär från en HTML-sida"""
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            # Om action är relativ, gör den absolut
            if form_data['action'] and not form_data['action'].startswith(('http://', 'https://')):
                if form_data['action'].startswith('/'):
                    # Absolut väg men relativ till domän
                    parsed_url = urllib.parse.urlparse(response.url)
                    form_data['action'] = f"{parsed_url.scheme}://{parsed_url.netloc}{form_data['action']}"
                else:
                    # Relativ till aktuell sida
                    form_data['action'] = urllib.parse.urljoin(response.url, form_data['action'])
            
            # Om action är tom, använd sidans URL
            if not form_data['action']:
                form_data['action'] = response.url
            
            # Hämta input-fält
            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_type = input_field.get('type', '')
                input_name = input_field.get('name', '')
                
                # Hoppa över submit-knappar och dolda fält
                if input_type in ['submit', 'button', 'image'] or not input_name:
                    continue
                
                input_value = input_field.get('value', '')
                form_data['inputs'].append({
                    'name': input_name,
                    'type': input_type,
                    'value': input_value
                })
            
            forms.append(form_data)
        
        return forms
    
    def extract_parameters(self, url):
        """Extrahera parametrar från en URL"""
        parsed_url = urllib.parse.urlparse(url)
        params = []
        
        if parsed_url.query:
            query_params = urllib.parse.parse_qsl(parsed_url.query)
            for name, value in query_params:
                params.append({
                    'name': name,
                    'value': value
                })
        
        return params
    
    def test_parameter(self, url, param_name, param_value, cookies=None):
        """Testa en specifik parameter för SQL injection"""
        results = []
        original_url = url
        parsed_url = urllib.parse.urlparse(url)
        
        # Skapa baslinjerespons
        try:
            baseline_response = self.session.get(url, cookies=cookies, timeout=5)
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
            baseline_time = time.time()
        except Exception as e:
            print(f"Error getting baseline response: {str(e)}")
            return []
        
        # Testa varje payload
        for payload in self.payloads:
            try:
                # Skapa ny query string med injekterad payload
                query_params = urllib.parse.parse_qsl(parsed_url.query)
                new_query_params = []
                
                for name, value in query_params:
                    if name == param_name:
                        new_query_params.append((name, value + payload))
                    else:
                        new_query_params.append((name, value))
                
                new_query = urllib.parse.urlencode(new_query_params)
                new_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                
                # Skicka begäran med payload
                start_time = time.time()
                response = self.session.get(new_url, cookies=cookies, timeout=10)
                end_time = time.time()
                
                response_time = end_time - start_time
                status_code = response.status_code
                content_length = len(response.text)
                
                # Kontrollera om det finns SQL-felmeddelanden
                has_sql_error = any(pattern in response.text for pattern in self.error_patterns)
                
                # Kontrollera om tidsfördröjning (time-based)
                is_time_based = False
                if 'SLEEP' in payload or 'PG_SLEEP' in payload or 'WAITFOR DELAY' in payload:
                    is_time_based = response_time > (time.time() - baseline_time + 0.5)
                
                # Kontrollera on boolean-based
                is_boolean_based = False
                if 'OR' in payload and content_length != baseline_length and status_code == baseline_status:
                    is_boolean_based = True
                
                if has_sql_error or is_time_based or is_boolean_based:
                    vulnerability = {
                        'parameter': param_name,
                        'payload': payload,
                        'url': new_url,
                        'original_url': original_url,
                        'response_time': response_time,
                        'has_sql_error': has_sql_error,
                        'is_time_based': is_time_based,
                        'is_boolean_based': is_boolean_based,
                        'status_code': status_code,
                        'content_length': content_length,
                        'baseline_length': baseline_length
                    }
                    results.append(vulnerability)
            except Exception as e:
                print(f"Error testing payload {payload} on parameter {param_name}: {str(e)}")
        
        return results
    
    def test_form(self, form, cookies=None):
        """Testa ett formulär för SQL injection"""
        results = []
        
        # Testa varje inputfält i formuläret
        for input_field in form['inputs']:
            field_name = input_field['name']
            
            for payload in self.payloads:
                try:
                    # Skapa formulärdata med injekterad payload
                    form_data = {}
                    for input_item in form['inputs']:
                        if input_item['name'] == field_name:
                            form_data[input_item['name']] = input_item['value'] + payload
                        else:
                            form_data[input_item['name']] = input_item['value']
                    
                    # Skicka formuläret med payload
                    start_time = time.time()
                    
                    if form['method'] == 'post':
                        response = self.session.post(form['action'], data=form_data, cookies=cookies, timeout=10)
                    else:
                        response = self.session.get(form['action'], params=form_data, cookies=cookies, timeout=10)
                    
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    # Kontrollera om det finns SQL-felmeddelanden
                    has_sql_error = any(pattern in response.text for pattern in self.error_patterns)
                    
                    # Kontrollera om tidsfördröjning (time-based)
                    is_time_based = False
                    if 'SLEEP' in payload or 'PG_SLEEP' in payload or 'WAITFOR DELAY' in payload:
                        is_time_based = response_time > 1.0
                    
                    if has_sql_error or is_time_based:
                        vulnerability = {
                            'form_action': form['action'],
                            'form_method': form['method'],
                            'field_name': field_name,
                            'payload': payload,
                            'has_sql_error': has_sql_error,
                            'is_time_based': is_time_based,
                            'response_time': response_time,
                            'status_code': response.status_code,
                            'content_length': len(response.text)
                        }
                        results.append(vulnerability)
                except Exception as e:
                    print(f"Error testing form field {field_name} with payload {payload}: {str(e)}")
        
        return results
    
    def start_scan(self, target_url, cookies=None):
        """Starta en scanning för SQL injections"""
        scan_id = self._generate_scan_id()
        scan_dir = os.path.join(self.storage_path, scan_id)
        os.makedirs(scan_dir, exist_ok=True)
        
        # Spara information om skanningen
        scan_info = {
            'scan_id': scan_id,
            'target_url': target_url,
            'start_time': time.time(),
            'status': 'running',
            'cookies_used': cookies is not None
        }
        
        with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
            json.dump(scan_info, f, indent=2)
        
        # Starta scanning i bakgrunden
        threading.Thread(target=self._run_scan, args=(scan_id, target_url, cookies)).start()
        
        return {
            'scan_id': scan_id,
            'status': 'started',
            'target_url': target_url
        }
    
    def _run_scan(self, scan_id, target_url, cookies=None):
        """Kör scanning i bakgrunden"""
        scan_dir = os.path.join(self.storage_path, scan_id)
        all_results = []
        debug_info = {
            'response_status': None,
            'params_found': 0,
            'forms_found': 0,
            'tests_performed': 0,
            'errors': []
        }
        
        try:
            # Försök hämta målsidan
            print(f"[SQLi Tester] Scanning {target_url} with scan_id {scan_id}")
            response = self.session.get(target_url, cookies=cookies, timeout=10)
            debug_info['response_status'] = response.status_code
            print(f"[SQLi Tester] Got response with status {response.status_code}, content length {len(response.text)}")
            
            # Extrahera alla URL-parametrar
            params = self.extract_parameters(target_url)
            debug_info['params_found'] = len(params)
            print(f"[SQLi Tester] Found {len(params)} URL parameters to test")
            
            # Extrahera alla formulär
            forms = self.extract_forms(response)
            debug_info['forms_found'] = len(forms)
            print(f"[SQLi Tester] Found {len(forms)} forms to test")
            
            # Om inga parametrar eller formulär hittades, försök utforska sidan
            if not params and not forms:
                print(f"[SQLi Tester] No forms or parameters found. Trying to explore the site...")
                links = self._extract_links(response)
                print(f"[SQLi Tester] Found {len(links)} links on the page")
                
                # Testa några av länkarna för att hitta paramatrar
                for link in links[:5]:  # Begränsa till 5 länkar för att undvika överbelastning
                    try:
                        print(f"[SQLi Tester] Exploring link: {link}")
                        link_response = self.session.get(link, cookies=cookies, timeout=10)
                        link_params = self.extract_parameters(link)
                        link_forms = self.extract_forms(link_response)
                        
                        if link_params:
                            print(f"[SQLi Tester] Found {len(link_params)} parameters in link {link}")
                            for param in link_params:
                                param_results = self.test_parameter(link, param['name'], param['value'], cookies)
                                debug_info['tests_performed'] += len(self.payloads)
                                all_results.extend(param_results)
                        
                        if link_forms:
                            print(f"[SQLi Tester] Found {len(link_forms)} forms in link {link}")
                            for form in link_forms:
                                form_results = self.test_form(form, cookies)
                                inputs_count = len(form.get('inputs', []))
                                debug_info['tests_performed'] += inputs_count * len(self.payloads)
                                all_results.extend(form_results)
                    except Exception as e:
                        error_msg = f"Error exploring link {link}: {str(e)}"
                        print(f"[SQLi Tester] {error_msg}")
                        debug_info['errors'].append(error_msg)
            
            # Testa URL-parametrar
            for param in params:
                print(f"[SQLi Tester] Testing parameter: {param['name']}")
                param_results = self.test_parameter(target_url, param['name'], param['value'], cookies)
                debug_info['tests_performed'] += len(self.payloads)
                all_results.extend(param_results)
            
            # Testa formulär
            for i, form in enumerate(forms):
                print(f"[SQLi Tester] Testing form {i+1}/{len(forms)}: {form.get('action', 'unknown')}")
                form_results = self.test_form(form, cookies)
                inputs_count = len(form.get('inputs', []))
                debug_info['tests_performed'] += inputs_count * len(self.payloads)
                all_results.extend(form_results)
            
            # Spara resultat och debug-information
            with open(os.path.join(scan_dir, 'results.json'), 'w') as f:
                json.dump(all_results, f, indent=2)
                
            with open(os.path.join(scan_dir, 'debug.json'), 'w') as f:
                json.dump(debug_info, f, indent=2)
            
            # Uppdatera status till slutförd
            with open(os.path.join(scan_dir, 'info.json'), 'r') as f:
                scan_info = json.load(f)
            
            scan_info['status'] = 'completed'
            scan_info['end_time'] = time.time()
            scan_info['duration'] = scan_info['end_time'] - scan_info['start_time']
            scan_info['results_count'] = len(all_results)
            scan_info['debug_info'] = debug_info
            
            with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                json.dump(scan_info, f, indent=2)
                
            print(f"[SQLi Tester] Scan completed for {target_url}. Found {len(all_results)} vulnerabilities after performing {debug_info['tests_performed']} tests.")
                
        except Exception as e:
            # Spara fel om något går fel
            with open(os.path.join(scan_dir, 'info.json'), 'r') as f:
                scan_info = json.load(f)
            
            scan_info['status'] = 'error'
            scan_info['error'] = str(e)
            scan_info['end_time'] = time.time()
            
            with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                json.dump(scan_info, f, indent=2)
    
    def get_status(self, scan_id):
        """Hämta status för en pågående skanning"""
        info_file = os.path.join(self.storage_path, scan_id, 'info.json')
        
        if not os.path.exists(info_file):
            return {'status': 'not_found'}
        
        try:
            with open(info_file, 'r') as f:
                scan_info = json.load(f)
            
            return scan_info
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Error reading scan info: {str(e)}'
            }
    
    def get_results(self, scan_id):
        """Hämta resultat för en slutförd scanning"""
        results_file = os.path.join(self.storage_path, scan_id, 'results.json')
        
        if not os.path.exists(results_file):
            return []
        
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            
            return results
        except Exception as e:
            return [{
                'error': f'Error reading results: {str(e)}'
            }]
    
    def get_summary(self, scan_id):
        """Hämta en sammanfattning av resultaten"""
        scan_info = self.get_status(scan_id)
        results = self.get_results(scan_id)
        
        if not results or 'error' in scan_info:
            return {
                'scan_id': scan_id,
                'status': scan_info.get('status', 'unknown'),
                'vulnerabilities_found': 0,
                'error': scan_info.get('error', None)
            }
        
        # Gruppera resultat per parameter
        vulnerabilities_by_param = {}
        
        for result in results:
            param_name = result.get('parameter', result.get('field_name', 'unknown'))
            if param_name not in vulnerabilities_by_param:
                vulnerabilities_by_param[param_name] = []
            vulnerabilities_by_param[param_name].append(result)
        
        # Sammanställ
        summary = {
            'scan_id': scan_id,
            'target_url': scan_info.get('target_url', 'unknown'),
            'status': scan_info.get('status', 'unknown'),
            'duration': scan_info.get('duration', 0),
            'vulnerabilities_found': len(results),
            'vulnerable_parameters': len(vulnerabilities_by_param),
            'parameters': []
        }
        
        for param_name, param_results in vulnerabilities_by_param.items():
            param_summary = {
                'name': param_name,
                'vulnerabilities': len(param_results),
                'error_based': any(r.get('has_sql_error', False) for r in param_results),
                'time_based': any(r.get('is_time_based', False) for r in param_results),
                'boolean_based': any(r.get('is_boolean_based', False) for r in param_results),
                'example_payloads': list(set(r.get('payload', '') for r in param_results))[:3]
            }
            summary['parameters'].append(param_summary)
        
        return summary
    



    def _identify_interesting_params(self, url, param_name):
        """Identifiera särskilt intressanta parametrar baserat på namn"""
        # Lista över parametrar som ofta är utsatta för SQL-injektioner
        high_risk_params = [
            'id', 'user_id', 'item_id', 'product_id', 'cat_id', 'category_id', 'pid',
            'uid', 'userid', 'user', 'username', 'login', 'email', 'search', 'query', 
            'q', 'keyword', 'keywords', 'name', 'p', 'page', 'book', 'article', 'post',
            'sid', 'session', 'select', 'where', 'order', 'sort', 'group', 'limit',
            'table', 'from', 'file', 'view', 'detail', 'details', 'show', 'list'
        ]
        
        # Lista över parametrar som kan innehålla SQL-kod
        sql_related_params = [
            'sql', 'query', 'db', 'database', 'data', 'field', 'column', 'table',
            'order', 'sort', 'group', 'limit', 'select', 'filter'
        ]
        
        # Normalisera parametern för jämförelse
        param_lower = param_name.lower()
        
        # Kontrollera om parametern är i någon av listorna
        is_high_risk = param_lower in high_risk_params
        is_sql_related = param_lower in sql_related_params
        
        # Kontrollera om parametern innehåller numeriska värden (ofta databasnycklar)
        param_value = self._get_param_value(url, param_name)
        is_numeric = param_value.isdigit()
        
        return {
            'is_high_risk': is_high_risk,
            'is_sql_related': is_sql_related,
            'is_numeric': is_numeric,
            'risk_score': (2 if is_high_risk else 0) + 
                        (1 if is_sql_related else 0) + 
                        (1 if is_numeric else 0)
        }

    def _get_param_value(self, url, param_name):
        """Extrahera värdet för en specifik parameter från en URL"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            if param_name in query_params:
                return query_params[param_name][0]
        except Exception:
            pass
        
        return ""

    def _prioritize_params(self, url, params):
        """Prioritera parametrar för testning baserat på deras sannolikhet att vara utsatta"""
        param_risks = []
        
        for param in params:
            risk_info = self._identify_interesting_params(url, param['name'])
            param_risks.append({
                'param': param,
                'risk_info': risk_info
            })
        
        # Sortera parametrarna enligt riskvärdering (högre risk först)
        param_risks.sort(key=lambda x: x['risk_info']['risk_score'], reverse=True)
        
        return [p['param'] for p in param_risks]



    def _extract_links(self, response):
        """Extrahera alla länkar från en HTML-sida med förbättrad parsing"""
        links = []
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Hitta alla a-taggar med href-attribut
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                
                # Hantera relativa länkar
                if href.startswith('/'):
                    # Absolut väg men relativ till domän
                    parsed_url = urllib.parse.urlparse(response.url)
                    absolute_url = f"{parsed_url.scheme}://{parsed_url.netloc}{href}"
                    links.append(absolute_url)
                elif href.startswith(('http://', 'https://')):
                    # Redan absolut URL
                    links.append(href)
                elif not href.startswith(('#', 'javascript:', 'mailto:')):
                    # Relativ till aktuell sida
                    absolute_url = urllib.parse.urljoin(response.url, href)
                    links.append(absolute_url)
            
            # Sök även efter enskilda URL:er i href, src, data-* attribut etc.
            for tag in soup.find_all(True):  # Hitta alla taggar
                for attr in tag.attrs:
                    if isinstance(tag[attr], str) and (
                        tag[attr].startswith('http') or 
                        tag[attr].startswith('/') or 
                        '?' in tag[attr]
                    ):
                        # Detta kan vara en URL med parametrar
                        url = tag[attr]
                        if url.startswith('/'):
                            parsed_url = urllib.parse.urlparse(response.url)
                            url = f"{parsed_url.scheme}://{parsed_url.netloc}{url}"
                        elif not url.startswith(('http://', 'https://')):
                            url = urllib.parse.urljoin(response.url, url)
                        
                        links.append(url)
            
            # Sök även efter URL:er i JavaScript-kod
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Använd regex för att hitta URL:er i script-taggar
                    url_patterns = [
                        r'["\'](https?://[^"\']+)["\']',  # "http://example.com/path"
                        r'["\'](/[^"\']*\?[^"\']+)["\']',  # "/path?param=value"
                        r'["\']((?:\w+/)+\w+\.\w+(?:\?\w+=\w+)?)["\']'  # "path/to/file.php?id=1"
                    ]
                    
                    for pattern in url_patterns:
                        for match in re.finditer(pattern, script.string):
                            url = match.group(1)
                            if url.startswith('/'):
                                parsed_url = urllib.parse.urlparse(response.url)
                                url = f"{parsed_url.scheme}://{parsed_url.netloc}{url}"
                            elif not url.startswith(('http://', 'https://')):
                                url = urllib.parse.urljoin(response.url, url)
                            
                            links.append(url)
            
            # Deduplikera länkar
            return list(set(links))
        except Exception as e:
            self.logger.error(f"Error extracting links: {str(e)}")
            return []



    def get_enhanced_summary(self, scan_id):
        """Ge en mer detaljerad sammanfattning av resultaten"""
        scan_info = self.get_status(scan_id)
        results = self.get_results(scan_id)
        
        if not results or 'error' in scan_info:
            return {
                'scan_id': scan_id,
                'status': scan_info.get('status', 'unknown'),
                'vulnerabilities_found': 0,
                'error': scan_info.get('error', None)
            }
        
        # Gruppera resultat per parameter och vulnerability typer
        vulnerabilities_by_param = {}
        vulnerability_types = {
            'error_based': 0,
            'time_based': 0,
            'boolean_based': 0
        }
        
        # Separera GET och POST resultat
        get_vulnerabilities = []
        post_vulnerabilities = []
        
        for result in results:
            # Identifiera metoden (GET eller POST)
            method = result.get('method', 'GET')  # Default till GET om inget anges
            
            if method == 'POST':
                post_vulnerabilities.append(result)
            else:
                get_vulnerabilities.append(result)
            
            # Gruppera enligt parameter
            param_name = result.get('parameter', result.get('field_name', 'unknown'))
            if param_name not in vulnerabilities_by_param:
                vulnerabilities_by_param[param_name] = []
            vulnerabilities_by_param[param_name].append(result)
            
            # Räkna typer av sårbarheter
            if result.get('has_sql_error', False):
                vulnerability_types['error_based'] += 1
            if result.get('is_time_based', False):
                vulnerability_types['time_based'] += 1
            if result.get('is_boolean_based', False):
                vulnerability_types['boolean_based'] += 1
        
        # Hämta information om ZAP-baserad scanning
        urls_processed = scan_info.get('processed_urls', 0)
        total_urls = scan_info.get('total_urls', 0)
        
        # Generera sammanfattning
        summary = {
            'scan_id': scan_id,
            'target_url': scan_info.get('target_url', scan_info.get('urls_to_test', [{}])[0].get('site', 'unknown') if scan_info.get('urls_to_test') else 'unknown'),
            'status': scan_info.get('status', 'unknown'),
            'start_time': scan_info.get('start_time', 0),
            'end_time': scan_info.get('end_time', 0),
            'duration': scan_info.get('duration', 0),
            'urls': {
                'processed': urls_processed,
                'total': total_urls,
                'percent_complete': int((urls_processed / total_urls * 100) if total_urls > 0 else 0)
            },
            'vulnerabilities': {
                'total': len(results),
                'by_method': {
                    'get': len(get_vulnerabilities),
                    'post': len(post_vulnerabilities)
                },
                'by_type': vulnerability_types,
                'unique_parameters': len(vulnerabilities_by_param)
            },
            'parameters': []
        }
        
        # Lägga till detaljerad information om varje sårbar parameter
        for param_name, param_results in vulnerabilities_by_param.items():
            param_summary = {
                'name': param_name,
                'vulnerabilities': len(param_results),
                'error_based': any(r.get('has_sql_error', False) for r in param_results),
                'time_based': any(r.get('is_time_based', False) for r in param_results),
                'boolean_based': any(r.get('is_boolean_based', False) for r in param_results),
                'methods': list(set(r.get('method', 'GET') for r in param_results)),
                'urls': list(set(r.get('url', '') for r in param_results))[:3],  # Begränsa till 3 URL:er
                'example_payloads': list(set(r.get('payload', '') for r in param_results))[:3]
            }
            summary['parameters'].append(param_summary)
        
        # Sortera parametrarna efter antal sårbarheter (högst först)
        summary['parameters'].sort(key=lambda x: x['vulnerabilities'], reverse=True)
        
        return summary



    def test_form_parameters(self, url, form_params, cookies=None):
        """Testa formulärparametrar för SQL injection"""
        results = []
        
        # Omvandla form_params från strängformat till dictionary
        form_data = {}
        for param_str in form_params:
            if '=' in param_str:
                name, value = param_str.split('=', 1)
                form_data[name] = value
        
        # Om inga parametrar hittades, returnera tomt resultat
        if not form_data:
            return results
        
        # Skapa baslinjerespons för jämförelse
        try:
            baseline_response = self.session.post(url, data=form_data, cookies=cookies, timeout=5)
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
            baseline_time = time.time()
        except Exception as e:
            print(f"Error getting baseline response for POST: {str(e)}")
            return results
        
        # Testa varje parameter
        for param_name, param_value in form_data.items():
            # Prioritera parametern baserat på namn
            risk_info = self._identify_interesting_params(url, param_name)
            if risk_info['risk_score'] < 1:
                # Skippa parametrar med låg risk om vi har för många att testa
                if len(form_data) > len(self.payloads) / 2:
                    continue
            
            # Testa varje SQL-injektionspayload
            for payload in self.payloads:
                try:
                    # Skapa en kopia av form_data och modifiera den specifika parametern
                    modified_data = form_data.copy()
                    modified_data[param_name] = param_value + payload
                    
                    # Skicka begäran med payload
                    start_time = time.time()
                    response = self.session.post(url, data=modified_data, cookies=cookies, timeout=10)
                    end_time = time.time()
                    
                    response_time = end_time - start_time
                    status_code = response.status_code
                    content_length = len(response.text)
                    
                    # Kontrollera om det finns SQL-felmeddelanden
                    has_sql_error = any(pattern in response.text for pattern in self.error_patterns)
                    
                    # Kontrollera om tidsfördröjning (time-based)
                    is_time_based = False
                    if 'SLEEP' in payload or 'PG_SLEEP' in payload or 'WAITFOR DELAY' in payload:
                        is_time_based = response_time > (time.time() - baseline_time + 0.5)
                    
                    # Kontrollera om boolean-based
                    is_boolean_based = False
                    if 'OR' in payload and content_length != baseline_length and status_code == baseline_status:
                        is_boolean_based = True
                    
                    if has_sql_error or is_time_based or is_boolean_based:
                        vulnerability = {
                            'parameter': param_name,
                            'payload': payload,
                            'url': url,
                            'method': 'POST',
                            'original_data': form_data,
                            'response_time': response_time,
                            'has_sql_error': has_sql_error,
                            'is_time_based': is_time_based,
                            'is_boolean_based': is_boolean_based,
                            'status_code': status_code,
                            'content_length': content_length,
                            'baseline_length': baseline_length
                        }
                        results.append(vulnerability)
                except Exception as e:
                    print(f"Error testing POST payload {payload} on parameter {param_name}: {str(e)}")
        
        return results

    def scan_from_zap_results(self, zap, target_site=None, max_urls=50, cookies=None):
        """
        Startar SQL-injectionstester baserat på ZAP-resultat med förbättrad sökning efter URL:er
        """
        try:
            self.logger.info("Starting scan from ZAP results")
            
            # Kontrollera om ZAP är tillgänglig
            if not zap.is_available():
                self.logger.error("ZAP is not available")
                return {"error": "ZAP is not available", "status": "failed"}
            
            # Direkta HTTP-anrop för att få URL:er
            import requests
            sites_url = f"http://{zap.host}:{zap.port}/JSON/core/view/sites/"
            try:
                sites_response = requests.get(
                    sites_url,
                    params={'apikey': zap.api_key},
                    timeout=5
                )
                
                if sites_response.status_code != 200:
                    self.logger.error(f"Failed to get sites from ZAP API: {sites_response.status_code}")
                    return {"error": "Failed to get sites from ZAP API", "status": "failed"}
                    
                sites_data = sites_response.json()
                sites = sites_data.get('sites', [])
                
                if not sites:
                    self.logger.warning("No sites found in ZAP")
                    return {"error": "No sites found in ZAP", "status": "failed"}
            except Exception as e:
                self.logger.error(f"Error getting sites from ZAP API: {str(e)}")
                return {"error": f"Error getting sites from ZAP API: {str(e)}", "status": "failed"}
            
            # Filtrera sites om target_site anges
            if target_site:
                self.logger.info(f"Filtering sites by target: {target_site}")
                
                # Normalisera target_site för bättre matchning
                domain = self._extract_domain_or_ip(target_site)
                
                filtered_sites = []
                for site in sites:
                    site_domain = self._extract_domain_or_ip(site)
                    if domain == site_domain or domain in site or site_domain in domain:
                        filtered_sites.append(site)
                        self.logger.info(f"Match found for {target_site}: {site}")
                
                if not filtered_sites:
                    self.logger.warning(f"Target site {target_site} not found in ZAP sites.")
                    self.logger.info(f"Available sites in ZAP: {', '.join(sites)}")
                    
                    # Använd alla sites istället
                    self.logger.info(f"Proceeding with all available sites instead.")
                    filtered_sites = sites
                    
                sites = filtered_sites
            
            self.logger.info(f"Found {len(sites)} sites in ZAP")
            
            # Samla alla URL:er med parametrar från ZAP
            urls_to_test = []
            
            # Använd både ZAP History och URLs för att vara säker på att hitta alla URL:er
            for site in sites:
                try:
                    # Metod 1: Hämta meddelanden för denna site
                    messages_url = f"http://{zap.host}:{zap.port}/JSON/core/view/messages/"
                    messages_response = requests.get(
                        messages_url,
                        params={
                            'apikey': zap.api_key,
                            'baseurl': site,
                            'start': '0',
                            'count': '1000'  # Hämta många meddelanden
                        },
                        timeout=10
                    )
                    
                    if messages_response.status_code == 200:
                        messages_data = messages_response.json()
                        messages = messages_data.get('messages', [])
                        
                        self.logger.info(f"Found {len(messages)} messages for site {site}")
                        
                        # Loopa igenom alla meddelanden och samla URL:er med parametrar
                        for message in messages:
                            if not isinstance(message, dict):
                                continue
                                
                            url = message.get('url', '')
                            method = message.get('method', '')
                            
                            # Skippa om varken GET-parameter eller POST-formulär
                            if not ('?' in url or method == 'POST'):
                                continue
                            
                            # Skapa unik identifierare för denna URL
                            url_key = f"{method}:{url}"
                            
                            # Undvik duplicat-URL:er
                            if url_key in [u.get('url_key') for u in urls_to_test]:
                                continue
                            
                            # Analysera URL:en för parametrar
                            has_params = '?' in url
                            
                            # Analysera formulärdata för POST-anrop
                            form_params = []
                            if method == 'POST':
                                request_body = message.get('requestBody', '')
                                if request_body:
                                    # Försök tolka formulärdata
                                    if '&' in request_body and '=' in request_body:
                                        form_params = request_body.split('&')
                                    elif request_body.strip().startswith('{') and request_body.strip().endswith('}'):
                                        try:
                                            json_data = json.loads(request_body)
                                            for key, value in json_data.items():
                                                if isinstance(value, str):
                                                    form_params.append(f"{key}={value}")
                                        except:
                                            pass
                            
                            # Endast inkludera URL:er med parametrar eller formulärdata
                            if has_params or form_params:
                                # Prioritera URL:er med SQL-relaterade alerts
                                has_sql_alert = False
                                for alert in message.get('alerts', []):
                                    if isinstance(alert, dict) and 'sql' in alert.get('name', '').lower():
                                        has_sql_alert = True
                                        break
                                
                                urls_to_test.append({
                                    'url': url,
                                    'url_key': url_key,
                                    'method': method,
                                    'form_params': form_params,
                                    'site': site,
                                    'has_sql_alert': has_sql_alert,
                                    'priority': 2 if has_sql_alert else (1 if method == 'POST' else 0)
                                })
                    
                    # Metod 2: Använd URL View för att hitta alla URL:er
                    urls_url = f"http://{zap.host}:{zap.port}/JSON/core/view/urls/"
                    urls_response = requests.get(
                        urls_url,
                        params={
                            'apikey': zap.api_key,
                            'baseurl': site
                        },
                        timeout=5
                    )
                    
                    if urls_response.status_code == 200:
                        urls_data = urls_response.json()
                        urls = urls_data.get('urls', [])
                        
                        self.logger.info(f"Found {len(urls)} URLs for site {site}")
                        
                        # Loopa igenom alla URL:er och hitta dem med parametrar
                        for url in urls:
                            if '?' in url:
                                # Skapa unik identifierare för denna URL
                                url_key = f"GET:{url}"
                                
                                # Undvik duplicat-URL:er
                                if url_key in [u.get('url_key') for u in urls_to_test]:
                                    continue
                                    
                                urls_to_test.append({
                                    'url': url,
                                    'url_key': url_key,
                                    'method': 'GET',
                                    'form_params': [],
                                    'site': site,
                                    'has_sql_alert': False,
                                    'priority': 0
                                })
                    
                    # Begränsa antalet URL:er
                    if len(urls_to_test) >= max_urls:
                        break
                except Exception as e:
                    self.logger.error(f"Error processing site {site}: {str(e)}")
            
            # Om vi fortfarande inte har några URL:er, återvänd till direkttestning
            if not urls_to_test:
                self.logger.warning("No URLs with parameters found in ZAP results")
                
                # Om en specifik target_site angavs, testa den direkt
                if target_site:
                    self.logger.info(f"Testing target site directly: {target_site}")
                    scan_id = self._generate_scan_id()
                    scan_dir = os.path.join(self.storage_path, scan_id)
                    os.makedirs(scan_dir, exist_ok=True)
                    
                    # Spara information om skanningen
                    scan_info = {
                        'scan_id': scan_id,
                        'target_url': target_site,
                        'start_time': time.time(),
                        'status': 'running',
                        'cookies_used': cookies is not None,
                        'direct_test': True,
                        'scan_type': 'direct',
                        'zap_search_failed': True
                    }
                    
                    with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                        json.dump(scan_info, f, indent=2)
                    
                    # Starta direktskanning i bakgrunden
                    threading.Thread(
                        target=self._run_direct_scan,
                        args=(scan_id, target_site, cookies)
                    ).start()
                    
                    return {
                        'scan_id': scan_id,
                        'status': 'started',
                        'direct_test': True,
                        'message': 'No URLs with parameters found in ZAP. Starting direct test instead.'
                    }
                else:
                    return {"error": "No URLs with parameters found in ZAP", "status": "no_urls"}
            
            # Sortera URL:er efter prioritet (högre prioritet först)
            urls_to_test.sort(key=lambda x: x.get('priority', 0), reverse=True)
            
            self.logger.info(f"Collected {len(urls_to_test)} URLs with parameters to test, sorted by priority")
            
            # Logga detaljer om URL:er som ska testas
            for i, url_info in enumerate(urls_to_test[:10]):
                self.logger.debug(f"URL {i+1}: {url_info['method']} {url_info['url']}")
                self.logger.debug(f"  - Priority: {url_info.get('priority', 0)}")
                self.logger.debug(f"  - Has SQL alert: {url_info.get('has_sql_alert', False)}")
                if url_info.get('form_params'):
                    self.logger.debug(f"  - Form parameters: {len(url_info['form_params'])}")
            
            if len(urls_to_test) > 10:
                self.logger.debug(f"...and {len(urls_to_test) - 10} more URLs")
            
            # Starta scanning för varje URL
            scan_id = self._generate_scan_id()
            scan_dir = os.path.join(self.storage_path, scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            
            # Spara information om skanningen
            scan_info = {
                'scan_id': scan_id,
                'urls_to_test': urls_to_test,
                'start_time': time.time(),
                'status': 'running',
                'cookies_used': cookies is not None,
                'zap_site_count': len(sites),
                'target_site': target_site,
                'total_urls': len(urls_to_test),
                'processed_urls': 0
            }
            
            with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                json.dump(scan_info, f, indent=2)
            
            # Starta scanning i bakgrunden
            threading.Thread(
                target=self._run_zap_based_scan,
                args=(scan_id, urls_to_test, cookies)
            ).start()
            
            self.logger.info(f"Started ZAP-based scan with ID: {scan_id}")
            self.logger.info(f"Test results will be stored in: {scan_dir}")
            
            # Skapa en URL för att visa loggfilen
            log_file_path = self.logger.get_log_file_path()
            log_url = f"/view-log?file={os.path.basename(log_file_path)}"
            
            return {
                'scan_id': scan_id,
                'status': 'started',
                'urls_count': len(urls_to_test),
                'sites': sites[:5],  # Returnera bara de första 5 för enkel översikt
                'log_url': log_url  # URL för att visa loggfilen
            }
        except Exception as e:
            self.logger.error(f"Error in scan_from_zap_results: {str(e)}", exc_info=True)
            return {"error": str(e), "status": "error"}

    def _run_zap_based_scan(self, scan_id, urls_to_test, cookies=None):
        """Kör scanning baserat på ZAP-data i bakgrunden"""
        scan_dir = os.path.join(self.storage_path, scan_id)
        all_results = []
        processed_urls = 0
        total_urls = len(urls_to_test)
        
        self.logger.info(f"Starting ZAP-based scan with ID: {scan_id}")
        self.logger.info(f"Total URLs to test: {total_urls}")
        
        try:
            # Uppdatera status
            with open(os.path.join(scan_dir, 'info.json'), 'r') as f:
                scan_info = json.load(f)
            
            scan_info['total_urls'] = total_urls
            scan_info['processed_urls'] = 0
            
            with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                json.dump(scan_info, f, indent=2)
                
            self.logger.info("Scan status file updated with initial info")
            
            # Börja testa varje URL
            for url_info in urls_to_test:
                url = url_info['url']
                method = url_info['method']
                form_params = url_info.get('form_params', [])
                
                print(f"[SQLi Tester] Testing URL from ZAP: {method} {url}")
                
                try:
                    # För GET-anrop, testa URL-parametrar
                    if '?' in url:
                        # Extrahera parametrar från URL
                        params = self.extract_parameters(url)
                        
                        # Prioritera parametrar baserat på risk
                        prioritized_params = self._prioritize_params(url, params)
                        
                        print(f"[SQLi Tester] Found {len(params)} parameters in URL {url}, testing in priority order")
                        
                        # Testa varje parameter i prioritetsordning
                        for param in prioritized_params:
                            try:
                                param_name = param['name']
                                param_value = param['value']
                                
                                # Logg för hög risk parametrar
                                risk_info = self._identify_interesting_params(url, param_name)
                                if risk_info['risk_score'] >= 2:
                                    print(f"[SQLi Tester] Testing high-risk parameter: {param_name} (risk score: {risk_info['risk_score']})")
                                
                                # Utför testning
                                param_results = self.test_parameter(url, param_name, param_value, cookies)
                                
                                # Om vi hittade sårbarheter, logga det
                                if param_results:
                                    print(f"[SQLi Tester] Found {len(param_results)} vulnerabilities in parameter {param_name}")
                                    
                                all_results.extend(param_results)
                            except Exception as e:
                                print(f"Error testing parameter {param['name']} in {url}: {str(e)}")
                    
                    # För POST-anrop, testa formulärparametrar
                    if method == 'POST' and form_params:
                        print(f"[SQLi Tester] Testing POST form with {len(form_params)} parameters for {url}")
                        
                        try:
                            # Testa alla formulärparametrar
                            form_results = self.test_form_parameters(url, form_params, cookies)
                            
                            if form_results:
                                print(f"[SQLi Tester] Found {len(form_results)} vulnerabilities in POST form parameters")
                                
                            all_results.extend(form_results)
                        except Exception as e:
                            print(f"Error testing POST form parameters for {url}: {str(e)}")
                except Exception as e:
                    print(f"[SQLi Tester] Error processing URL {url}: {str(e)}")
                
                # Uppdatera framsteg
                processed_urls += 1
                if processed_urls % 5 == 0 or processed_urls == total_urls:
                    # Uppdatera status
                    with open(os.path.join(scan_dir, 'info.json'), 'r') as f:
                        scan_info = json.load(f)
                    
                    scan_info['processed_urls'] = processed_urls
                    scan_info['progress_percent'] = int((processed_urls / total_urls) * 100)
                    
                    with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                        json.dump(scan_info, f, indent=2)
            
            # Spara alla resultat
            with open(os.path.join(scan_dir, 'results.json'), 'w') as f:
                json.dump(all_results, f, indent=2)
            
            # Uppdatera status till slutförd
            with open(os.path.join(scan_dir, 'info.json'), 'r') as f:
                scan_info = json.load(f)
            
            scan_info['status'] = 'completed'
            scan_info['end_time'] = time.time()
            scan_info['duration'] = scan_info['end_time'] - scan_info['start_time'] 
            scan_info['results_count'] = len(all_results)
            
            with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                json.dump(scan_info, f, indent=2)
                
            print(f"[SQLi Tester] ZAP-based scan completed. Found {len(all_results)} vulnerabilities.")
                
        except Exception as e:
            # Spara fel om något går fel
            error_msg = str(e)
            print(f"[SQLi Tester] Error in ZAP-based scan: {error_msg}")
            
            with open(os.path.join(scan_dir, 'info.json'), 'r') as f:
                scan_info = json.load(f)
            
            scan_info['status'] = 'error'
            scan_info['error'] = error_msg
            scan_info['end_time'] = time.time()
            
            with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                json.dump(scan_info, f, indent=2)
        
    def _parse_cookies(self, cookies_str):
        """Parsa cookies-sträng till dictionary"""
        if not cookies_str:
            return None
            
        cookies_dict = {}
        try:
            # Dela upp cookies-strängen på semikolon
            cookie_parts = cookies_str.split(';')
            
            for part in cookie_parts:
                if '=' in part:
                    name, value = part.strip().split('=', 1)
                    cookies_dict[name.strip()] = value.strip()
            
            self.logger.info(f"Parsed {len(cookies_dict)} cookies from string")
            return cookies_dict
        except Exception as e:
            self.logger.error(f"Error parsing cookies: {str(e)}")
            # Returnera original-strängen som ett dictionary med en enda cookie
            # Detta är en fallback om parsningen misslyckas
            return {"raw_cookie": cookies_str}
    
    
    def _run_direct_scan(self, scan_id, target_url, cookies=None):
        """Kör en direkt SQL injection scanning utan ZAP-integration"""
        scan_dir = os.path.join(self.storage_path, scan_id)
        all_results = []
        
        self.logger.info(f"Starting direct SQL injection scan for {target_url}")
        self.logger.info(f"Scan ID: {scan_id}, Cookies provided: {cookies is not None}")
        
        try:
            # Parsa cookies om de är i strängformat
            cookies_dict = None
            if cookies:
                if isinstance(cookies, str):
                    cookies_dict = self._parse_cookies(cookies)
                    self.logger.debug(f"Parsed cookies dictionary with {len(cookies_dict)} entries")
                else:
                    cookies_dict = cookies
            
            # Uppdatera status
            with open(os.path.join(scan_dir, 'info.json'), 'r') as f:
                scan_info = json.load(f)
            
            # Förbered testning av URL
            self.logger.info(f"Preparing to test {target_url} for SQL injections")
            
            # Första steget: Request för att se om sidan finns och för att hämta eventuella länkar
            try:
                self.logger.info(f"Sending initial request to {target_url}")
                initial_response = self.session.get(target_url, cookies=cookies_dict, timeout=10)
                self.logger.info(f"Initial response status: {initial_response.status_code}")
                
                # Extrahera länkar för att hitta URL:er att testa
                self.logger.info(f"Extracting links from initial response")
                all_links = self._extract_links(initial_response)
                self.logger.info(f"Found {len(all_links)} links on page")
                
                # Logga de första 10 länkarna
                for i, link in enumerate(all_links[:10]):
                    self.logger.debug(f"Link {i+1}: {link}")
                
                # Hitta länkar med parametrar
                links_with_params = [link for link in all_links if '?' in link]
                self.logger.info(f"Found {len(links_with_params)} links with parameters")
                
                # Extrahera eventuella formulär
                self.logger.info(f"Extracting forms from initial response")
                forms = self.extract_forms(initial_response)
                self.logger.info(f"Found {len(forms)} forms on page")
                
                # Uppdatera status med antal URL:er att testa
                scan_info['total_urls'] = len(links_with_params) + len(forms)
                scan_info['processed_urls'] = 0
                scan_info['links_with_params'] = len(links_with_params)
                scan_info['forms'] = len(forms)
                
                with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                    json.dump(scan_info, f, indent=2)
                    
                # Testa varje URL med parametrar
                processed_urls = 0
                total_to_process = scan_info['total_urls']
                
                # Om ingen URL med parametrar hittades, testa huvudsidan
                if not links_with_params and not forms:
                    self.logger.warning(f"No parameters or forms found. Testing main URL anyway.")
                    
                    # Försök extrahera en parameter från URL:en
                    parsed_url = urllib.parse.urlparse(target_url)
                    if parsed_url.query:
                        self.logger.info(f"Found query parameters in main URL: {parsed_url.query}")
                        params = self.extract_parameters(target_url)
                        
                        # Testa varje parameter
                        for param in params:
                            self.logger.info(f"Testing parameter: {param['name']}")
                            try:
                                param_results = self.test_parameter(target_url, param['name'], param['value'], cookies_dict)
                                all_results.extend(param_results)
                                
                                if param_results:
                                    self.logger.info(f"Found {len(param_results)} vulnerabilities in parameter {param['name']}")
                            except Exception as e:
                                self.logger.error(f"Error testing parameter {param['name']}: {str(e)}")
                    else:
                        self.logger.info(f"No parameters in main URL. Testing some common parameters.")
                        # Testa några vanliga parametrar
                        common_params = ['id', 'page', 'search', 'q', 'user', 'product']
                        test_url = target_url
                        if not test_url.endswith('/'):
                            test_url += '/'
                            
                        # Lägg till ? om det inte finns
                        if '?' not in test_url:
                            test_url += '?'
                        elif not test_url.endswith('?') and not test_url.endswith('&'):
                            test_url += '&'
                        
                        for param in common_params:
                            try:
                                param_url = f"{test_url}{param}=1"
                                self.logger.info(f"Testing common parameter: {param} with URL {param_url}")
                                param_results = self.test_parameter(param_url, param, "1", cookies_dict)
                                all_results.extend(param_results)
                                
                                if param_results:
                                    self.logger.info(f"Found {len(param_results)} vulnerabilities in parameter {param}")
                            except Exception as e:
                                self.logger.error(f"Error testing common parameter {param}: {str(e)}")
                
                # Testa varje länk med parametrar
                for i, link in enumerate(links_with_params):
                    self.logger.info(f"Testing link {i+1}/{len(links_with_params)}: {link}")
                    try:
                        # Extrahera parametrar från URL:en
                        params = self.extract_parameters(link)
                        
                        # Testa varje parameter
                        for param in params:
                            self.logger.info(f"Testing parameter: {param['name']}")
                            try:
                                param_results = self.test_parameter(link, param['name'], param['value'], cookies_dict)
                                all_results.extend(param_results)
                                
                                if param_results:
                                    self.logger.info(f"Found {len(param_results)} vulnerabilities in parameter {param['name']}")
                            except Exception as e:
                                self.logger.error(f"Error testing parameter {param['name']}: {str(e)}")
                        
                        # Uppdatera framsteg
                        processed_urls += 1
                        scan_info['processed_urls'] = processed_urls
                        scan_info['progress_percent'] = int((processed_urls / total_to_process) * 100) if total_to_process > 0 else 100
                        
                        with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                            json.dump(scan_info, f, indent=2)
                    except Exception as e:
                        self.logger.error(f"Error processing link {link}: {str(e)}")
                
                # Testa varje formulär
                for i, form in enumerate(forms):
                    self.logger.info(f"Testing form {i+1}/{len(forms)}: {form.get('action', 'unknown')}")
                    try:
                        # Testa formuläret
                        form_results = self.test_form(form, cookies_dict)
                        all_results.extend(form_results)
                        
                        if form_results:
                            self.logger.info(f"Found {len(form_results)} vulnerabilities in form")
                        
                        # Uppdatera framsteg
                        processed_urls += 1
                        scan_info['processed_urls'] = processed_urls
                        scan_info['progress_percent'] = int((processed_urls / total_to_process) * 100) if total_to_process > 0 else 100
                        
                        with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                            json.dump(scan_info, f, indent=2)
                    except Exception as e:
                        self.logger.error(f"Error testing form: {str(e)}")
                
            except Exception as req_e:
                self.logger.error(f"Error during initial request: {str(req_e)}")
                # Om initiala anropet misslyckas, testa bara huvudsidan direkt
                self.logger.info(f"Testing only main URL directly")
                
                # Försök med några vanliga parametrar
                common_params = ['id', 'page', 'search', 'q', 'user', 'product']
                test_url = target_url
                if not test_url.endswith('/'):
                    test_url += '/'
                    
                # Lägg till ? om det inte finns
                if '?' not in test_url:
                    test_url += '?'
                elif not test_url.endswith('?') and not test_url.endswith('&'):
                    test_url += '&'
                
                for param in common_params:
                    try:
                        param_url = f"{test_url}{param}=1"
                        self.logger.info(f"Testing common parameter: {param} with URL {param_url}")
                        param_results = self.test_parameter(param_url, param, "1", cookies_dict)
                        all_results.extend(param_results)
                        
                        if param_results:
                            self.logger.info(f"Found {len(param_results)} vulnerabilities in parameter {param}")
                    except Exception as e:
                        self.logger.error(f"Error testing common parameter {param}: {str(e)}")
            
            # Spara alla resultat
            with open(os.path.join(scan_dir, 'results.json'), 'w') as f:
                json.dump(all_results, f, indent=2)
            
            # Uppdatera status till slutförd
            with open(os.path.join(scan_dir, 'info.json'), 'r') as f:
                scan_info = json.load(f)
            
            scan_info['status'] = 'completed'
            scan_info['end_time'] = time.time()
            scan_info['duration'] = scan_info['end_time'] - scan_info['start_time']
            scan_info['results_count'] = len(all_results)
            
            with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                json.dump(scan_info, f, indent=2)
                
            self.logger.info(f"Direct scan completed for {target_url}. Found {len(all_results)} vulnerabilities.")
                
        except Exception as e:
            # Spara fel om något går fel
            self.logger.error(f"Error in direct scan: {str(e)}", exc_info=True)
            
            with open(os.path.join(scan_dir, 'info.json'), 'r') as f:
                scan_info = json.load(f)
            
            scan_info['status'] = 'error'
            scan_info['error'] = str(e)
            scan_info['end_time'] = time.time()
            
            with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                json.dump(scan_info, f, indent=2)

    def _extract_domain_or_ip(self, url):
        """Extrahera domännamn eller IP från en URL"""
        try:
            # Normalisera URL:en genom att ta bort avslutande slash
            if url.endswith('/'):
                url = url[:-1]
                
            # Försök först med vanlig URL-parsning
            parsed_url = urllib.parse.urlparse(url)
            
            # Om URL:en saknar schema, lägg till ett tillfälligt
            if not parsed_url.scheme and not url.startswith('//'):
                parsed_url = urllib.parse.urlparse(f"http://{url}")
                
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