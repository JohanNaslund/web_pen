from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
import os
import json
import time
import subprocess  # Lägg till denna import
import glob  # För att söka efter filer
import uuid  # För att generera unika ID:n
from urllib.parse import urlparse  # För att hantera URL:er
from datetime import datetime  # För tidsstämplar
from modules.zap_controller import ZAPController
from modules.session_manager import SessionManager
from modules.report_generator import ReportGenerator
from flask_wtf.csrf import CSRFProtect, generate_csrf
import threading
import uuid
import json
from bs4 import BeautifulSoup
import re
import logging, base64
import requests, psutil
import urllib.parse
import traceback

from modules.sql_injection_tester import SQLInjectionTester

app = Flask(__name__)
app.secret_key = os.urandom(24)  # För sessionshantering
csrf = CSRFProtect(app)

ZAP_API_KEY = 'changeme123'
ZAP_HOST = '192.168.2.110'  # eller IP-adressen där ZAP körs
ZAP_API_PORT = 8080
ZAP_PROXY_PORT = 8080
scan_status_lock = threading.Lock()
scan_statuses = {}  # Dictionary för att lagra status för alla skanningar
app.config['RESULTS_DIR'] = './data'

# Initiera ZAP-controller med korrekt konfiguration
zap = ZAPController(
    api_key=ZAP_API_KEY,
    host=ZAP_HOST,
    port=ZAP_API_PORT
)
print(f"ZAPController initialized: {zap}")
print(f"ZAP available: {zap.is_available()}")
#print(f"ZAP version: {zap.core.version if zap.is_available() else 'N/A'}")

sql_tester = SQLInjectionTester(storage_path='./data/sql_tester')
session_manager = SessionManager(storage_path='./data/sessions')
report_generator = ReportGenerator(storage_path='./data/reports')

@app.route('/report')
def report():
    """Rapportvy med förbättrad sårbarhetsvisning"""
    # Kontrollera om det finns ett mål-URL i sessionen
    target_url = session.get('target_url', '')
    if not target_url:
        flash("Inget mål-URL konfigurerat. Vänligen konfigurera ett mål först.", "warning")
        return redirect(url_for('target'))
    
    # Generera ett rapport-ID
    report_id = str(uuid.uuid4())
    
    return render_template(
        'report.html',
        report_id=report_id,
        target_url=target_url,
        debug_mode=False  # Pass this explicitly
    )

@app.route('/scan-zap-urls')
def scan_zap_urls():
    """Starta SQL injection-scanning på URL:er hämtade från ZAP"""
    # Kontrollera om ZAP är tillgänglig
    if not zap.is_available():
        return jsonify({'error': 'ZAP is not available'}), 500
    
    # Få målsite från parametrar (valfritt)
    target_site = request.args.get('site')
    
    # Få max-url-parametern (valfritt, standard är 50)
    max_urls = int(request.args.get('max', 50))
    
    # Få sessionscookies om tillgängliga
    session_name = request.args.get('session')
    cookies = None
    
    if session_name:
        session_data = session_manager.load_cookies(session_name)
        if session_data:
            cookies = session_data.get('cookies')
    
    # Starta scanningen från ZAP-data
    result = sql_tester.scan_from_zap_results(zap, target_site, max_urls, cookies)
    
    return jsonify(result)

@app.route('/test-sql-injection')
def test_sql_injection():
    """Testrutt för SQL injection-testern"""
    target_url = request.args.get('url', 'http://192.168.2.144:3000')
    
    # Lägg till en testparameter om ingen finns
    if '?' not in target_url:
        target_url = target_url + '?id=1'
    
    # Starta en testscanning
    result = sql_tester.start_scan(target_url)
    scan_id = result.get('scan_id')
    
    # Vänta kort stund för att låta scanningen börja
    time.sleep(2)
    
    # Hämta status
    status = sql_tester.get_status(scan_id)
    
    return jsonify({
        'start_result': result,
        'status': status,
        'note': 'Scanning körs i bakgrunden. Använd /api/sqlmap-status/{} för att kontrollera status.'.format(scan_id),
        'debug_url': f'/sql-debug/{scan_id}',
        'results_url': f'/api/sqlmap-results/{scan_id}'
    })

@app.route('/test-zap-api')
def test_zap_api():
    """Testar ZAP API-anslutningen"""
    try:
        version = zap.zap.core.version
        sites = zap.zap.core.sites
        return jsonify({
            'status': 'connected',
            'version': version,
            'sites': sites
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        })

# Lägg till en API-endpoint för att kontrollera ZAP-status
@app.route('/api/zap-status')
def api_zap_status():
    """API-endpoint för att kontrollera ZAP-status"""
    try:
        version = zap.zap.core.version
        return jsonify({
            'status': 'available',
            'version': version
        })
    except Exception as e:
        return jsonify({
            'status': 'unavailable',
            'error': str(e)
        }), 500

session_manager = SessionManager(storage_path='./data/sessions')
report_generator = ReportGenerator(storage_path='./data/reports')



@app.route('/api/extract-cookies', methods=['GET', 'POST'])
def api_extract_cookies():
    """API-endpoint för cookie-extrahering med förbättrad felhantering"""
    if request.method == 'POST':
        data = request.json
        cookies = data.get('cookies', '')
    else:
        # För GET-förfrågningar, försök hämta cookies från ZAP
        target_url = session.get('target_url', '')
        cookies = ''
        
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'No target URL in session'
            }), 400
        
        # Försök hämta cookies
        try:
            # Logga försöket
            app.logger.info(f"Attempting to extract cookies for URL: {target_url}")
            
            # Kontrollera ZAP-status först
            if zap.is_available():
                app.logger.info("ZAP is available, proceeding to get cookies")
                cookies = zap.get_cookies(target_url)
                app.logger.info(f"Cookies extraction result: {bool(cookies)}")
            else:
                app.logger.warning("ZAP is not available")
                return jsonify({
                    'success': False,
                    'error': 'ZAP is not available',
                    'zap_status': 'unavailable'
                }), 503
        except Exception as e:
            app.logger.error(f"Exception during cookie extraction: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Error: {str(e)}'
            }), 500
    
    return jsonify({
        'success': True,
        'cookies': cookies
    })

# Uppdatera app.py för att inkludera statiska filer
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

# Se till att den här metoden läggs till i ReportGenerator-klassen
"""
def get_report(self, report_id):
    # Hämta rapportinnehåll
    report_path = self.get_report_path(report_id)
    
    if not os.path.exists(report_path):
        return None
        
    with open(report_path, 'r') as f:
        report_data = json.load(f)
        
    return report_data
"""

@app.route('/')
def index():
    """Dashboard-sida"""
    return render_template('index.html')

@app.route('/target', methods=['GET', 'POST'])
def target():
    """Målkonfiguration med förbättrad scope-hantering"""
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        scan_type = request.form.get('scan_type', 'standard')
        zap_mode = request.form.get('zap_mode', 'protect')
        
        # Validera URL-formatet
        if not target_url:
            flash('Du måste ange en URL', 'danger')
            return redirect(url_for('target'))
            
        # Se till att URL:en har ett protokoll
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        # Spara måldetaljer i sessionen
        session['target_url'] = target_url
        session['scan_type'] = scan_type
        session['zap_mode'] = zap_mode
        
        # Extrahera domän från URL för context scope
        from urllib.parse import urlparse
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        # Om ZAP är tillgänglig, konfigurera ZAP-läge och scope
        if zap.is_available():
            # Set ZAP mode
            success = zap.set_mode(zap_mode)
            if success:
                flash(f"ZAP-läge inställt på: {zap_mode.upper()}", "info")
            
            # Skapa ett nytt context för vår target
            context_name = "Target Context"
            context_result = _direct_api_call('context/action/newContext', {
                'contextName': context_name
            })
            
            if context_result['success']:
                # Sätt scope för denna domän (inkludera allt på domänen)
                include_pattern = f".*{domain}.*"
                include_result = _direct_api_call('context/action/includeInContext', {
                    'contextName': context_name,
                    'regex': include_pattern
                })
                
                if include_result['success']:
                    flash(f"Context scope satt till: {domain}", "info")
                else:
                    flash("Kunde inte sätta context scope", "warning")
            else:
                flash("Kunde inte skapa context", "warning")
        else:
            flash("ZAP är inte tillgänglig, läge och scope kunde inte ställas in", "warning")
        
        flash(f'Mål konfigurerat: {target_url}', 'success')
        return redirect(url_for('session_capture'))
        
    return render_template('target.html')

@app.route('/session-capture')
def session_capture():
    """Sessionskaptureringsvy med förenklad session-hantering"""
    target_url = session.get('target_url', '')
    if not target_url:
        flash("Inget mål-URL konfigurerat. Vänligen konfigurera ett mål först.", "warning")
        return redirect(url_for('target'))
    
    # Get ZAP mode from session
    zap_mode = session.get('zap_mode', 'protect')
    
    # Set ZAP mode if ZAP is available
    if zap.is_available():
        # Set ZAP mode
        success = zap.set_mode(zap_mode)
        if success:
            flash(f"ZAP-läge inställt på: {zap_mode.upper()}", "info")
            
            # Check if we already have a session name, if not create "Session 1"
            if not session.get('zap_session_name'):
                # Create a default HTTP session in ZAP
                result = _direct_api_call('httpSessions/action/createEmptySession', {
                    'site': target_url,
                    'session': 'Session 1'
                })
                
                if result['success']:
                    session['zap_session_name'] = 'Session 1'
                    flash("Session 'Session 1' skapad automatiskt.", "info")
                else:
                    flash("Kunde inte skapa standardsession. Du kan fortsätta utan sessionsnamn.", "warning")
        else:
            flash(f"Kunde inte ställa in ZAP-läge på: {zap_mode.upper()}", "warning")
    else:
        flash("ZAP är inte tillgänglig, läge kunde inte ställas in", "warning")
    
    return render_template(
        'session_capture.html', 
        proxy_host='localhost', 
        proxy_port=8080,
        target_url=target_url,
        zap_mode=zap_mode,
        zap_session_name=session.get('zap_session_name', '')
    )

@app.route('/api/zap-mode', methods=['GET', 'POST'])
def api_zap_mode():
    """API endpoint for getting or setting ZAP mode"""
    try:
        # Check if ZAP is available
        if not zap.is_available():
            return jsonify({
                'success': False,
                'error': 'ZAP is not available',
                'current_mode': 'unknown'
            }), 503
        
        # Handle POST request (setting mode)
        if request.method == 'POST':
            if not request.is_json:
                return jsonify({
                    'success': False,
                    'error': 'Invalid content type, expected application/json'
                }), 400
            
            data = request.json
            new_mode = data.get('mode')
            
            if not new_mode or new_mode not in ['safe', 'protect', 'standard', 'attack']:
                return jsonify({
                    'success': False,
                    'error': f'Invalid mode: {new_mode}. Must be one of: safe, protect, standard, attack'
                }), 400
            
            # Set the mode
            success = zap.set_mode(new_mode)
            
            if success:
                # Update session
                session['zap_mode'] = new_mode
                
                return jsonify({
                    'success': True,
                    'message': f'ZAP mode set to: {new_mode}',
                    'current_mode': new_mode
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Failed to set ZAP mode to: {new_mode}',
                    'current_mode': zap.get_mode()
                }), 500
        
        # Handle GET request (getting current mode)
        current_mode = zap.get_mode()
        
        return jsonify({
            'success': True,
            'current_mode': current_mode,
            'session_mode': session.get('zap_mode', 'protect')
        })
    except Exception as e:
        app.logger.error(f"Error in ZAP mode API: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'current_mode': 'unknown'
        }), 500


@app.route('/api/save-session', methods=['POST'])
def save_session():
    """API-endpoint för att spara en session"""
    if not request.is_json:
        return jsonify({
            'success': False,
            'error': 'Invalid content type, expected application/json'
        }), 400
    
    data = request.json
    
    # Validera obligatoriska fält
    if not data.get('session_name'):
        return jsonify({
            'success': False,
            'error': 'Session name is required'
        }), 400
    
    if not data.get('cookies'):
        return jsonify({
            'success': False,
            'error': 'Cookies data is required'
        }), 400
    
    cookies = data.get('cookies', '')
    session_name = data.get('session_name', f"session_{int(time.time())}")
    target_url = session.get('target_url')
    
    # Validera att target_url finns
    if not target_url:
        return jsonify({
            'success': False,
            'error': 'No target URL in session'
        }), 400
    
    try:
        # Logga input-data för felsökning
        print(f"Saving session with name: {session_name}")
        print(f"Target URL: {target_url}")
        print(f"Cookies (first 50 chars): {cookies[:50]}...")
        
        # Försök spara sessionen
        success = session_manager.save_cookies(session_name, target_url, cookies)
        
        if success:
            return jsonify({
                'success': True,
                'session_name': session_name
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to save session'
            }), 500
    except Exception as e:
        print(f"Error saving session: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Exception: {str(e)}'
        }), 500


def get_spider_status_direct(scan_id):
    """Hämta spider-status direkt via HTTP API med förbättrad felhantering"""
    try:
        # Skapa URL för API-anrop
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/spider/view/status/"
        params = {
            'scanId': scan_id,
            'apikey': ZAP_API_KEY
        }
        
        # Gör API-anrop via HTTP
        import requests
        response = requests.get(api_url, params=params, timeout=10)
        if response.status_code != 200:
            raise Exception(f"API call failed with status {response.status_code}: {response.text}")
        
        data = response.json()
        status = data.get('status', '0')
        
        # Kontrollera även state från scans-endpointen
        scans_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/spider/view/scans/"
        scans_response = requests.get(scans_url, params={'apikey': ZAP_API_KEY}, timeout=10)
        state = "UNKNOWN"
        
        if scans_response.status_code == 200:
            scans_data = scans_response.json()
            for scan in scans_data.get('scans', []):
                if scan.get('id') == scan_id:
                    state = scan.get('state', 'UNKNOWN')
                    break
        
        # Fixa problemet med Spider som fastnar på 97%
        if status == '97' and state == 'FINISHED':
            status = '100'  # Uppdatera till 100% om ZAP anser att scanningen är klar

        # Hämta även resultaten om tillgängliga
        results = []
        try:
            results_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/spider/view/results/"
            results_params = {
                'scanId': scan_id,
                'apikey': ZAP_API_KEY
            }
            results_response = requests.get(results_url, params=results_params, timeout=10)
            if results_response.status_code == 200:
                results_data = results_response.json()
                results = results_data.get('results', [])
        except Exception as e:
            print(f"Error getting spider results: {str(e)}")
        
        return {
            'id': scan_id,
            'status': status,
            'state': state,
            'results': results
        }
    except Exception as e:
        print(f'Error getting spider status: {str(e)}')
        return {
            'id': scan_id,
            'status': 'error',
            'error': str(e)
        }

def get_scan_status_direct(scan_id):
    """Hämta active scan-status direkt via HTTP API med förbättrad felhantering"""
    try:
        # Skapa URL för API-anrop
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ascan/view/status/"
        params = {
            'scanId': scan_id,
            'apikey': ZAP_API_KEY
        }
        
        # Gör API-anrop via HTTP
        import requests
        response = requests.get(api_url, params=params, timeout=10)
        if response.status_code != 200:
            raise Exception(f"API call failed with status {response.status_code}: {response.text}")
        
        data = response.json()
        status = data.get('status', '0')

        # Kontrollera även state från scans-endpointen
        scans_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ascan/view/scans/"
        scans_response = requests.get(scans_url, params={'apikey': ZAP_API_KEY}, timeout=10)
        state = "UNKNOWN"
        reqCount = 0
        alertCount = 0
        
        if scans_response.status_code == 200:
            scans_data = scans_response.json()
            for scan in scans_data.get('scans', []):
                if scan.get('id') == scan_id:
                    state = scan.get('state', 'UNKNOWN')
                    reqCount = scan.get('reqCount', '0')
                    alertCount = scan.get('alertCount', '0')
                    break
                    
        # Fixa problem med scan progress som inte visas korrekt
        # Om state är RUNNING men progress är 100, sätt den till 99 för att förhindra falsk slutförande
        if state == 'RUNNING' and status == '100':
            status = '99'
        
        # Hämta antal alerts
        alerts_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/core/view/alerts/"
        alerts_response = requests.get(alerts_url, params={'apikey': ZAP_API_KEY}, timeout=10)
        alerts_count = 0
        
        if alerts_response.status_code == 200:
            alerts_data = alerts_response.json()
            alerts_count = len(alerts_data.get('alerts', []))
        
        return {
            'id': scan_id,
            'status': status,
            'state': state,
            'reqCount': reqCount,
            'alerts': alertCount or alerts_count
        }
    except Exception as e:
        print(f'Error getting scan status: {str(e)}')
        return {
            'id': scan_id,
            'status': 'error',
            'error': str(e)
        }

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scanningsvy"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start_spider':
            target_url = session.get('target_url')
            if target_url:
                try:
                    print(f"Starting spider scan for URL: {target_url}")
                    
                    # Uppdaterat anrop utan cookie-parameter
                    scan_id = start_spider_direct(target_url)
                    
                    print(f"Spider scan ID received: {scan_id}")  # Debug-logg
                    session['spider_scan_id'] = scan_id
                    print(f"Spider scan ID stored in session: {session.get('spider_scan_id')}")  # Debug-logg
                    flash('Spider scanning started successfully', 'success')
                except Exception as e:
                    print(f"Error starting spider scan: {str(e)}")  # Debug-logg
                    flash(f'Error starting spider scan: {str(e)}', 'danger')
            else:
                flash('No target URL specified', 'danger')
            
        elif action == 'start_active_scan':
            target_url = session.get('target_url')
            if target_url:
                try:
                    print(f"Starting active scan for URL: {target_url}")
                    
                    # Uppdaterat anrop utan cookie-parameter
                    scan_id = start_active_scan_direct(target_url)
                    
                    print(f"Active scan ID received: {scan_id}")  # Debug-logg
                    session['active_scan_id'] = scan_id
                    print(f"Active scan ID stored in session: {session.get('active_scan_id')}")  # Debug-logg
                    flash('Active scanning started successfully', 'success')
                except Exception as e:
                    print(f"Error starting active scan: {str(e)}")  # Debug-logg
                    flash(f'Error starting active scan: {str(e)}', 'danger')
            else:
                flash('No target URL specified', 'danger')
                
        elif action == 'start_ajax_spider':
            target_url = session.get('target_url')
            if target_url:
                try:
                    print(f"Starting Ajax Spider for URL: {target_url}")
                    
                    # Starta Ajax Spider med bara target_url
                    result = start_ajax_spider_direct(target_url)
                    
                    # Markera att Ajax Spider är igång
                    session['ajax_spider_running'] = True
                    print(f"Ajax Spider started successfully")
                    flash('Ajax Spider started successfully', 'success')
                except Exception as e:
                    print(f"Error starting Ajax Spider: {str(e)}")
                    flash(f'Error starting Ajax Spider: {str(e)}', 'danger')
            else:
                flash('No target URL specified', 'danger')
            
        elif action == 'start_sqlmap':
            session_name = request.form.get('session_name')
            target_url = session.get('target_url')
            
            if not target_url:
                flash('No target URL specified', 'danger')
                return redirect(url_for('scan'))
                
            session_data = None
            cookies = None
            
            if session_name:
                session_data = session_manager.load_cookies(session_name)
                if session_data:
                    cookies = session_data.get('cookies', '')
            
            # Ställ in alternativ baserat på scanningstyp
            risk = 1
            level = 1
            
            if session.get('scan_type') == 'deep':
                risk = 2
                level = 3
        
        return redirect(url_for('scan'))
    
    # Hämta status för pågående scanningar
    spider_status = None
    active_scan_status = None
    sqlmap_status = None
    ajax_spider_status = None
    
    if 'spider_scan_id' in session:
        try:
            spider_status = get_spider_status(session['spider_scan_id'])
        except Exception as e:
            print(f"Error getting spider status: {str(e)}")
            
    if 'active_scan_id' in session:
        try:
            active_scan_status = zap.get_scan_status(session['active_scan_id'])
        except Exception as e:
            print(f"Error getting active scan status: {str(e)}")
            
    # Hämta Ajax Spider-status om den körs
    if 'ajax_spider_running' in session:
        try:
            ajax_spider_status = get_ajax_spider_status()
        except Exception as e:
            print(f"Error getting Ajax Spider status: {str(e)}")
    
    # Hämta tillgängliga sessioner
    sessions = session_manager.list_sessions()
    
    return render_template(
            'scan.html',
            target_url=session.get('target_url'),
            spider_status=spider_status,
            active_scan_status=active_scan_status,
            ajax_spider_status=ajax_spider_status,
            zap_session_name=session.get('zap_session_name')  # Lägg till detta
        )

def get_spider_status(scan_id):
        """Get spider status"""
        return get_spider_status_direct(scan_id)



def get_ajax_spider_status():
    """Get the status of the running Ajax Spider scan using direct HTTP calls"""
    try:
        # Direct API call to get Ajax Spider status
        result = _direct_api_call('ajaxSpider/view/status')
        
        if result['success']:
            status_data = result['data']
            status = status_data.get('status', '')
            
            # Build response object
            response = {
                'success': True,
                'status': status,
                'running': status == 'running'
            }
            
            # Include additional data if available
            if 'numberOfResults' in status_data:
                response['numberOfResults'] = status_data['numberOfResults']
            if 'numberOfURLsToFetch' in status_data:
                response['urls_to_fetch'] = status_data['numberOfURLsToFetch']
            if 'timeTakenInSecs' in status_data:
                response['time_taken'] = status_data['timeTakenInSecs']
                
            return response
        else:
            error_msg = f"Failed to get Ajax Spider status: {result.get('response', 'Unknown error')}"
            app.logger.error(error_msg)
            return {
                'success': False,
                'status': 'error',
                'error': error_msg,
                'running': False
            }
    except Exception as e:
        app.logger.error(f'Error getting Ajax Spider status: {str(e)}')
        return {
            'success': False,
            'status': 'error',
            'error': str(e),
            'running': False
        }

def transform_ajax_spider_results(raw_results):
    """Transformerar råa Ajax Spider-resultat till det format som templates förväntar sig."""
    transformed = []
    
    for item in raw_results:
        # Extrahera URL och metod från requestHeader
        url = ""
        method = "GET"  # standard
        
        if "requestHeader" in item:
            request_header = item["requestHeader"]
            first_line = request_header.split('\r\n')[0] if '\r\n' in request_header else request_header
            parts = first_line.split(' ', 2)  # Split max 2 times: METHOD URL HTTP_VERSION
            if len(parts) >= 2:
                method = parts[0]
                url = parts[1]
        
        # Extrahera statuskod från responseHeader
        status_code = None
        if "responseHeader" in item:
            response_header = item["responseHeader"]
            first_line = response_header.split('\r\n')[0] if '\r\n' in response_header else response_header
            parts = first_line.split(' ', 2)  # Split max 2 times: HTTP_VERSION STATUS_CODE STATUS_TEXT
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])
        
        # Skapa nytt objekt med rätt struktur
        transformed_item = {
            'url': url,
            'method': method,
            'statusCode': status_code,
            # Lägg till andra egenskaper vid behov
            'id': item.get('id'),
            'timestamp': item.get('timestamp'),
            'cookieParams': item.get('cookieParams', '')
        }
        
        transformed.append(transformed_item)
    
    return transformed


def setup_zap_session_with_cookies(target_url, cookies_str):
    """Sets up a ZAP session with the provided cookies"""
    if not cookies_str:
        return False
    
    try:
        # Parse cookies
        cookies_dict = {}
        for cookie in cookies_str.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies_dict[name.strip()] = value.strip()
        
        # Extract domain properly without http:// prefix
        domain = target_url.split('//')[1].split('/')[0]
        site = domain  # No http:// prefix
        
        print(f"Setting up ZAP session for site: {site}")
        print(f"Found {len(cookies_dict)} cookies to add")
        
        # Create a session in ZAP
        session_name = f"auth-session-{int(time.time())}"  # Make session name unique
        session_create_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/httpSessions/action/createEmptySession/"
        session_create_response = requests.get(
            session_create_url,
            params={
                'apikey': ZAP_API_KEY,
                'site': site,
                'sessionName': session_name
            },
            timeout=5
        )
        print(f"Create session response: {session_create_response.text}")
        
        # Set it as active
        active_session_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/httpSessions/action/setActiveSession/"
        active_session_response = requests.get(
            active_session_url,
            params={
                'apikey': ZAP_API_KEY,
                'site': site,
                'session': session_name
            },
            timeout=5
        )
        print(f"Set active session response: {active_session_response.text}")
        
        # Process each cookie
        for name, value in cookies_dict.items():
            print(f"Processing cookie: {name}")
            
            # Step 1: Make sure the token is recognized by ZAP
            token_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/httpSessions/action/addSessionToken/"
            token_response = requests.get(
                token_url,
                params={
                    'apikey': ZAP_API_KEY,
                    'site': site,
                    'sessionToken': name
                },
                timeout=5
            )
            
            # Check if token was added successfully
            token_response_text = token_response.text
            print(f"Add token response for {name}: {token_response_text}")
            
            # Step 2: Set the token value in the session
            token_value_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/httpSessions/action/setSessionTokenValue/"
            token_value_response = requests.get(
                token_value_url,
                params={
                    'apikey': ZAP_API_KEY,
                    'site': site,
                    'session': session_name,
                    'sessionToken': name,
                    'tokenValue': value
                },
                timeout=5
            )
            
            # Check if token value was set successfully
            token_value_response_text = token_value_response.text
            print(f"Set token value response for {name}: {token_value_response_text}")
        
        # Verify session setup by getting the session details
        sessions_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/httpSessions/view/sessions/"
        sessions_response = requests.get(
            sessions_url,
            params={
                'apikey': ZAP_API_KEY,
                'site': site
            },
            timeout=5
        )
        
        # Check if session was created and has tokens
        sessions_response_text = sessions_response.text
        print(f"Sessions after setup: {sessions_response_text}")
        
        # Parse the JSON response to look for token values
        sessions_data = json.loads(sessions_response_text)
        sessions_list = sessions_data.get('sessions', [])
        
        # Check if our session exists with tokens
        session_found = False
        tokens_found = 0
        
        for session_info in sessions_list:
            if session_info.get('name') == session_name:
                session_found = True
                tokens = session_info.get('tokens', {})
                tokens_found = len(tokens)
                print(f"Found session with {tokens_found} tokens")
                
                # Print each token and its value
                for token_name, token_value in tokens.items():
                    print(f"Token: {token_name}, Value: {token_value}")
        
        if not session_found:
            print("WARNING: Session was not found after setup!")
            return False
            
        if tokens_found == 0:
            print("WARNING: Session was found but has no tokens!")
            return False
            
        print(f"ZAP session setup successful with {tokens_found} tokens")
        return True
        
    except Exception as e:
        print(f"Error setting up ZAP session: {str(e)}")
        return False
    

@app.route('/api/start-scan', methods=['POST'])
def api_start_scan():
    """API-endpoint för att starta skanning asynkront"""
    data = request.json
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({'error': 'No target URL specified'}), 400
    
    # Generera ett unikt ID för denna skanning
    scan_id = str(uuid.uuid4())
    
    # Starta skanning i en bakgrundstråd
    thread = threading.Thread(
        target=run_scan_in_background,
        args=(scan_id, target_url)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'status': 'started',
        'scan_id': scan_id
    })




def run_scan_in_background(scan_id, target_url):
    """Kör skanning i bakgrunden och uppdatera resultaten"""
    try:
        # Spara status som "running"
        with scan_status_lock:
            scan_statuses[scan_id] = {
                'status': 'running',
                'progress': 0,
                'start_time': time.time(),
                'target_url': target_url
            }
        
        # Kör progressiv skanning
        result = zap.start_progressive_scan(target_url)
        
        # Spara initiala resultat
        with scan_status_lock:
            scan_statuses[scan_id].update({
                'progress': 10,
                'spider_id': result.get('spider_id'),
                'ascan_id': result.get('ascan_id'),
                'strategy': result.get('strategy')
            })
        
        # Övervaka framsteg
        if 'ascan_id' in result:
            ascan_id = result['ascan_id']
            while int(zap.zap.ascan.status(ascan_id)) < 100:
                progress = int(zap.zap.ascan.status(ascan_id))
                with scan_status_lock:
                    scan_statuses[scan_id]['progress'] = 10 + (progress * 0.9)  # 10% till 100%
                time.sleep(5)
        
        # Skanning klar
        with scan_status_lock:
            scan_statuses[scan_id].update({
                'status': 'completed',
                'progress': 100,
                'completion_time': time.time()
            })
            
        # Hämta och spara resultat
        alerts = zap.get_alerts()
        
        with scan_status_lock:
            scan_statuses[scan_id]['alerts'] = len(alerts)
            scan_statuses[scan_id]['results'] = alerts[:10]  # Bara de 10 första för snabb åtkomst
        
        # Spara fullständiga resultat till fil
        save_scan_results_to_file(scan_id, alerts)
            
    except Exception as e:
        # Fel vid skanning
        with scan_status_lock:
            scan_statuses[scan_id].update({
                'status': 'error',
                'error': str(e)
            })

@app.route('/api/scan-status')
def scan_status():
    """API-endpoint för att hämta scanningsstatus med förbättrad ZAP-kommunikation"""
    status = {
        'spider': None,
        'active_scan': None,
        'sqlmap': None,
        'ajax_spider': None,
        'zap_available': zap.is_available()
    }
    
    # Om ZAP inte är tillgänglig, försök återansluta
    if not status['zap_available']:
        reconnect_success = zap.reconnect_zap()
        status['zap_reconnect_attempted'] = True
        status['zap_reconnect_success'] = reconnect_success
        status['zap_available'] = zap.is_available()
        
    # Fortsätt som vanligt om ZAP är tillgänglig
    if status['zap_available']:
        # Hämta pågående scannings-ID från ZAP direkt istället för att förlita oss på session
        try:
            # Hämta alla pågående Spider scanningar
            spider_scans_result = _direct_api_call('spider/view/scans')
            if spider_scans_result['success']:
                spider_scans = spider_scans_result['data'].get('scans', [])
                # Ta det senaste scan ID om det finns någon pågående scanning
                if spider_scans:
                    latest_spider = spider_scans[-1]  # Anta att den senaste är den vi vill ha
                    spider_id = latest_spider.get('id')
                    if spider_id:
                        status['spider'] = get_spider_status_direct(spider_id)
                        #print(f"Found active spider scan with ID: {spider_id}, status: {status['spider']}")
                        # Spara detta ID i sessionen för framtida bruk
                        session['spider_scan_id'] = spider_id
            
            # Hämta alla pågående Active scanningar
            ascan_scans_result = _direct_api_call('ascan/view/scans')
            if ascan_scans_result['success']:
                ascan_scans = ascan_scans_result['data'].get('scans', [])
                # Ta det senaste scan ID om det finns någon pågående scanning
                if ascan_scans:
                    latest_ascan = ascan_scans[-1]  # Anta att den senaste är den vi vill ha
                    ascan_id = latest_ascan.get('id')
                    if ascan_id:
                        status['active_scan'] = get_scan_status_direct(ascan_id)
                        print(f"Found active scan with ID: {ascan_id}, status: {status['active_scan']}")
                        # Spara detta ID i sessionen för framtida bruk
                        session['active_scan_id'] = ascan_id
            
            # Kontrollera Ajax Spider status
            ajax_status_result = _direct_api_call('ajaxSpider/view/status')
            if ajax_status_result['success']:
                ajax_status = ajax_status_result['data'].get('status')
                running = ajax_status == 'running'
                status['ajax_spider'] = {
                    'status': ajax_status,
                    'running': running
                }
                
                # Om Ajax Spider körs eller har stoppats nyligen, hämta resultat
                if running or ajax_status == 'stopped':
                    try:
                        results_response = _direct_api_call('ajaxSpider/view/results')
                        if results_response['success']:
                            results = results_response['data'].get('results', [])
                            status['ajax_spider']['urls_found'] = len(results)
                    except Exception as e:
                        print(f"Error getting Ajax Spider results: {str(e)}")
                
                # Uppdatera sessionen baserat på status
                session['ajax_spider_running'] = running
            
            # Kontrollera SQLMap status om vi har ett scan_id
            if 'sqlmap_scan_id' in session:
                try:
                    sqlmap_scan_id = session['sqlmap_scan_id']
                    status['sqlmap'] = sql_tester.get_status(sqlmap_scan_id)
                except Exception as e:
                    print(f"Error getting SQLMap status: {str(e)}")
                    status['sqlmap'] = {'error': str(e)}
            
        except Exception as e:
            print(f"Error retrieving scan status: {str(e)}")
            status['error'] = str(e)
    
    return jsonify(status)

@app.route('/api/scan-status-light')
def scan_status_light():
    """Lättviktig API-endpoint för att bara hämta grundläggande scanningsstatus utan detaljerade resultat"""
    status = {
        'spider': None,
        'active_scan': None,
        'ajax_spider': None,
        'zap_available': True,
        'alerts_summary': None
    }
    
    try:
        # Hämta spider status om det finns ett ID
        spider_id = session.get('spider_scan_id')
        if spider_id:
            try:
                api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/spider/view/status/"
                response = requests.get(api_url, params={'scanId': spider_id, 'apikey': ZAP_API_KEY}, timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    status['spider'] = {
                        'id': spider_id,
                        'status': data.get('status', '0')
                    }
                    
                # Kontrollera även state
                scans_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/spider/view/scans/"
                scans_response = requests.get(scans_url, params={'apikey': ZAP_API_KEY}, timeout=3)
                if scans_response.status_code == 200:
                    scans_data = scans_response.json()
                    for scan in scans_data.get('scans', []):
                        if scan.get('id') == spider_id:
                            status['spider']['state'] = scan.get('state', 'UNKNOWN')
                            # Fixa 97% problemet
                            if status['spider']['status'] == '97' and status['spider']['state'] == 'FINISHED':
                                status['spider']['status'] = '100'
                            break
            except Exception as e:
                print(f"Error getting light spider status: {str(e)}")
        
        # Hämta active scan status om det finns ett ID
        active_scan_id = session.get('active_scan_id')
        if active_scan_id:
            try:
                api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ascan/view/status/"
                response = requests.get(api_url, params={'scanId': active_scan_id, 'apikey': ZAP_API_KEY}, timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    status['active_scan'] = {
                        'id': active_scan_id,
                        'status': data.get('status', '0')
                    }
                    
                # Kontrollera även state
                scans_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ascan/view/scans/"
                scans_response = requests.get(scans_url, params={'apikey': ZAP_API_KEY}, timeout=3)
                if scans_response.status_code == 200:
                    scans_data = scans_response.json()
                    for scan in scans_data.get('scans', []):
                        if scan.get('id') == active_scan_id:
                            status['active_scan']['state'] = scan.get('state', 'UNKNOWN')
                            status['active_scan']['alertCount'] = scan.get('alertCount', '0')
                            # Förhindra falsk 100% om scanning fortfarande pågår
                            if status['active_scan']['status'] == '100' and status['active_scan']['state'] == 'RUNNING':
                                status['active_scan']['status'] = '99'
                            break
            except Exception as e:
                print(f"Error getting light active scan status: {str(e)}")
        
        # Hämta Ajax Spider status
        try:
            ajax_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ajaxSpider/view/status/"
            ajax_response = requests.get(ajax_url, params={'apikey': ZAP_API_KEY}, timeout=3)
            if ajax_response.status_code == 200:
                ajax_data = ajax_response.json()
                ajax_status = ajax_data.get('status', '')
                status['ajax_spider'] = {
                    'status': ajax_status,
                    'running': ajax_status == 'running'
                }
            if ajax_status != 'running':
                try:
                    # Försök hämta antal resultat, inte alla resultat
                    num_results_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ajaxSpider/view/numberOfResults/"
                    num_results_response = requests.get(num_results_url, params={'apikey': ZAP_API_KEY}, timeout=3)
                    if num_results_response.status_code == 200:
                        num_results_data = num_results_response.json()
                        status['ajax_spider']['urls_found'] = num_results_data.get('numberOfResults', 0)
                except Exception as e:
                    print(f"Error getting number of Ajax Spider results: {str(e)}")                
        except Exception as e:
            print(f"Error getting light Ajax Spider status: {str(e)}")
        
        # Hämta sammanfattning av alerts (mycket mindre data än fullständiga alerts)
        try:
            summary_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alertsSummary/"
            summary_response = requests.get(summary_url, params={'apikey': ZAP_API_KEY}, timeout=3)
            if summary_response.status_code == 200:
                summary_data = summary_response.json()
                status['alerts_summary'] = summary_data.get('alertsSummary', {})
        except Exception as e:
            print(f"Error getting alerts summary: {str(e)}")
            
        return jsonify(status)
    except Exception as e:
        print(f"Error in scan-status-light: {str(e)}")
        return jsonify({
            'error': str(e),
            'spider': status['spider'],
            'active_scan': status['active_scan'],
            'ajax_spider': status['ajax_spider']
        })


@app.route('/api/scan-status/<scan_id>')
def api_scan_status(scan_id):
    """Hämta status för en pågående skanning"""
    with scan_status_lock:
        status = scan_statuses.get(scan_id)
        
    if not status:
        return jsonify({'error': 'Scan not found'}), 404
        
    return jsonify(status)

@app.route('/api/all-scans')
def api_all_scans():
    """Hämta lista över alla skanningar"""
    with scan_status_lock:
        # Skapa en kopia av scan_statuses för att undvika konkurrens
        all_scans = {
            scan_id: {
                'status': scan.get('status', 'unknown'),
                'progress': scan.get('progress', 0),
                'target_url': scan.get('target_url', ''),
                'start_time': scan.get('start_time', 0),
                'completion_time': scan.get('completion_time', 0) if scan.get('status') == 'completed' else 0,
                'alerts': scan.get('alerts', 0) if scan.get('status') == 'completed' else 0
            }
            for scan_id, scan in scan_statuses.items()
        }
    
    return jsonify(all_scans)

@app.route('/api/scan-results/<scan_id>')
def api_scan_results(scan_id):
    """Hämta resultaten från en slutförd skanning"""
    with scan_status_lock:
        status = scan_statuses.get(scan_id)
        
    if not status:
        return jsonify({'error': 'Scan not found'}), 404
        
    if status.get('status') != 'completed':
        return jsonify({
            'error': 'Scan not completed',
            'status': status.get('status', 'unknown'),
            'progress': status.get('progress', 0)
        }), 400
    
    # Försök att hämta fullständiga resultat från fil
    results_file = os.path.join(app.config['RESULTS_DIR'], 'scans', f"{scan_id}.json")
    
    if os.path.exists(results_file):
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            return jsonify(results)
        except Exception as e:
            return jsonify({
                'error': f'Error loading results: {str(e)}',
                'summary': status.get('results', [])
            }), 500
    else:
        # Om filen inte finns, returnera sammanfattningen från minnet
        return jsonify(status.get('results', []))



@app.route('/api/cancel-scan/<scan_id>', methods=['POST'])
def api_cancel_scan(scan_id):
    """Avbryt en pågående skanning"""
    with scan_status_lock:
        status = scan_statuses.get(scan_id)
        
    if not status:
        return jsonify({'error': 'Scan not found'}), 404
        
    if status.get('status') != 'running':
        return jsonify({
            'error': 'Scan is not running',
            'status': status.get('status', 'unknown')
        }), 400
    
    # Avbryt skanningen
    try:
        spider_id = status.get('spider_id')
        ascan_id = status.get('ascan_id')
        
        if spider_id and int(zap.zap.spider.status(spider_id)) < 100:
            zap.zap.spider.stop(spider_id)
            
        if ascan_id and int(zap.zap.ascan.status(ascan_id)) < 100:
            zap.zap.ascan.stop(ascan_id)
        
        # Uppdatera status
        with scan_status_lock:
            scan_statuses[scan_id].update({
                'status': 'cancelled',
                'progress': -1,
                'cancellation_time': time.time()
            })
        
        return jsonify({
            'success': True,
            'message': 'Scan cancelled'
        })
    except Exception as e:
        return jsonify({
            'error': f'Error cancelling scan: {str(e)}'
        }), 500



def save_scan_results_to_file(scan_id, results):
    """Spara fullständiga skanningsresultat till fil"""
    try:
        results_dir = os.path.join(app.config['RESULTS_DIR'], 'scans')
        os.makedirs(results_dir, exist_ok=True)
        
        results_file = os.path.join(results_dir, f"{scan_id}.json")
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"Saved full scan results to {results_file}")
    except Exception as e:
        print(f"Error saving scan results: {str(e)}")

@app.route('/api/download-report/<report_id>')
def download_report(report_id):
    """Hämta en genererad rapport"""
    report_path = report_generator.get_report_path(report_id)
    
    if os.path.exists(report_path):
        try:
            with open(report_path, 'r') as f:
                report_data = json.load(f)
                
            # Bearbeta data för bättre presentation
            if 'sqlmap_results' in report_data:
                for i, result in enumerate(report_data['sqlmap_results']):
                    # Extrahera sårbarheter från loggutdrag
                    if 'log_excerpt' in result:
                        vulnerabilities = []
                        for line in result['log_excerpt'].split('\n'):
                            if '[INFO]' in line and ('is vulnerable' in line or 'vulnerability' in line):
                                vulnerabilities.append(line)
                        
                        if vulnerabilities:
                            report_data['sqlmap_results'][i]['vulnerabilities_found'] = vulnerabilities
            
            return jsonify(report_data)
        except Exception as e:
            return jsonify({'error': f'Error parsing report file: {str(e)}'}), 500
    
    return jsonify({'error': 'Report not found'}), 404



@app.route('/api/start-sqlmap', methods=['POST'])
def api_start_sqlmap():
    """API-endpoint för att starta SQL injection-scanning"""
    try:
        data = request.json
        target_url = data.get('target_url')
        session_name = data.get('session_name')
        
        if not target_url:
            return jsonify({'error': 'Inget mål-URL angivet'}), 400
            
        cookies = None
        if session_name:
            session_data = session_manager.load_cookies(session_name)
            if session_data:
                cookies = session_data.get('cookies')
        
        # Starta scanning med vår nya tester
        result = sql_tester.start_scan(target_url, cookies)
        
        # Spara scan_id i sessionen om scanningen startades
        if result.get('status') == 'started':
            session['sqlmap_scan_id'] = result['scan_id']
            return jsonify(result)
        else:
            return jsonify({
                'status': 'error',
                'error': result.get('error', 'Okänt fel vid start av SQL test')
            }), 500
    except Exception as e:
        print(f"Error starting SQL injection scan: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/sqlmap-status/<scan_id>')
def api_sqlmap_status(scan_id):
    """API-endpoint för att hämta SQL injection-status"""
    status = sql_tester.get_status(scan_id)
    return jsonify(status)

@app.route('/api/sqlmap-results/<scan_id>')
def sqlmap_results(scan_id):
    """API-endpoint för att hämta SQL injection-resultat"""
    if not scan_id:
        return jsonify({'error': 'No scan ID provided'}), 400
        
    results = sql_tester.get_results(scan_id)
    summary = sql_tester.get_summary(scan_id)
    
    return jsonify({
        'results': results,
        'summary': summary
    })


@app.route('/api/debug-zap-cookies')
def debug_zap_cookies():
    """Debug endpoint for ZAP cookie extraction"""
    target_url = session.get('target_url', '')
    result = {
        'target_url': target_url,
        'sites': [],
        'methods_tried': [],
        'cookies_found': {}
    }
    
    if not target_url:
        result['error'] = 'No target URL in session'
        return jsonify(result)
    
    if not zap.is_available():
        result['error'] = 'ZAP is not available'
        return jsonify(result)
    
    try:
        # Get all sites in ZAP
        sites = zap.zap.core.sites
        result['sites'] = sites
        
        # Try method 1: HTTP Sessions
        result['methods_tried'].append('http_sessions')
        try:
            for site in sites:
                if urlparse(target_url).netloc in site:
                    sessions = zap.zap.httpsessions.sessions(site)
                    result['cookies_found']['http_sessions'] = {
                        'site': site,
                        'sessions': sessions
                    }
        except Exception as e:
            result['http_sessions_error'] = str(e)
        
        # Try method 2: Messages
        result['methods_tried'].append('messages')
        try:
            for site in sites:
                if urlparse(target_url).netloc in site:
                    messages = zap.zap.core.messages(baseurl=site)
                    cookies_found = []
                    
                    for msg in messages:
                        if 'requestHeader' in msg:
                            headers = msg['requestHeader'].split('\r\n')
                            for header in headers:
                                if header.lower().startswith('cookie:'):
                                    cookies_found.append(header[7:].strip())
                    
                    if cookies_found:
                        result['cookies_found']['messages'] = {
                            'site': site,
                            'cookies': cookies_found
                        }
        except Exception as e:
            result['messages_error'] = str(e)
        
        return jsonify(result)
    except Exception as e:
        result['error'] = str(e)
        return jsonify(result)

@app.route('/api/debug-cookies')
def debug_cookies():
    """Debug-endpoint för cookie-hantering"""
    debug_info = {
        'session_data': {k: session.get(k) for k in session},
        'target_url': session.get('target_url', 'Not set'),
        'zap_status': 'unknown',
        'zap_sites': [],
        'manual_cookies_test': {}
    }
    
    # Testa om vi kan hämta cookies manuellt
    if 'target_url' in session and session['target_url']:
        target_url = session['target_url']
        debug_info['manual_cookies_test']['target_url'] = target_url
        
        # Testa om ZAP är tillgängligt
        try:
            if zap.is_available():
                debug_info['zap_status'] = 'available'
                
                # Hämta alla webbplatser i ZAP
                try:
                    sites = zap.zap.core.sites
                    debug_info['zap_sites'] = sites
                    
                    # Se om vår target_url finns i någon av platserna
                    domain = urlparse(target_url).netloc
                    matching_sites = [site for site in sites if domain in site]
                    debug_info['matching_sites'] = matching_sites
                    
                    # Försök få cookies från matching sites
                    for site in matching_sites:
                        try:
                            # Metod 1: Hämta sessioner
                            sessions = zap.zap.httpsessions.sessions(site)
                            debug_info['manual_cookies_test'][f'sessions_{site}'] = sessions
                            
                            # Metod 2: Hämta meddelanden
                            messages = zap.zap.core.messages(baseurl=site)
                            cookie_headers = []
                            
                            for msg in messages:
                                if isinstance(msg, dict) and 'requestHeader' in msg:
                                    headers = msg['requestHeader'].split('\r\n')
                                    for header in headers:
                                        if header.lower().startswith('cookie:'):
                                            cookie_headers.append(header[7:].strip())
                            
                            debug_info['manual_cookies_test'][f'cookie_headers_{site}'] = cookie_headers
                        except Exception as e:
                            debug_info['manual_cookies_test'][f'error_{site}'] = str(e)
                except Exception as e:
                    debug_info['zap_sites_error'] = str(e)
            else:
                debug_info['zap_status'] = 'unavailable'
        except Exception as e:
            debug_info['zap_error'] = str(e)
    
    return jsonify(debug_info)

@app.route('/test-cookies')
def test_cookies():
    """Test endpoint för cookies"""
    target_url = session.get('target_url', '')
    cookies = ''
    
    if target_url and zap.is_available():
        try:
            cookies = zap.get_cookies(target_url)
        except Exception as e:
            cookies = f"Error: {str(e)}"
    
    return render_template('test_cookies.html', 
                          target_url=target_url, 
                          cookies=cookies, 
                          zap_available=zap.is_available())


@app.route('/sqlmap-status-file/<scan_id>')
def sqlmap_status_file(scan_id):
    """Visa status-filen för en SQLMap-scanning"""
    status_file = os.path.join(app.config['RESULTS_DIR'], 'sqlmap', scan_id, 'status.json')
    
    if not os.path.exists(status_file):
        return jsonify({'error': 'Status file not found'}), 404
    
    try:
        with open(status_file, 'r') as f:
            status_data = json.load(f)
        
        # Lista även innehållet i katalogen
        task_dir = os.path.join(app.config['RESULTS_DIR'], 'sqlmap', scan_id)
        dir_contents = os.listdir(task_dir)
        
        # Kontrollera om containern fortfarande kör
        container_id = status_data.get('container_id')
        container_running = False
        
        if container_id:
            try:
                container_check = subprocess.run(['docker', 'ps', '-q', '-f', f"id={container_id}"], 
                                                capture_output=True, text=True)
                container_running = container_id in container_check.stdout
            except Exception as e:
                status_data['container_check_error'] = str(e)
        
        return jsonify({
            'status_data': status_data,
            'directory_contents': dir_contents,
            'container_running': container_running
        })
    except Exception as e:
        return jsonify({'error': f'Error reading status file: {str(e)}'}), 500

@app.route('/api/zap-diagnostic')
def api_zap_diagnostic():
    """Detaljerad diagnostisk endpoint för ZAP-anslutningsproblem"""
    result = {
        'timestamp': time.time(),
        'configuration': {
            'zap_host': ZAP_HOST,
            'zap_port': 8080,
            'zap_api_key': ZAP_API_KEY[:3] + '***',  # Visa bara början av API-nyckeln
        },
        'connectivity': {
            'zap_available': False,
            'api_reachable': False,
            'proxy_reachable': False
        },
        'troubleshooting': {
            'suggested_actions': []
        }
    }
    
    # Steg 1: Kontrollera om ZAP-objektet fungerar
    try:
        version = zap.zap.core.version
        result['connectivity']['zap_available'] = True
        result['zap_version'] = version
    except Exception as e:
        result['errors'] = {'zap_connection': str(e)}
        result['troubleshooting']['suggested_actions'].append(
            "ZAP API connection failed - check that ZAP is running and API key is correct"
        )
    
    # Steg 2: Försök att pinga ZAP API direkt
    try:
        api_url = f"http://{ZAP_HOST}:{ZAP_PROXY_PORT}/JSON/core/view/version/"
        response = requests.get(api_url, params={'apikey': ZAP_API_KEY}, timeout=3)
        result['connectivity']['api_reachable'] = response.status_code == 200
        result['api_response'] = {
            'status_code': response.status_code,
            'content': response.text[:100] if response.status_code == 200 else response.text
        }
        
        if response.status_code != 200:
            result['troubleshooting']['suggested_actions'].append(
                f"ZAP API returned status code {response.status_code} - check your network and firewall settings"
            )
    except requests.exceptions.RequestException as e:
        result['errors']['api_request'] = str(e)
        result['troubleshooting']['suggested_actions'].append(
            f"Cannot reach ZAP API at http://{ZAP_HOST}:{ZAP_PROXY_PORT} - check that ZAP is running and port is correct"
        )
    
    # Steg 3: Kontrollera om proxyn är tillgänglig
    try:
        proxy_url = f"http://{ZAP_HOST}:{ZAP_PROXY_PORT}"
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        response = requests.get('http://example.com', proxies=proxies, timeout=5)
        result['connectivity']['proxy_reachable'] = response.status_code == 200
        
        if response.status_code != 200:
            result['troubleshooting']['suggested_actions'].append(
                f"ZAP proxy returned status code {response.status_code} - check proxy settings"
            )
    except requests.exceptions.RequestException as e:
        result['errors']['proxy_test'] = str(e)
        result['troubleshooting']['suggested_actions'].append(
            f"Cannot use ZAP as proxy at {ZAP_HOST}:{ZAP_PROXY_PORT} - check proxy settings"
        )
    
    # Steg 4: Kontrollera processer
    try:
        import psutil
        java_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'java' in proc.info['name'].lower():
                    cmdline = ' '.join(proc.info.get('cmdline', []))
                    if 'zap' in cmdline.lower():
                        java_processes.append({
                            'pid': proc.info['pid'],
                            'cmdline': cmdline[:100]
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        result['processes'] = {
            'java_zap_processes': java_processes,
            'count': len(java_processes)
        }
        
        if not java_processes:
            result['troubleshooting']['suggested_actions'].append(
                "No Java processes related to ZAP found running - start ZAP"
            )
            
    except ImportError:
        result['processes'] = {
            'error': 'psutil module not available'
        }
    
    # Steg 5: Kontrollera om vi kan hämta cookies för ett exempel
    target_url = session.get('target_url')
    if target_url and result['connectivity']['zap_available']:
        try:
            # Försök varje strategi individuellt
            cookie_results = {}
            
            # Anropa varje strategi separat
            strategies = [
                '_get_cookies_from_httpsessions',
                '_get_cookies_from_messages',
                '_get_cookies_from_direct_api',
                '_get_cookies_from_history'
            ]
            
            domain = urlparse(target_url).netloc
            for strategy in strategies:
                try:
                    method = getattr(zap, strategy)
                    cookies = method(target_url, domain)
                    cookie_results[strategy] = {
                        'success': bool(cookies),
                        'cookies': cookies[:50] + '...' if cookies and len(cookies) > 50 else cookies
                    }
                except Exception as e:
                    cookie_results[strategy] = {
                        'success': False,
                        'error': str(e)
                    }
            
            result['cookie_test'] = {
                'target_url': target_url,
                'strategies': cookie_results
            }
            
            # Lägg till tips baserat på resultaten
            if not any(r.get('success') for r in cookie_results.values()):
                result['troubleshooting']['suggested_actions'].append(
                    "No cookies found with any strategy - verify that the target has been visited through ZAP proxy"
                )
        except Exception as e:
            result['cookie_test'] = {
                'error': str(e)
            }
    
    # Lägg till generella tips
    if not result['connectivity']['zap_available']:
        result['troubleshooting']['suggested_actions'].append(
            "Restart the ZAP application and ensure API is enabled"
        )
        
    if result['connectivity']['zap_available'] and not result['connectivity']['proxy_reachable']:
        result['troubleshooting']['suggested_actions'].append(
            "ZAP API is available but proxy isn't working - check proxy settings and firewall"
        )
    
    return jsonify(result)


@app.route('/api/scan-from-zap', methods=['POST'])
def api_scan_from_zap():
    """API-endpoint för att starta SQL injection scan baserat på ZAP-resultat"""
    try:
        # Hämta parametrar från POST-request (JSON)
        data = request.json
        target_site = data.get('target_site')
        max_urls = int(data.get('max_urls', 50))
        session_name = data.get('session_name')
        
        # Logga begäran för felsökning
        app.logger.info(f"Received scan-from-zap request: target={target_site}, max_urls={max_urls}, session={session_name}")
        
        # Hämta cookies om en session angavs
        cookies = None
        if session_name:
            session_data = session_manager.load_cookies(session_name)
            if session_data:
                cookies = session_data.get('cookies')
                app.logger.info(f"Loaded cookies from session '{session_name}', cookie length: {len(cookies) if cookies else 0}")
                app.logger.debug(f"Cookie content (first 100 chars): {cookies[:100] if cookies else 'None'}")
            else:
                app.logger.warning(f"No session data found for '{session_name}'")
                
        # Kontrollera ZAP-status
        if not zap.is_available():
            app.logger.error("ZAP is not available for scan-from-zap")
            return jsonify({
                'error': 'ZAP is not available. Please check connection.',
                'status': 'failed'
            }), 500
        
        # Dummy-scanning - använda alltid SQL Injection Tester direkt utan ZAP sites
        if target_site:
            # Skapa ett manuellt test baserat på målsidan
            # Detta är en fallback om ZAP-integrationen inte fungerar
            try:
                app.logger.info(f"Starting direct SQL injection test for {target_site}")
                scan_id = sql_tester._generate_scan_id()
                scan_dir = os.path.join(sql_tester.storage_path, scan_id)
                os.makedirs(scan_dir, exist_ok=True)
                
                # Spara information om skanningen
                scan_info = {
                    'scan_id': scan_id,
                    'target_url': target_site,
                    'start_time': time.time(),
                    'status': 'running',
                    'cookies_used': cookies is not None,
                    'direct_test': True
                }
                
                with open(os.path.join(scan_dir, 'info.json'), 'w') as f:
                    json.dump(scan_info, f, indent=2)
                
                # Starta direktskanning i bakgrunden
                threading.Thread(
                    target=sql_tester._run_direct_scan,
                    args=(scan_id, target_site, cookies)
                ).start()
                
                session['sql_zap_scan_id'] = scan_id
                
                return jsonify({
                    'scan_id': scan_id,
                    'status': 'started',
                    'direct_test': True,
                    'message': 'Starting direct SQL injection test without ZAP integration'
                })
            except Exception as direct_e:
                app.logger.error(f"Error in direct testing: {str(direct_e)}", exc_info=True)
                # Fall tillbaka till ZAP-test om direkt test misslyckas
                pass
            
        try:
            # Logga ZAP-status och sites
            app.logger.info(f"ZAP is available, version: {zap.zap.core.version}")
            sites = zap.zap.core.sites
            app.logger.info(f"Found {len(sites)} sites in ZAP: {', '.join(sites)}")
                
            # Starta scanning baserat på ZAP-data
            result = sql_tester.scan_from_zap_results(zap, target_site, max_urls, cookies)
            
            # Logga resultatet
            app.logger.info(f"Scan-from-zap result: {result}")
            
            # Om scanning startades framgångsrikt, spara scan_id i sessionen
            if result.get('status') == 'started':
                session['sql_zap_scan_id'] = result['scan_id']
                
            return jsonify(result)
        except Exception as zap_e:
            app.logger.error(f"Error in ZAP-based testing: {str(zap_e)}", exc_info=True)
            return jsonify({
                'error': f"Error in ZAP-based test: {str(zap_e)}",
                'status': 'error'
            }), 500
    except Exception as e:
        app.logger.error(f"Error in scan-from-zap: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/sql-zap-status/<scan_id>')
def api_sql_zap_status(scan_id):
    """API-endpoint för att hämta status för SQL injection scan baserat på ZAP-data"""
    status = sql_tester.get_status(scan_id)
    return jsonify(status)

@app.route('/api/sql-zap-results/<scan_id>')
def api_sql_zap_results(scan_id):
    """API-endpoint för att hämta resultat från SQL injection scan baserat på ZAP-data"""
    if not scan_id:
        return jsonify({'error': 'No scan ID provided'}), 400
        
    results = sql_tester.get_results(scan_id)
    
    # Använd den förbättrade sammanfattningsmetoden
    try:
        summary = sql_tester.get_enhanced_summary(scan_id)
    except Exception as e:
        # Fallback till den ursprungliga sammanfattningsmetoden om den förbättrade misslyckas
        print(f"Error using enhanced summary, falling back to standard: {str(e)}")
        summary = sql_tester.get_summary(scan_id)
    
    return jsonify({
        'results': results,
        'summary': summary
    })

@app.route('/view-log')
def view_log():
    """Visar innehållet i en loggfil"""
    log_file = request.args.get('file')
    
    if not log_file or '..' in log_file:  # Enkel säkerhetskontroll
        return jsonify({'error': 'Invalid log file'}), 400
    
    log_path = os.path.join('./logs/sql_injection', log_file)
    
    if not os.path.exists(log_path):
        return jsonify({'error': 'Log file not found'}), 404
    
    try:
        with open(log_path, 'r') as f:
            log_content = f.read()
        
        # Returnera loggfilen som HTML med formatering
        return render_template('view_log.html', 
                               log_file=log_file,
                               log_content=log_content)
    except Exception as e:
        return jsonify({'error': f'Error reading log file: {str(e)}'}), 500

@app.route('/logs')
def logs_list():
    """Visar en lista över alla tillgängliga loggfiler"""
    return render_template('logs.html')



@app.route('/api/log-files')
def api_log_files():
    """API-endpoint för att lista alla SQL Injection loggfiler"""
    log_dir = './logs/sql_injection'
    
    try:
        # Kontrollera om katalogen finns
        if not os.path.exists(log_dir):
            return jsonify({'files': []})
        
        # Lista alla .log filer i katalogen
        files = []
        for file in os.listdir(log_dir):
            if file.endswith('.log'):
                file_path = os.path.join(log_dir, file)
                files.append({
                    'name': file,
                    'size': os.path.getsize(file_path),
                    'created': os.path.getctime(file_path),
                    'url': f'/view-log?file={file}'
                })
        
        # Sortera filer efter skapande-tid (nyast först)
        files.sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sql-scan-details/<scan_id>')
def api_sql_scan_details(scan_id):
    """API-endpoint för att få detaljerad information om en SQL injection scanning"""
    try:
        # Hämta statusfilen
        scan_dir = os.path.join(app.config['RESULTS_DIR'], 'sql_tester', scan_id)
        status_file = os.path.join(scan_dir, 'info.json')
        
        if not os.path.exists(status_file):
            return jsonify({
                'error': 'Scan not found',
                'scan_id': scan_id
            }), 404
            
        with open(status_file, 'r') as f:
            status_data = json.load(f)
            
        # Hämta resultatfilen om scanningen är klar
        results = []
        if status_data.get('status') == 'completed':
            results_file = os.path.join(scan_dir, 'results.json')
            
            if os.path.exists(results_file):
                with open(results_file, 'r') as f:
                    results = json.load(f)
        
        # Hämta eventuell loggfil
        log_dir = './logs/sql_injection'
        log_files = []
        
        if os.path.exists(log_dir):
            for file in os.listdir(log_dir):
                if file.endswith('.log'):
                    # Öppna och läs loggfilen för att se om den innehåller scan_id
                    log_path = os.path.join(log_dir, file)
                    try:
                        with open(log_path, 'r') as f:
                            log_content = f.read()
                            if scan_id in log_content:
                                log_files.append({
                                    'name': file,
                                    'url': f'/view-log?file={file}'
                                })
                    except:
                        pass
        
        # Sammanställ detaljerad info
        details = {
            'scan_id': scan_id,
            'status': status_data,
            'results_count': len(results),
            'logs': log_files,
            'urls_processed': status_data.get('processed_urls', 0),
            'urls_total': status_data.get('total_urls', 0),
            'progress_percent': status_data.get('progress_percent', 0),
            'start_time': status_data.get('start_time'),
            'duration': status_data.get('end_time', time.time()) - status_data.get('start_time', time.time()) if status_data.get('start_time') else 0
        }
        
        # Samla de senaste resultaten (upp till 10 st)
        if results:
            details['latest_findings'] = results[-10:] if len(results) > 10 else results
        
        return jsonify(details)
    except Exception as e:
        return jsonify({
            'error': str(e),
            'scan_id': scan_id
        }), 500

@app.route('/scan-details/<scan_id>')
def scan_details(scan_id):
    """Visa detaljerad information om en SQL injection scanning"""
    
    # Kontrollera att scanningen finns
    scan_dir = os.path.join(app.config['RESULTS_DIR'], 'sql_tester', scan_id)
    if not os.path.exists(scan_dir):
        flash('Scanning med angivet ID hittades inte.', 'danger')
        return redirect(url_for('scan'))
    
    return render_template('scan_details.html', scan_id=scan_id)
@app.route('/api/reset-zap', methods=['POST'])
def api_reset_zap():
    """Reset ZAP och skapa ny session med korrekt scope"""
    try:
        app.logger.info("Starting complete reset (ZAP and application session)...")
        target_url = session.get('target_url', '')
        
        # Reset ZAP using the existing functionality
        zap_reset_result = _zap_api_call('core/action/newSession', {
            'name': 'session',
            'overwrite': 'true'
        }, timeout=10)
        
        # Clear alerts
        alerts_result = _zap_api_call('core/action/deleteAllAlerts')
        
        # Clear the Flask session but remember target URL if set
        if target_url:
            temp_target_url = target_url
            session.clear()
            session['target_url'] = temp_target_url
        else:
            session.clear()
        
        # Om vi har en target_url, sätt scope baserat på denna
        if target_url:
            # Extrahera domän från URL för context scope
            from urllib.parse import urlparse
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            
            # Skapa ett nytt context för vår target
            context_name = "Target Context"
            context_result = _zap_api_call('context/action/newContext', {
                'contextName': context_name
            })
            
            if context_result['success']:
                app.logger.info(f"Created new context: {context_name}")
                
                # Sätt scope för denna domän (inkludera allt på domänen)
                include_pattern = f".*{domain}.*"
                include_result = _zap_api_call('context/action/includeInContext', {
                    'contextName': context_name,
                    'regex': include_pattern
                })
                
                if include_result['success']:
                    app.logger.info(f"Set context scope to include: {include_pattern}")
                else:
                    app.logger.warning(f"Failed to set context scope: {include_result.get('response', 'Unknown error')}")
                
                # Skapa en default HTTP session i ZAP
                session_result = _zap_api_call('httpSessions/action/createEmptySession', {
                    'site': target_url,
                    'session': 'Session 1'
                })
                
                if session_result['success']:
                    app.logger.info("Created default HTTP session: Session 1")
                    session['zap_session_name'] = 'Session 1'
                else:
                    app.logger.warning(f"Failed to create HTTP session: {session_result.get('response', 'Unknown error')}")
            else:
                app.logger.warning(f"Failed to create context: {context_result.get('response', 'Unknown error')}")
        
        return jsonify({
            'success': True,
            'message': 'ZAP och applikationssessionen har återställts',
            'zap_reset': zap_reset_result['success'],
            'target_set': bool(target_url),
            'scope_set': target_url and context_result.get('success', False) and include_result.get('success', False)
        })
    except Exception as e:
        app.logger.error(f"Error in complete reset: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/check-zap')
def api_check_zap():
    """Kontrollera ZAP-anslutningen"""
    try:
        # Prova att göra ett direkt HTTP-anrop till ZAP API:n
        
        direct_api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/core/view/version/"
        
        try:
            direct_response = requests.get(
                direct_api_url, 
                params={'apikey': ZAP_API_KEY},
                timeout=5
            )
            direct_success = direct_response.status_code == 200
            direct_content = direct_response.text if direct_success else f"Status code: {direct_response.status_code}"
        except Exception as direct_error:
            direct_success = False
            direct_content = str(direct_error)
        
        # Kontrollera om ZAP anses vara tillgänglig enligt applikationen
        is_available = zap.is_available()
        
        # Hämta detaljer om vad som händer i is_available-metoden
        available_details = "Unknown"
        try:
            # Detta är för debugging - anropa is_available med en parameter för att få mer info
            available_details = _debug_zap_availability()
        except Exception as debug_error:
            available_details = f"Error in debugging: {str(debug_error)}"
        
        return jsonify({
            'zap_available': is_available,
            'zap_config': {
                'host': ZAP_HOST,
                'port': ZAP_API_PORT,
                'api_key': ZAP_API_KEY[:3] + '***'  # Visa bara första tecknen av API-nyckeln
            },
            'direct_api_check': {
                'url': direct_api_url,
                'success': direct_success,
                'content': direct_content
            },
            'is_available_details': available_details
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

def _debug_zap_availability():
    """Hjälpfunktion för att debugga ZAP-tillgänglighet"""
    try:
        # Importera klassen direkt för att testa
        from zapv2 import ZAPv2
        test_zap = ZAPv2(apikey=ZAP_API_KEY, proxies=None)
        test_zap.base = f'http://{ZAP_HOST}:{ZAP_API_PORT}/'
        
        try:
            version = test_zap.core.version
            return {
                'connected': True,
                'version': version,
                'base_url': test_zap.base
            }
        except Exception as core_error:
            return {
                'connected': False,
                'error': str(core_error),
                'base_url': test_zap.base
            }
    except Exception as e:
        return {
            'connected': False,
            'import_error': str(e)
        }

def _zap_api_call(endpoint, params=None, timeout=5):
    """Wrap ZAP API calls for better error handling and logging"""
    
    if params is None:
        params = {}
    
    # Always include the API key
    params['apikey'] = ZAP_API_KEY
    
    # Construct the full URL
    url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/{endpoint}/"
    
    try:
        app.logger.debug(f"Making ZAP API call to: {url}")
        
        response = requests.get(url, params=params, timeout=timeout)
        
        if response.status_code == 200:
            app.logger.debug(f"API call to {endpoint} successful")
            return {
                'success': True,
                'data': response.json()
            }
        else:
            app.logger.warning(f"API call to {endpoint} failed. Status code: {response.status_code}")
            return {
                'success': False,
                'status_code': response.status_code,
                'error': f"API call returned status code {response.status_code}",
                'response_text': response.text
            }
    except Exception as e:
        app.logger.error(f"Error calling ZAP API endpoint {endpoint}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }



@app.route('/test-sql-injection-url')
def test_sql_injection_url():
    """Starta SQL injection-test för en specifik URL"""
    url = request.args.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter saknas'}), 400
    
    # Starta scanning
    try:
        result = sql_tester.start_scan(url)
        
        return jsonify({
            'status': 'started',
            'scan_id': result.get('scan_id'),
            'message': f'SQL injection-testning startad för {url}',
            'progress_url': f'/api/sqlmap-status/{result.get("scan_id")}'
        })
    except Exception as e:
        return jsonify({
            'error': f'Kunde inte starta SQL injection-test: {str(e)}'
        }), 500

def _direct_api_call(endpoint, params=None, timeout=15):
    """Perform a direct HTTP API call to ZAP with better error handling"""
    if params is None:
        params = {}
        
    # Always add the API key
    params['apikey'] = ZAP_API_KEY
    
    # Construct full URL
    url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/{endpoint}/"
    
    print(f"Making direct API call to: {url}")
    print(f"With parameters: {params}")
    
    try:
        # Make HTTP request
        import requests
        response = requests.get(url, params=params, timeout=timeout)
        
        if response.status_code == 200:
            try:
                data = response.json()
                #print(f"API response: {data}")
                return {
                    'success': True,
                    'data': data
                }
            except ValueError:
                # Failed to parse JSON
                print(f"API returned non-JSON response: {response.text[:100]}")
                return {
                    'success': False,
                    'error': 'Invalid JSON response',
                    'response': response.text[:100] + '...' if len(response.text) > 100 else response.text
                }
        else:
            #print(f"API call to {endpoint} failed with status {response.status_code}: {response.text}")
            return {
                'success': False,
                'status_code': response.status_code,
                'error': f"API call returned status code {response.status_code}",
                'response': response.text
            }
    except Exception as e:
        print(f"Exception in direct API call to {endpoint}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

@app.route('/api/ajax-spider/start', methods=['POST'])
def api_ajax_spider_start():
    """API-endpoint för att starta Ajax Spider asynkront"""
    try:
        data = request.json
        target_url = data.get('target_url')
        
        if not target_url:
            return jsonify({'error': 'No target URL specified'}), 400
        
        # Hämta cookies om sådana finns i sessionen
        cookies = None
        session_name = data.get('session_name')
        
        if session_name:
            try:
                session_data = session_manager.load_cookies(session_name)
                if session_data:
                    cookies = session_data.get('cookies')
                    print(f"Loaded cookies from session '{session_name}', length: {len(cookies) if cookies else 0}")
            except Exception as e:
                print(f"Error loading session cookies: {str(e)}")
        
        # Start Ajax Spider using our direct function
        try:
            result = start_ajax_spider_direct(target_url, cookies)
            
            # Store session information for status checking
            session['ajax_spider_running'] = True
            
            return jsonify({
                'status': 'started',
                'target_url': target_url,
                'message': 'Ajax Spider started successfully'
            })
        except Exception as e:
            print(f"Error starting Ajax Spider: {str(e)}")
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500
    except Exception as e:
        print(f"General error in Ajax Spider start API: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

def start_ajax_spider_direct(target_url):
    """Start Ajax Spider using the active session"""
    try:
        print(f'Starting Ajax Spider for target: {target_url}')
        
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ajaxSpider/action/scan/"
        params = {
            'url': target_url,
            'apikey': ZAP_API_KEY
        }
        
        print(f"Ajax Spider parameters: {params}")
        
        import requests
        response = requests.get(api_url, params=params)
        
        if response.status_code != 200:
            error_message = f"API call failed with status {response.status_code}: {response.text}"
            print(error_message)
            raise Exception(error_message)
        
        data = response.json()
        print(f"Ajax Spider response: {data}")
        
        return "OK"
    except Exception as e:
        print(f'Error starting Ajax Spider: {str(e)}')
        raise e

def run_ajax_spider_in_background(scan_id, target_url, cookies=None):
    """Kör Ajax Spider i bakgrunden och uppdatera resultaten"""
    try:
        # Spara status som "running"
        with scan_status_lock:
            scan_statuses[scan_id] = {
                'status': 'running',
                'progress': 0,
                'start_time': time.time(),
                'target_url': target_url,
                'type': 'ajax_spider'
            }
        
        # Skapa kontext med cookies om sådana finns
        context_id = None
        if cookies:
            try:
                context_id = zap._create_context_with_session(target_url, cookies)
                print(f"Created context with ID: {context_id} for Ajax Spider")
            except Exception as e:
                print(f"Error creating context with session: {str(e)}")
        
        # Starta Ajax Spider
        ajax_scan_id = zap.zap.ajaxSpider.scan(target_url, contextname=context_id)
        
        # Spara initiala resultat
        with scan_status_lock:
            scan_statuses[scan_id].update({
                'progress': 10,
                'ajax_scan_id': ajax_scan_id
            })
        
        # Övervaka framsteg
        is_running = True
        while is_running:
            try:
                status = zap.zap.ajaxSpider.status
                is_running = status == "running"
                
                # Beräkna framsteg baserat på antal upptäckta resurser
                try:
                    num_resources = len(zap.zap.ajaxSpider.results())
                    # Sätt framsteg till mellan 10% och 90% baserat på antal resurser
                    progress = min(90, 10 + num_resources)
                    
                    with scan_status_lock:
                        scan_statuses[scan_id]['progress'] = progress
                        scan_statuses[scan_id]['resources_found'] = num_resources
                except Exception as e:
                    print(f"Error checking Ajax Spider results: {str(e)}")
                
                time.sleep(5)
            except Exception as e:
                print(f"Error monitoring Ajax Spider: {str(e)}")
                is_running = False
        
        # Skanning klar
        results = zap.zap.ajaxSpider.results()
        
        with scan_status_lock:
            scan_statuses[scan_id].update({
                'status': 'completed',
                'progress': 100,
                'completion_time': time.time(),
                'results_count': len(results)
            })
            
        # Spara fullständiga resultat till fil
        results_dir = os.path.join(app.config['RESULTS_DIR'], 'ajax_spider')
        os.makedirs(results_dir, exist_ok=True)
        
        results_file = os.path.join(results_dir, f"{scan_id}.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"Saved Ajax Spider results to {results_file}")
            
    except Exception as e:
        # Fel vid skanning
        with scan_status_lock:
            scan_statuses[scan_id].update({
                'status': 'error',
                'error': str(e)
            })
        print(f"Error in Ajax Spider scan: {str(e)}")

@app.route('/api/ajax-spider/results')
def api_ajax_spider_results():
    """API-endpoint för att hämta Ajax Spider resultat"""
    try:
        # Ensure requests is properly imported
        
        
        # Kontrollera ZAP-status
        if not zap.is_available():
            return jsonify({
                'error': 'ZAP är inte tillgänglig. Kontrollera anslutningen.',
                'status': 'failed'
            }), 500
        
        # Hämta resultat with direct HTTP call
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ajaxSpider/view/results/"
        response = requests.get(
            api_url,
            params={
                'apikey': ZAP_API_KEY
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            
            return jsonify({
                'status': 'success',
                'results': results,
                'count': len(results)
            })
        else:
            return jsonify({
                'status': 'error',
                'error': f"API call failed with status code {response.status_code}: {response.text}"
            }), 500
    except Exception as e:
        app.logger.error(f"Error getting Ajax Spider results: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/ajax-spider/stop', methods=['POST'])
def api_stop_ajax_spider():
    """API-endpoint för att stoppa Ajax Spider scanning"""
    try:
        # Ensure requests is properly imported

        # Kontrollera ZAP-status
        if not zap.is_available():
            return jsonify({
                'error': 'ZAP är inte tillgänglig. Kontrollera anslutningen.',
                'status': 'failed'
            }), 500
        
        # Stoppa Ajax Spider with direct HTTP call
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ajaxSpider/action/stop/"
        response = requests.get(
            api_url,
            params={
                'apikey': ZAP_API_KEY
            },
            timeout=10
        )
        
        if response.status_code == 200:
            return jsonify({
                'status': 'stopped'
            })
        else:
            return jsonify({
                'status': 'error',
                'error': f"API call failed with status code {response.status_code}: {response.text}"
            }), 500
    except Exception as e:
        app.logger.error(f"Error stopping Ajax Spider: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/ajax-spider-results')
def ajax_spider_results():
    """View for Ajax Spider results"""
    target_url = session.get('target_url', '')
    
    return render_template('ajax_spider_results.html', target_url=target_url)

def analyze_ajax_spider_results(results):
    """Analyserar Ajax Spider-resultat och extraherar strukturinformation."""
    
    if not results or not isinstance(results, list):
        return {"error": "Inga resultat eller felaktigt format"}
    
    summary = {
        "total_items": len(results),
        "sample_item": results[0] if results else None,
        "keys_frequency": {},
        "structure_overview": {},
        "url_examples": [],
        "status_code_distribution": {}
    }
    
    # Räkna frekvensen av olika nycklar
    for item in results:
        if not isinstance(item, dict):
            continue
            
        for key in item.keys():
            summary["keys_frequency"][key] = summary["keys_frequency"].get(key, 0) + 1
    
    # Extrahera statuskodinformation från responseHeader
    for i, item in enumerate(results[:min(100, len(results))]):  # Undersök max 100 poster
        if not isinstance(item, dict):
            continue
            
        response_header = item.get('responseHeader', '')
        request_header = item.get('requestHeader', '')
        
        # Extrahera statuskod
        status_code = None
        if response_header:
            try:
                first_line = response_header.split('\r\n')[0]
                parts = first_line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    status_code = int(parts[1])
                    summary["status_code_distribution"][status_code] = summary["status_code_distribution"].get(status_code, 0) + 1
            except:
                pass
        
        # Extrahera URL och metod
        url = None
        method = None
        if request_header:
            try:
                first_line = request_header.split('\r\n')[0]
                parts = first_line.split()
                if len(parts) >= 3:
                    method = parts[0]
                    url = parts[1]
                    
                    # Spara några exempel på URL:er
                    if len(summary["url_examples"]) < 5 and url:
                        summary["url_examples"].append({
                            "url": url, 
                            "method": method, 
                            "status_code": status_code
                        })
            except:
                pass
    
    # Analyser strukturen på första objektet
    if summary["sample_item"]:
        for key, value in summary["sample_item"].items():
            value_type = type(value).__name__
            summary["structure_overview"][key] = {
                "type": value_type,
                "example": str(value)[:100] + ('...' if len(str(value)) > 100 else '')
            }
    
    return summary

def transform_ajax_spider_results(raw_results):
    """Transformerar råa Ajax Spider-resultat till det format som templates förväntar sig."""
    transformed = []
    
    for item in raw_results:
        # Extrahera URL och metod från requestHeader
        url = ""
        method = "GET"  # standard
        
        if "requestHeader" in item:
            request_header = item["requestHeader"]
            first_line = request_header.split('\r\n')[0] if '\r\n' in request_header else request_header
            parts = first_line.split(' ', 2)  # Split max 2 times: METHOD URL HTTP_VERSION
            if len(parts) >= 2:
                method = parts[0]
                url = parts[1]
        
        # Extrahera statuskod från responseHeader
        status_code = None
        if "responseHeader" in item:
            response_header = item["responseHeader"]
            first_line = response_header.split('\r\n')[0] if '\r\n' in response_header else response_header
            parts = first_line.split(' ', 2)  # Split max 2 times: HTTP_VERSION STATUS_CODE STATUS_TEXT
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])
        
        # Skapa nytt objekt med rätt struktur
        transformed_item = {
            'url': url,
            'method': method,
            'statusCode': status_code,
            # Lägg till andra egenskaper vid behov
            'id': item.get('id'),
            'timestamp': item.get('timestamp'),
            'cookieParams': item.get('cookieParams', '')
        }
        
        transformed.append(transformed_item)
    
    return transformed

@app.route('/api/ajax-spider-analysis')
def ajax_spider_analysis():
    """API-endpoint för att analysera Ajax Spider-resultat"""
    try:
        # Anropa din befintliga funktion för att hämta resultat
        results = zap.get_ajax_spider_results()
        
        # Analysera resultaten
        analysis = analyze_ajax_spider_results(results)
        
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ajax-spider/status/<scan_id>')
def api_ajax_spider_status(scan_id):
    """API-endpoint för att hämta status för en Ajax Spider-scanning"""
    with scan_status_lock:
        status = scan_statuses.get(scan_id)
        
    if not status or status.get('type') != 'ajax_spider':
        return jsonify({'error': 'Ajax Spider scan not found'}), 404
        
    return jsonify(status)

def start_active_scan_direct(target_url):
    """Start active scanning using the active session and context"""
    try:
        print(f'Active scanning target: {target_url}')
        
        # Förbered parametrar
        params = {
            'url': target_url,
            'apikey': ZAP_API_KEY,
            'recurse': 'true'
        }
        
        # Lägg till context ID om det finns ett
        context_exists = False
        context_name = "Target Context"
        
        try:
            contexts_result = _direct_api_call('context/view/contextList')
            if contexts_result['success']:
                context_list = contexts_result['data'].get('contextList', [])
                if context_name in context_list:
                    context_exists = True
                    # Hämta context ID
                    context_result = _direct_api_call('context/view/context', {
                        'contextName': context_name
                    })
                    if context_result['success'] and 'context' in context_result['data']:
                        context_id = context_result['data']['context'].get('id')
                        if context_id:
                            params['contextId'] = context_id
                            print(f"Using context ID: {context_id} for Active Scan")
        except Exception as e:
            print(f"Error getting context: {str(e)}")
        
        # Gör API-anrop för att starta active scan
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ascan/action/scan/"
        print(f"Active scan parameters: {params}")
        
        import requests
        response = requests.get(api_url, params=params)
        
        if response.status_code != 200:
            error_message = f"API call failed with status {response.status_code}: {response.text}"
            print(error_message)
            raise Exception(error_message)
        
        data = response.json()
        scan_id = data.get('scan')
        
        return scan_id
    except Exception as e:
        print(f'Error starting active scan: {str(e)}')
        raise e

def start_spider_direct(target_url):
    """Start ZAP spider using the active session and context"""
    try:
        print(f'Spidering target: {target_url}')
        
        # Förbered parametrar
        params = {
            'url': target_url,
            'apikey': ZAP_API_KEY,
            'recurse': 'true'
        }
        
        # Lägg till context ID om det finns ett
        context_exists = False
        context_name = "Target Context"
        
        try:
            contexts_result = _direct_api_call('context/view/contextList')
            if contexts_result['success']:
                context_list = contexts_result['data'].get('contextList', [])
                if context_name in context_list:
                    context_exists = True
                    # Hämta context ID
                    context_result = _direct_api_call('context/view/context', {
                        'contextName': context_name
                    })
                    if context_result['success'] and 'context' in context_result['data']:
                        context_id = context_result['data']['context'].get('id')
                        if context_id:
                            params['contextId'] = context_id
                            print(f"Using context ID: {context_id} for Spider")
        except Exception as e:
            print(f"Error getting context: {str(e)}")
        
        # Gör API-anrop för att starta spider
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/spider/action/scan/"
        print(f"Spider parameters: {params}")
        
        import requests
        response = requests.get(api_url, params=params)
        
        if response.status_code != 200:
            error_message = f"API call failed with status {response.status_code}: {response.text}"
            print(error_message)
            raise Exception(error_message)
        
        data = response.json()
        scan_id = data.get('scan')
        
        return scan_id
    except Exception as e:
        print(f'Error starting spider scan: {str(e)}')
        raise e


def test_zap_functionality():
    """Test basic ZAP functionality to identify issues"""
    results = {
        "success": False,
        "messages": [],
        "errors": []
    }
    
    try:
        # Test 1: Check ZAP version
        version_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/core/view/version/"
        version_params = {'apikey': ZAP_API_KEY}
        
        import requests
        version_response = requests.get(version_url, params=version_params)
        
        if version_response.status_code == 200:
            version_data = version_response.json()
            results["messages"].append(f"ZAP version: {version_data.get('version', 'unknown')}")
        else:
            results["errors"].append(f"Failed to get ZAP version: {version_response.text}")
            return results  # Stop if basic connectivity fails
            
        # Test 2: Create a simple context
        context_name = f"test-context-{int(time.time())}"
        context_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/context/action/newContext/"
        context_params = {'contextName': context_name, 'apikey': ZAP_API_KEY}
        
        context_response = requests.get(context_url, params=context_params)
        
        if context_response.status_code == 200:
            results["messages"].append(f"Created test context: {context_name}")
            
            # Test 3: Try to include a URL pattern in context
            include_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/context/action/includeInContext/"
            include_params = {
                'contextName': context_name, 
                'regex': '.*example\\.com.*',
                'apikey': ZAP_API_KEY
            }
            
            include_response = requests.get(include_url, params=include_params)
            
            if include_response.status_code == 200:
                results["messages"].append("Successfully included URL pattern in context")
            else:
                results["errors"].append(f"Failed to include URL in context: {include_response.text}")
        else:
            results["errors"].append(f"Failed to create test context: {context_response.text}")
        
        # Test 4: Check sites
        sites_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/core/view/sites/"
        sites_params = {'apikey': ZAP_API_KEY}
        
        sites_response = requests.get(sites_url, params=sites_params)
        
        if sites_response.status_code == 200:
            sites_data = sites_response.json()
            sites = sites_data.get('sites', [])
            results["messages"].append(f"Found {len(sites)} sites in ZAP")
        else:
            results["errors"].append(f"Failed to get sites: {sites_response.text}")
            
        # Final result
        results["success"] = len(results["errors"]) == 0
        return results
    except Exception as e:
        results["errors"].append(f"Exception in ZAP test: {str(e)}")
        return results

@app.route('/test-zap')
def test_zap():
    """Test ZAP functionality directly"""
    results = test_zap_functionality()
    return jsonify(results)


@app.route('/api/sessions')
def api_sessions():
    """API endpoint för att lista alla sessioner"""
    try:
        # Hämta target URL från session
        target_url = session.get('target_url', '')
        
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'Ingen target URL speciferad',
                'sessions': []
            })
        
        # Hämta sessioner från ZAP API
        from urllib.parse import urlparse
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        result = _direct_api_call('httpSessions/view/sessions', {
            'site': target_url  # Använd full URL för att matcha ZAP:s interna format
        })
        
        if not result['success']:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Okänt fel'),
                'sessions': []
            })
        
        # Transformera resultatet till ett enklare format
        zap_sessions = result['data'].get('sessions', [])
        sessions = []
        
        for s in zap_sessions:
            if isinstance(s, list) and len(s) > 0:
                name = s[0]
                active = False  # Behöver ett extra anrop för att kolla aktiv status
                sessions.append({
                    'name': name,
                    'site': domain,
                    'active': active,
                    'created': time.time() * 1000  # Simulera timestamp
                })
            elif isinstance(s, dict) and 'session' in s:
                session_data = s['session']
                if isinstance(session_data, list) and len(session_data) > 0:
                    name = session_data[0]
                    active = False
                    sessions.append({
                        'name': name,
                        'site': domain,
                        'active': active,
                        'created': time.time() * 1000
                    })
        
        # Hämta aktiv session
        active_result = _direct_api_call('httpSessions/view/activeSession', {
            'site': target_url
        })
        
        if active_result['success']:
            active_session = active_result['data'].get('activeSession')
            # Markera aktiv session
            for s in sessions:
                if s['name'] == active_session:
                    s['active'] = True
        
        return jsonify({
            'success': True,
            'sessions': sessions
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'sessions': []
        })

@app.route('/api/create-session', methods=['POST'])
def api_create_session():
    """API endpoint för att skapa en ny session med korrekt scope"""
    try:
        data = request.json
        session_name = data.get('session_name')
        target_url = data.get('target_url', session.get('target_url'))
        
        if not session_name:
            return jsonify({
                'success': False,
                'error': 'Inget sessionsnamn angett'
            })
        
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'Ingen target URL angiven'
            })
        
        # Extrahera domän från URL för context scope
        from urllib.parse import urlparse
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        # Kontrollera om vi behöver skapa en kontext
        context_name = "Target Context"
        context_exists = False
        
        contexts_result = _direct_api_call('context/view/contextList')
        if contexts_result['success']:
            context_list = contexts_result['data'].get('contextList', [])
            for ctx in context_list:
                if ctx == context_name:
                    context_exists = True
                    break
        
        # Skapa kontext om den inte finns
        if not context_exists:
            context_result = _direct_api_call('context/action/newContext', {
                'contextName': context_name
            })
            
            if context_result['success']:
                app.logger.info(f"Created new context: {context_name}")
                
                # Sätt scope för denna domän (inkludera allt på domänen)
                include_pattern = f".*{domain}.*"
                include_result = _direct_api_call('context/action/includeInContext', {
                    'contextName': context_name,
                    'regex': include_pattern
                })
                
                if include_result['success']:
                    app.logger.info(f"Set context scope to include: {include_pattern}")
                else:
                    app.logger.warning(f"Failed to set context scope: {include_result.get('response', 'Unknown error')}")
            else:
                app.logger.warning(f"Failed to create context: {context_result.get('response', 'Unknown error')}")
        
        # Skapa en ny tom session
        create_result = _direct_api_call('httpSessions/action/createEmptySession', {
            'site': target_url,
            'session': session_name
        })
        
        if not create_result['success']:
            return jsonify({
                'success': False,
                'error': f"Kunde inte skapa session: {create_result.get('error', 'Okänt fel')}"
            })
        
        # Sätt sessionen som aktiv
        active_result = _direct_api_call('httpSessions/action/setActiveSession', {
            'site': target_url,
            'session': session_name
        })
        
        # Spara vald session i Flask-sessionen
        session['zap_session_name'] = session_name
        
        # Sätt även target URL i sessionen om det inte redan finns
        if 'target_url' not in session:
            session['target_url'] = target_url
        
        return jsonify({
            'success': True,
            'message': f"Session {session_name} skapad och aktiverad, scope satt till {domain}",
            'context_created': not context_exists
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/activate-session', methods=['POST'])
def api_activate_session():
    """API endpoint för att aktivera en befintlig session"""
    try:
        data = request.json
        session_name = data.get('session_name')
        target_url = data.get('target_url', session.get('target_url'))
        
        if not session_name:
            return jsonify({
                'success': False,
                'error': 'Inget sessionsnamn angett'
            })
        
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'Ingen target URL angiven'
            })
        
        # Sätt sessionen som aktiv
        active_result = _direct_api_call('httpSessions/action/setActiveSession', {
            'site': target_url,
            'session': session_name
        })
        
        if not active_result['success']:
            return jsonify({
                'success': False,
                'error': f"Kunde inte aktivera session: {active_result.get('error', 'Okänt fel')}"
            })
        
        # Spara vald session i Flask-sessionen
        session['zap_session_name'] = session_name
        
        return jsonify({
            'success': True,
            'message': f"Session {session_name} aktiverad"
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

def report():
    """Rapportvy med förbättrad sårbarhetsvisning"""
    # Kontrollera om det finns ett mål-URL i sessionen
    target_url = session.get('target_url', '')
    if not target_url:
        flash("Inget mål-URL konfigurerat. Vänligen konfigurera ett mål först.", "warning")
        return redirect(url_for('target'))
    
    # Generera ett rapport-ID
    report_id = str(uuid.uuid4())
    
    return render_template(
        'report.html',
        report_id=report_id,
        target_url=target_url,
        debug_mode=False  # Pass this explicitly
    )

@app.route('/api/zap-alerts-by-risk')
def api_zap_alerts_by_risk():
    """Hämta sårbarheter grupperade efter risknivå"""
    target_url = session.get('target_url', '')
    
    if not target_url:
        return jsonify({'error': 'No target URL in session'}), 400
    
    try:
        # Kontrollera om ZAP är tillgänglig
        if not zap.is_available():
            return jsonify({'error': 'ZAP is not available'}), 503
        
        # Anropa ZAP API för att hämta sårbarheter efter risk
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alertsByRisk/"
        response = requests.get(api_url, params={
            'apikey': ZAP_API_KEY,
            'url': target_url,
            'recurse': 'true'
        }, timeout=10)
        
        if response.status_code != 200:
            return jsonify({'error': f'ZAP API returned status code {response.status_code}'}), 500
        
        # Få rådata
        raw_data = response.json()
        
        # Omstrukturera data för att matcha förväntad format
        # Extrahera alerts från nästlad struktur till en plattare struktur
        processed_data = {
            'highAlerts': [],
            'mediumAlerts': [],
            'lowAlerts': [],
            'infoAlerts': []
        }
        
        # Loopa igenom raw_data för att extrahera alerts
        if 'alertsByRisk' in raw_data:
            for risk_group in raw_data['alertsByRisk']:
                # Processa High alerts
                if 'High' in risk_group:
                    for alert_type in risk_group['High']:
                        for alert_name, alerts in alert_type.items():
                            for alert in alerts:
                                alert['name'] = alert_name  # Lägg till namnet i alert-objektet
                                processed_data['highAlerts'].append(alert)
                
                # Processa Medium alerts
                if 'Medium' in risk_group:
                    for alert_type in risk_group['Medium']:
                        for alert_name, alerts in alert_type.items():
                            for alert in alerts:
                                alert['name'] = alert_name
                                processed_data['mediumAlerts'].append(alert)
                
                # Processa Low alerts
                if 'Low' in risk_group:
                    for alert_type in risk_group['Low']:
                        for alert_name, alerts in alert_type.items():
                            for alert in alerts:
                                alert['name'] = alert_name
                                processed_data['lowAlerts'].append(alert)
                
                # Processa Informational alerts
                if 'Informational' in risk_group:
                    for alert_type in risk_group['Informational']:
                        for alert_name, alerts in alert_type.items():
                            for alert in alerts:
                                alert['name'] = alert_name
                                processed_data['infoAlerts'].append(alert)
        
        # Hämta sammanfattning
        summary_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alertsSummary/"
        summary_response = requests.get(summary_url, params={
            'apikey': ZAP_API_KEY,
            'baseurl': target_url
        }, timeout=10)
        
        if summary_response.status_code != 200:
            return jsonify({'error': f'ZAP API returned status code {summary_response.status_code}'}), 500
        
        # Extrahera summary från nästlad struktur
        raw_summary = summary_response.json()
        summary = {}
        
        if 'alertsSummary' in raw_summary:
            summary = raw_summary['alertsSummary']
        
        # Kombinera resultaten
        result = {
            'alerts_by_risk': processed_data,
            'summary': summary
        }
        
        # Logga för felsökning
        # app.logger.debug(f"Processed data: {json.dumps(processed_data)}")
        app.logger.debug(f"Summary: {json.dumps(summary)}")
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error fetching ZAP alerts: {str(e)}")
        return jsonify({'error': f'Error fetching ZAP alerts: {str(e)}'}), 500


@app.route('/api/download-report/<report_id>')
def api_download_report(report_id):
    """API för att hämta hela rapporten som JSON"""
    target_url = session.get('target_url', '')
    
    if not target_url:
        return jsonify({'error': 'No target URL in session'}), 400
    
    try:
        # Försök att hitta en befintlig rapport
        reports_dir = os.path.join(app.config['RESULTS_DIR'], 'reports')
        report_path = os.path.join(reports_dir, f"{report_id}.json")
        
        # Om rapporten inte finns, genererar vi den på begäran
        if not os.path.exists(report_path):
            # Hämta ZAP-sårbarheter via vår egen API (för att få samma format)
            api_response = api_zap_alerts_by_risk()
            
            # Om det är ett JSONify-objekt, extrahera data
            if hasattr(api_response, 'json'):
                alerts_data = api_response.json
            else:
                # Annars är det en tuple med (response, status_code)
                alerts_data = api_response[0]
            
            # Skapa rapport
            report_data = {
                'id': report_id,
                'timestamp': time.time(),
                'report_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'target_url': target_url,
                'zap_available': zap.is_available(),
                'alerts_by_risk': alerts_data.get('alerts_by_risk', {}),
                'summary': alerts_data.get('summary', {})
            }
            
            # Räkna antalet sårbarheter per risknivå
            if 'summary' in alerts_data:
                report_data['severity_counts'] = {
                    'high': alerts_data['summary'].get('High', 0),
                    'medium': alerts_data['summary'].get('Medium', 0),
                    'low': alerts_data['summary'].get('Low', 0),
                    'informational': alerts_data['summary'].get('Informational', 0)
                }
            
            # Spara rapporten till disk
            try:
                os.makedirs(reports_dir, exist_ok=True)
                
                with open(report_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
                    
                return jsonify(report_data)
            except Exception as save_error:
                app.logger.warning(f"Could not save report to disk: {str(save_error)}")
                return jsonify(report_data)  # Returnera data även om vi inte kunde spara den
        else:
            # Läs befintlig rapport från disk
            with open(report_path, 'r') as f:
                report_data = json.load(f)
            return jsonify(report_data)
            
    except Exception as e:
        app.logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': f'Error generating report: {str(e)}'}), 500

@app.route('/debug-zap-api')
def debug_zap_api():
    """Debug-sida för ZAP API-anrop"""
    target_url = session.get('target_url', '')
    
    result = {
        'target_url': target_url,
        'raw_api_calls': {}
    }
    
    if not target_url:
        result['error'] = 'No target URL in session'
        return jsonify(result)
    
    try:
        # Kontrollera om ZAP är tillgänglig
        zap_available = zap.is_available()
        result['zap_available'] = zap_available
        
        if not zap_available:
            result['error'] = 'ZAP is not available'
            return jsonify(result)
        
        # Testa direkt API-anrop till alertsByRisk
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alertsByRisk/"
        response = requests.get(api_url, params={
            'apikey': ZAP_API_KEY,
            'url': target_url,
            'recurse': 'true'
        }, timeout=10)
        
        result['raw_api_calls']['alertsByRisk'] = {
            'url': api_url,
            'params': {
                'apikey': '***',
                'url': target_url,
                'recurse': 'true'
            },
            'status_code': response.status_code,
            'response': response.json() if response.status_code == 200 else response.text
        }
        
        # Testa direkt API-anrop till alertsSummary
        summary_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alertsSummary/"
        summary_response = requests.get(summary_url, params={
            'apikey': ZAP_API_KEY,
            'baseurl': target_url
        }, timeout=10)
        
        result['raw_api_calls']['alertsSummary'] = {
            'url': summary_url,
            'params': {
                'apikey': '***',
                'baseurl': target_url
            },
            'status_code': summary_response.status_code,
            'response': summary_response.json() if summary_response.status_code == 200 else summary_response.text
        }
        
        # Testa vår bearbetade API-endpoint
        result['processed_api'] = requests.get(url_for('api_zap_alerts_by_risk', _external=True)).json()
        
        return jsonify(result)
    except Exception as e:
        result['error'] = str(e)
        result['traceback'] = traceback.format_exc()
        return jsonify(result)

@app.route('/debug-report-view')
def debug_report_view():
    """Debug-sida för rapport-vyn"""
    target_url = session.get('target_url', '')
    
    # Generera ett testrapport-ID
    report_id = f"debug-{str(uuid.uuid4())[:8]}"
    
    # Lägg till debug-info i sessionen
    session['debug_mode'] = True
    
    return render_template(
        'report.html',
        report_id=report_id,
        target_url=target_url,
        debug_mode=True
    )
 
@app.route('/api/alert-details/<alert_id>')
def api_alert_details(alert_id):
    """API-endpoint för att hämta detaljerad information om en alert"""
    try:
        # Kontrollera att ZAP är tillgänglig
        if not zap.is_available():
            return jsonify({
                'error': 'ZAP is not available'
            }), 503
        
        # Anropa ZAP API för att hämta detaljerad information
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alert/"
        params = {
            'id': alert_id,
            'apikey': ZAP_API_KEY
        }
        
        # Gör HTTP-anrop
        import requests
        response = requests.get(api_url, params=params, timeout=15)
        
        # Hantera svar
        if response.status_code != 200:
            return jsonify({
                'error': f'API call failed with status {response.status_code}: {response.text}'
            }), 500
        
        data = response.json()
        return jsonify(data)
    except Exception as e:
        app.logger.error(f"Error fetching alert details: {str(e)}")
        return jsonify({
            'error': str(e)
        }), 500

def get_alerts_with_ids():
    """Hämta alerts från ZAP med ID-fält säkerställt"""
    try:
        alerts = zap.get_alerts()
        
        # Om ID saknas i någon alert, lägg till det
        for i, alert in enumerate(alerts):
            if 'id' not in alert:
                # Använd alertRef eller pluginId om tillgängligt, annars använd index
                alert_id = alert.get('alertRef') or alert.get('pluginId') or str(i)
                alert['id'] = str(alert_id)
        
        return alerts
    except Exception as e:
        app.logger.error(f"Error getting alerts with IDs: {str(e)}")
        return []

if __name__ == '__main__':
    test_zap_functionality()
    app.run(host='0.0.0.0', port=5001, debug=True)


