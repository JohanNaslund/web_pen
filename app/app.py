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
import socket
import subprocess
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
import tempfile
from flask import make_response


active_recordings = {}

#from modules.sql_injection_tester import SQLInjectionTester

from modules.access_control_manager import AccessControlManager


def get_local_ip():
    """Hämta lokal IP-adress automatiskt"""
    try:
        # Metod 1: Anslut till en extern adress för att få lokal IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            # Anslut till en adress (behöver inte vara nåbar)
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
    except Exception:
        return '127.0.0.1'

def get_ubuntu_ip():
    """Hämta IP med Ubuntu-kommandon som fallback"""
    try:
        # Använd hostname -I för att få alla IP-adresser
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # Ta första IP-adressen (oftast den primära)
            ips = result.stdout.strip().split()
            if ips:
                return ips[0]
    except Exception as e:
        print(f"Error getting IP with hostname: {e}")
    
    # Fallback till ip route
    try:
        result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # Extrahera IP från output
            for line in result.stdout.split('\n'):
                if 'src' in line:
                    parts = line.split()
                    src_index = parts.index('src')
                    if src_index + 1 < len(parts):
                        return parts[src_index + 1]
    except Exception as e:
        print(f"Error getting IP with ip route: {e}")
    
    return '127.0.0.1'

def get_server_ip():
    """Kombinerad funktion för att få bästa IP-adress"""
    # Prova socket-metoden först
    ip = get_local_ip()
    
    # Om vi bara får localhost, prova Ubuntu-kommandon
    if ip == '127.0.0.1':
        ip = get_ubuntu_ip()
    
    return ip

app = Flask(__name__)
app.secret_key = os.urandom(24)  # För sessionshantering
csrf = CSRFProtect(app)


ZAP_API_KEY = 'wsaYdB64K4'
ZAP_HOST = get_server_ip()
PROXY_HOST = ZAP_HOST
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

'''sql_tester = SQLInjectionTester(storage_path='./data/sql_tester')'''
session_manager = SessionManager(storage_path='./data/sessions')
'''report_generator = ReportGenerator(storage_path='./data/reports')'''

access_control_manager = AccessControlManager(zap)



@app.route('/access-control')
def access_control():
    """Access Control Testing huvudsida med förbättrad session-hantering"""
    
    # Kontrollera om det finns ett mål-URL från huvudkonfigurationen
    target_url = session.get('target_url', '')
    
    if not target_url:
        flash("Inget mål-URL konfigurerat. Gå till startsidan och konfigurera ett mål först.", "warning")
        return redirect(url_for('target'))
    
    # Kontrollera att ZAP är tillgänglig
    zap_available = zap.is_available()
    if not zap_available:
        flash("ZAP är inte tillgänglig. Kontrollera att ZAP körs.", "danger")
    
    # Kontrollera om det finns en aktiv inspelning
    recording_id = session.get('active_recording_id')
    is_recording = recording_id and recording_id in active_recordings
    
    # Hämta information om aktiv inspelning om den finns
    recording_data = None
    if is_recording:
        recording_data = active_recordings[recording_id]
        # Lägg till duration
        current_time = time.time()
        recording_data['duration'] = current_time - recording_data['start_timestamp']
        recording_data['duration_formatted'] = f"{int(recording_data['duration']//60):02d}:{int(recording_data['duration']%60):02d}"
    
    return render_template('access_control.html',  # Ändra till den nya templaten
                          target_url=target_url,
                          zap_available=zap_available,
                          is_recording=is_recording,
                          recording_data=recording_data)

@app.route('/api/access-control/reset-zap', methods=['POST'])
def api_access_control_reset_zap():
    """Nollställ ZAP för Access Control Testing"""
    try:
        result = access_control_manager.reset_for_new_test()
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/access-control/collect-urls', methods=['POST'])
def api_access_control_collect_urls():
    """Samla URL:er från nuvarande ZAP-session"""
    try:
        data = request.json
        session_label = data.get('session_label', 'unknown')
        target_url = data.get('target_url', session.get('target_url', ''))
        
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'Ingen target URL angiven'
            }), 400
        
        result = access_control_manager.collect_session_urls(session_label, target_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/access-control/sessions')
def api_access_control_list_sessions():
    """Lista alla insamlade sessioner"""
    try:
        sessions = access_control_manager.list_collected_sessions()
        return jsonify({
            'success': True,
            'sessions': sessions
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/access-control/session/<session_filename>')
def api_access_control_get_session(session_filename):
    """Hämta detaljer för en specifik session"""
    try:
        result = access_control_manager.get_session_urls(session_filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/access-control/test', methods=['POST'])
def api_access_control_test():
    """Starta Access Control test"""
    try:
        data = request.json
        source_session_file = data.get('source_session_file')
        test_cookies = data.get('test_cookies', '')
        test_label = data.get('test_label', 'test_user')
        selected_urls = data.get('selected_urls')  # Optional
        
        if not source_session_file:
            return jsonify({
                'success': False,
                'error': 'Ingen käll-session angiven'
            }), 400
        
        result = access_control_manager.test_access_control(
            source_session_file, 
            test_cookies, 
            test_label, 
            selected_urls
        )
        
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500



@app.route('/report')
def report():
    print("/scan-zap-urls")
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

@app.route('/test-zap-api')
def test_zap_api():
    """Testar ZAP API-anslutningen"""
    print("/test-zap-api")
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
    print('/api/zap-status')
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


    
# Uppdatera app.py för att inkludera statiska filer
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/', methods=['GET', 'POST'])
def target():
    """Målkonfiguration med automatisk ZAP-reset och förbättrad scope-hantering"""
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
        
        # AUTOMATISK ZAP RESET - Rensa all gammal data innan vi sätter upp nytt target
        try:
            app.logger.info("Starting automatic ZAP reset for new target...")
            
            # Rensa alerts
            alerts_result = _zap_api_call('core/action/deleteAllAlerts')
            if not alerts_result['success']:
                app.logger.warning(f"Failed to delete alerts: {alerts_result.get('response', 'Unknown error')}")
            
            # Skapa ny ZAP session (detta rensar all historik och data)
            zap_reset_result = _zap_api_call('core/action/newSession', {
                'name': 'session',
                'overwrite': 'true'
            }, timeout=20)
            
            if not zap_reset_result['success']:
                app.logger.warning(f"Failed to create new ZAP session: {zap_reset_result.get('response', 'Unknown error')}")
            else:
                app.logger.info("ZAP session reset successful")
            
            # Rensa alerts igen efter ny session
            alerts_result = _zap_api_call('core/action/deleteAllAlerts')
            
            # Rensa Flask session men behåll vissa värden
            old_target_url = session.get('target_url', '')
            session.clear()
            
            app.logger.info(f"ZAP reset completed. Old target: {old_target_url}, New target: {target_url}")
            
        except Exception as e:
            app.logger.error(f"Error during ZAP reset: {str(e)}")
            flash(f'Varning: Kunde inte rensa ZAP data helt: {str(e)}', 'warning')
        
        # Spara nya måldetaljer i sessionen
        session['target_url'] = target_url
        session['scan_type'] = scan_type
        session['zap_mode'] = zap_mode
        
        # Extrahera domän från URL för context scope
        from urllib.parse import urlparse
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        # Om ZAP är tillgänglig, konfigurera ZAP-läge och scope för det nya target:et
        if zap.is_available():
            try:
                # Set ZAP mode
                success = zap.set_mode(zap_mode)
                if success:
                    flash(f"ZAP-läge inställt på: {zap_mode.upper()}", "info")
                    app.logger.info(f"ZAP mode set to: {zap_mode}")
                else:
                    flash(f"Kunde inte ställa in ZAP-läge på: {zap_mode.upper()}", "warning")
                
                # Skapa ett nytt context för vårt nya target
                context_name = "Target Context"
                context_result = _zap_api_call('context/action/newContext', {
                    'contextName': context_name
                })
                
                if context_result['success']:
                    app.logger.info(f"Created new context: {context_name}")
                    
                    # Sätt scope för denna domän (inkludera allt på domänen)
                    include_pattern = f".*{re.escape(domain)}.*"
                    include_result = _zap_api_call('context/action/includeInContext', {
                        'contextName': context_name,
                        'regex': include_pattern
                    })
                    
                    if include_result['success']:
                        flash(f"Context scope satt till: {domain}", "info")
                        app.logger.info(f"Set context scope to include: {include_pattern}")
                    else:
                        flash("Kunde inte sätta context scope", "warning")
                        app.logger.warning(f"Failed to set context scope: {include_result.get('response', 'Unknown error')}")
                else:
                    flash("Kunde inte skapa context", "warning")
                    app.logger.warning(f"Failed to create context: {context_result.get('response', 'Unknown error')}")
                
                # Skapa en default HTTP session i ZAP för det nya target:et
                session_result = _zap_api_call('httpSessions/action/createEmptySession', {
                    'site': target_url,
                    'session': 'Session 1'
                })
                
                if session_result['success']:
                    session['zap_session_name'] = 'Session 1'
                    flash("Session 'Session 1' skapad automatiskt för det nya target:et", "info")
                    app.logger.info("Created default HTTP session: Session 1")
                else:
                    flash("Kunde inte skapa standardsession. Du kan skapa en manuellt.", "warning")
                    app.logger.warning(f"Failed to create HTTP session: {session_result.get('response', 'Unknown error')}")
                    
            except Exception as e:
                app.logger.error(f"Error configuring ZAP for new target: {str(e)}")
                flash(f"Fel vid konfiguration av ZAP: {str(e)}", "warning")
        else:
            flash("ZAP är inte tillgänglig, läge och scope kunde inte ställas in", "warning")
        
        flash(f'Nytt mål konfigurerat: {target_url} (Gammal ZAP-data rensad)', 'success')
        return redirect(url_for('session_capture'))
        
    return render_template('target.html')

@app.route('/session-capture')
def session_capture():
    print("/session-capture")   
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
        proxy_host=PROXY_HOST, 
        proxy_port=8080,
        target_url=target_url,
        zap_mode=zap_mode,
        zap_api_key=ZAP_API_KEY,
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
                    
                    # Markera att Ajax Spider är igång OCH att den har startats
                    session['ajax_spider_running'] = True
                    session['ajax_spider_ever_started'] = True  # NY FLAGGA
                    print(f"Ajax Spider started successfully")
                    flash('Ajax Spider started successfully', 'success')
                except Exception as e:
                    print(f"Error starting Ajax Spider: {str(e)}")
                    flash(f'Error starting Ajax Spider: {str(e)}', 'danger')
            else:
                flash('No target URL specified', 'danger')
            
        
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
            '''
            # Kontrollera SQLMap status om vi har ett scan_id
            if 'sqlmap_scan_id' in session:
                try:
                    sqlmap_scan_id = session['sqlmap_scan_id']
                    status['sqlmap'] = sql_tester.get_status(sqlmap_scan_id)
                except Exception as e:
                    print(f"Error getting SQLMap status: {str(e)}")
                    status['sqlmap'] = {'error': str(e)}
            '''
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
                
                # Förbättrad logik för Ajax Spider status
                status['ajax_spider'] = {
                    'status': ajax_status,
                    'running': ajax_status == 'running',
                    'ever_started': session.get('ajax_spider_ever_started', False)  # Ny flagga
                }
                
                # Hämta antal resultat endast om Ajax Spider har körts
                if ajax_status != 'running' and session.get('ajax_spider_ever_started', False):
                    try:
                        num_results_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/ajaxSpider/view/numberOfResults/"
                        num_results_response = requests.get(num_results_url, params={'apikey': ZAP_API_KEY}, timeout=3)
                        if num_results_response.status_code == 200:
                            num_results_data = num_results_response.json()
                            status['ajax_spider']['urls_found'] = num_results_data.get('numberOfResults', 0)
                    except Exception as e:
                        print(f"Error getting number of Ajax Spider results: {str(e)}")
                else:
                    # Om Ajax Spider aldrig har startats, sätt urls_found till None
                    status['ajax_spider']['urls_found'] = None if not session.get('ajax_spider_ever_started', False) else 0
                        
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
    print("/api/all-scans")
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
    print("/api/scan-results/<scan_id>")
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
    print("/api/cancel-scan/<scan_id>")
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




@app.route('/api/debug-zap-cookies')
def debug_zap_cookies():
    print("/api/debug-zap-cookies")
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



@app.route('/test-cookies')
def test_cookies():
    print("/test-cookies")
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
    print("/sqlmap-status-file/<scan_id>")
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

@app.route('/api/access-control/extract-cookies')
def api_access_control_extract_cookies():
    """Extrahera cookies från ZAP för access control testing med korrekt target"""
    try:
        # Kontrollera ZAP-status
        if not zap.is_available():
            return jsonify({
                'success': False,
                'error': 'ZAP är inte tillgänglig. Kontrollera att ZAP körs och är ansluten.'
            }), 503
        
        # Hämta target_url med prioriterad ordning
        target_url = None
        
        # 1. Från Flask session (huvudkonfiguration)
        if 'target_url' in session and session['target_url']:
            target_url = session['target_url']
            app.logger.info(f"Using target_url from main session: {target_url}")
        
        # 2. Från query parameter 
        elif request.args.get('target_url'):
            target_url = request.args.get('target_url')
            app.logger.info(f"Using target_url from query param: {target_url}")
        
        # 3. Från target-url form field (från access control sidan)
        elif request.args.get('url'):
            target_url = request.args.get('url')
            app.logger.info(f"Using target_url from url param: {target_url}")
        
        # 4. Försök hitta rätt site i ZAP (undvik test-sites)
        else:
            try:
                sites = zap.zap.core.sites
                app.logger.info(f"Available ZAP sites: {sites}")
                
                # Filtrera bort test/utvecklingssites
                real_sites = []
                skip_patterns = ['oast.pro', 'oast.online', 'amazonaws.com', 'gstatic.com', 'googleapis.com', ':5000', ':5001']
                
                for site in sites:
                    if site and not any(pattern in site for pattern in skip_patterns):
                        real_sites.append(site)
                
                if real_sites:
                    target_url = real_sites[0]
                    app.logger.info(f"Using first real site from ZAP: {target_url}")
                    
            except Exception as e:
                app.logger.warning(f"Could not get sites from ZAP: {str(e)}")
        
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'Ingen target URL tillgänglig.',
                'suggestions': [
                    'Gå till startsidan och konfigurera ett mål först',
                    'Eller ange target URL manuellt i formuläret'
                ],
                'debug_info': {
                    'session_keys': list(session.keys()),
                    'has_target_url': 'target_url' in session,
                    'session_target': session.get('target_url', 'None'),
                    'zap_sites': zap.zap.core.sites if zap.is_available() else []
                }
            }), 400
        
        app.logger.info(f"Extracting cookies for URL: {target_url}")
        
        # Använd den förbättrade cookie-extraktionen
        try:
            # Försök med den direkta metoden först
            cookies = access_control_manager.get_cookies_from_messages(target_url)
            
            if cookies and cookies.strip():
                return jsonify({
                    'success': True,
                    'cookies': cookies,
                    'target_url': target_url,
                    'message': f'Cookies extraherade från {target_url}',
                    'method': 'direct_header_extraction'
                })
            
            # Fallback till ZAP:s inbyggda metod
            app.logger.info("Trying fallback cookie extraction method...")
            fallback_cookies = zap.get_cookies(target_url)
            
            if fallback_cookies and fallback_cookies.strip():
                return jsonify({
                    'success': True,
                    'cookies': fallback_cookies,
                    'target_url': target_url,
                    'message': f'Cookies extraherade från {target_url} (fallback method)',
                    'method': 'zap_builtin_extraction'
                })
            
            # Om fortfarande inga cookies, ge detaljerad diagnostik
            domain = access_control_manager._extract_domain_or_ip(target_url)
            
            # Kontrollera meddelanden för denna domän
            messages_result = zap._direct_api_call('core/view/messages', {
                'baseurl': '',
                'start': '0',
                'count': '500'
            })
            
            messages_with_domain = 0
            messages_with_cookies = 0
            sample_headers = []
            
            if messages_result['success']:
                messages = messages_result['data'].get('messages', [])
                
                for message in messages:
                    request_header = message.get('requestHeader', '')
                    if domain in request_header:
                        messages_with_domain += 1
                        if 'Cookie:' in request_header:
                            messages_with_cookies += 1
                            # Spara ett exempel på header
                            if len(sample_headers) < 3:
                                cookie_line = ''
                                for line in request_header.split('\n'):
                                    if line.strip().lower().startswith('cookie:'):
                                        cookie_line = line.strip()
                                        break
                                if cookie_line:
                                    sample_headers.append(cookie_line[:100] + '...' if len(cookie_line) > 100 else cookie_line)
            
            return jsonify({
                'success': False,
                'error': f'Inga cookies hittades för {domain}',
                'target_url': target_url,
                'domain': domain,
                'diagnostics': {
                    'total_messages': len(messages_result['data'].get('messages', [])) if messages_result['success'] else 0,
                    'messages_with_domain': messages_with_domain,
                    'messages_with_cookies': messages_with_cookies,
                    'sample_cookie_headers': sample_headers
                },
                'suggestions': [
                    f'Kontrollera att du har surfat på {domain} via ZAP proxy',
                    'Ladda om målsidan medan ZAP proxy är aktivt',
                    'Kontrollera att du är inloggad på webbplatsen',
                    'Verifiera att ZAP fångar trafik från rätt domän'
                ]
            })
            
        except Exception as cookie_error:
            app.logger.error(f"Error extracting cookies: {str(cookie_error)}")
            return jsonify({
                'success': False,
                'error': f'Fel vid extrahering av cookies: {str(cookie_error)}',
                'target_url': target_url
            }), 500
            
    except Exception as e:
        app.logger.error(f"General error in extract-cookies endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Oväntat fel: {str(e)}'
        }), 500


@app.route('/api/access-control/set-target', methods=['POST'])
def api_access_control_set_target():
    """Sätt target URL för access control testing"""
    try:
        data = request.json
        target_url = data.get('target_url', '').strip()
        
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'Ingen target URL angiven'
            }), 400
        
        # Validera URL-format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        # Spara i sessionen
        session['target_url'] = target_url
        
        return jsonify({
            'success': True,
            'target_url': target_url,
            'message': f'Target URL satt till: {target_url}'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Debug-endpoint för att troubleshoot cookie-extraktion
@app.route('/api/access-control/debug-cookies')
def api_access_control_debug_cookies():
    """Debug-endpoint för cookie-extraktion"""
    debug_info = {
        'timestamp': time.time(),
        'zap_available': False,
        'session_data': {},
        'zap_sites': [],
        'target_url_sources': {}
    }
    
    try:
        # Kontrollera ZAP status
        debug_info['zap_available'] = zap.is_available()
        
        # Session data
        debug_info['session_data'] = {
            'has_target_url': 'target_url' in session,
            'target_url': session.get('target_url', 'None'),
            'all_keys': list(session.keys())
        }
        
        # ZAP sites
        if debug_info['zap_available']:
            try:
                sites = zap.zap.core.sites
                debug_info['zap_sites'] = sites
            except Exception as e:
                debug_info['zap_sites_error'] = str(e)
        
        # Test olika källor för target_url
        debug_info['target_url_sources'] = {
            'session': session.get('target_url', None),
            'query_param': request.args.get('target_url', None),
            'first_zap_site': debug_info['zap_sites'][0] if debug_info['zap_sites'] else None
        }
        
        # Om vi har en target_url, testa cookie-extraktion
        target_url = debug_info['target_url_sources']['session']
        if target_url and debug_info['zap_available']:
            try:
                cookies = zap.get_cookies(target_url)
                debug_info['cookie_test'] = {
                    'success': bool(cookies),
                    'cookies_length': len(cookies) if cookies else 0,
                    'cookies_preview': cookies[:100] + '...' if cookies and len(cookies) > 100 else cookies
                }
            except Exception as e:
                debug_info['cookie_test'] = {
                    'success': False,
                    'error': str(e)
                }
        
        return jsonify(debug_info)
    except Exception as e:
        debug_info['error'] = str(e)
        return jsonify(debug_info), 500

@app.route('/api/access-control/test-details/<test_filename>')
def api_access_control_test_details(test_filename):
    """Hämta detaljerade resultat från ett specifikt test"""
    try:
        # Säkerhetskontroll - bara tillåt filer som slutar med .json
        if not test_filename.endswith('.json') or '..' in test_filename:
            return jsonify({
                'success': False,
                'error': 'Ogiltig filnamn'
            }), 400
        
        filepath = os.path.join(access_control_manager.tests_dir, test_filename)
        
        if not os.path.exists(filepath):
            return jsonify({
                'success': False,
                'error': 'Testfil hittades inte'
            }), 404
        
        with open(filepath, 'r') as f:
            test_data = json.load(f)
        
        return jsonify({
            'success': True,
            'test_data': test_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/access-control/start-session-recording', methods=['POST'])
def api_access_control_start_session_recording():
    """Starta session-inspelning med timestamp-märkning"""
    try:
        data = request.json
        session_label = data.get('session_label', '').strip()
        target_url = data.get('target_url', '').strip()
        
        if not session_label:
            return jsonify({
                'success': False,
                'error': 'Sessionsetikett krävs'
            }), 400
            
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'Target URL krävs'
            }), 400
        
        # Kontrollera att ZAP är tillgänglig
        if not zap.is_available():
            return jsonify({
                'success': False,
                'error': 'ZAP är inte tillgänglig'
            }), 503
        
        # Starta inspelning genom att märka starttid
        recording_id = f"{session_label}_{int(time.time())}"
        start_timestamp = time.time()
        
        # Spara inspelningsdata
        active_recordings[recording_id] = {
            'session_label': session_label,
            'target_url': target_url,
            'start_timestamp': start_timestamp,
            'start_message_count': None  # Räkna meddelanden i ZAP vid start
        }
        
        # Hämta nuvarande antal meddelanden i ZAP som baseline
        try:
            messages_result = zap._direct_api_call('core/view/messages', {
                'baseurl': '',
                'start': '0',
                'count': '1'
            })
            if messages_result['success']:
                # Få totalt antal meddelanden
                total_messages = len(messages_result['data'].get('messages', []))
                active_recordings[recording_id]['start_message_count'] = total_messages
        except Exception as e:
            app.logger.warning(f"Could not get baseline message count: {e}")
            active_recordings[recording_id]['start_message_count'] = 0
        
        # Spara session_id i Flask session för att hålla koll
        session['active_recording_id'] = recording_id
        
        app.logger.info(f"Started session recording: {recording_id}")
        
        return jsonify({
            'success': True,
            'recording_id': recording_id,
            'session_label': session_label,
            'target_url': target_url,
            'start_timestamp': start_timestamp,
            'message': f'Session-inspelning startad för "{session_label}"'
        })
        
    except Exception as e:
        app.logger.error(f"Error starting session recording: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/access-control/stop-session-recording', methods=['POST'])
def api_access_control_stop_session_recording():
    """Stoppa session-inspelning och spara både URLs och cookies från exakt denna period"""
    try:
        data = request.json
        session_label = data.get('session_label', '').strip()
        target_url = data.get('target_url', '').strip()
        
        # Hitta aktiv inspelning
        recording_id = session.get('active_recording_id')
        if not recording_id or recording_id not in active_recordings:
            return jsonify({
                'success': False,
                'error': 'Ingen aktiv inspelning hittades'
            }), 400
        
        recording_data = active_recordings[recording_id]
        stop_timestamp = time.time()
        
        # Kontrollera att ZAP är tillgänglig
        if not zap.is_available():
            return jsonify({
                'success': False,
                'error': 'ZAP är inte tillgänglig'
            }), 503
        
        # Samla URLs och cookies från inspelningsperioden
        result = access_control_manager.collect_session_data_by_timeframe(
            session_label=recording_data['session_label'],
            target_url=recording_data['target_url'],
            start_timestamp=recording_data['start_timestamp'],
            stop_timestamp=stop_timestamp,
            start_message_count=recording_data.get('start_message_count', 0)
        )
        
        if result['success']:
            # Rensa aktiv inspelning
            del active_recordings[recording_id]
            if 'active_recording_id' in session:
                del session['active_recording_id']
            
            app.logger.info(f"Stopped session recording: {recording_id}, collected {result.get('url_count', 0)} URLs")
            
            return jsonify({
                'success': True,
                'session_label': recording_data['session_label'],
                'url_count': result.get('url_count', 0),
                'cookies_found': result.get('cookies_found', False),
                'filename': result.get('filename', ''),
                'recording_duration': stop_timestamp - recording_data['start_timestamp'],
                'message': f'Session sparad: {result.get("url_count", 0)} URL:er samlades'
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Okänt fel vid sparande av session')
            }), 500
            
    except Exception as e:
        app.logger.error(f"Error stopping session recording: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/access-control/test-with-sessions', methods=['POST'])
def api_access_control_test_with_sessions():
    """Testa access control med separata sessions för URLs och credentials"""
    try:
        data = request.json
        urls_from_session = data.get('urls_from_session', '').strip()
        credentials_from_session = data.get('credentials_from_session', '').strip()
        test_description = data.get('test_description', '').strip()
        
        if not urls_from_session:
            return jsonify({
                'success': False,
                'error': 'URL-session måste väljas'
            }), 400
            
        if not credentials_from_session:
            return jsonify({
                'success': False,
                'error': 'Credentials-session måste väljas'
            }), 400
        
        # Kontrollera att ZAP är tillgänglig
        if not zap.is_available():
            return jsonify({
                'success': False,
                'error': 'ZAP är inte tillgänglig'
            }), 503
        
        # Starta test med access control manager
        result = access_control_manager.test_access_control_with_separate_sessions(
            urls_session_file=urls_from_session,
            credentials_session_file=credentials_from_session,
            test_description=test_description
        )
        
        if result['success']:
            app.logger.info(f"Started access control test: {result.get('test_count', 0)} URLs to test")
            
            return jsonify({
                'success': True,
                'test_id': result.get('test_id'),
                'test_count': result.get('test_count', 0),
                'test_description': test_description,
                'urls_session': urls_from_session,
                'credentials_session': credentials_from_session,
                'message': f'Access Control Test startat: {result.get("test_count", 0)} URL:er att testa'
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Okänt fel vid start av test')
            }), 500
            
    except Exception as e:
        app.logger.error(f"Error starting access control test with sessions: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/access-control/test-results')
def api_access_control_test_results():
    """Hämta access control testresultat"""
    try:
        results = access_control_manager.get_test_results()
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching access control test results: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'results': []
        }), 500

@app.route('/api/access-control/recording-status')
def api_access_control_recording_status():
    """Kontrollera status för aktiv inspelning"""
    try:
        recording_id = session.get('active_recording_id')
        
        if not recording_id or recording_id not in active_recordings:
            return jsonify({
                'success': True,
                'is_recording': False,
                'recording_data': None
            })
        
        recording_data = active_recordings[recording_id]
        current_time = time.time()
        duration = current_time - recording_data['start_timestamp']
        
        return jsonify({
            'success': True,
            'is_recording': True,
            'recording_data': {
                'recording_id': recording_id,
                'session_label': recording_data['session_label'],
                'target_url': recording_data['target_url'],
                'start_timestamp': recording_data['start_timestamp'],
                'duration_seconds': duration,
                'duration_formatted': f"{int(duration//60):02d}:{int(duration%60):02d}"
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error getting recording status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'is_recording': False
        }), 500


# Lägg till dessa routes i din app.py fil

@app.route('/api/download-pdf-report')
@app.route('/api/download-pdf-report/<report_type>')
def download_pdf_report(report_type='full'):
    """Generera och ladda ner PDF-rapport i olika format"""
    try:
        target_url = session.get('target_url', '')
        
        if not target_url:
            return jsonify({'error': 'Vänligen konfigurera ett mål först.'}), 400
        
        # Validera rapporttyp
        valid_types = ['basic', 'medium', 'full']
        if report_type not in valid_types:
            report_type = 'full'
        
        # Hämta sårbarhetsdata
        alerts_data = get_zap_alerts_data(target_url)
        
        if 'error' in alerts_data:
            return jsonify({'error': f'Fel vid hämtning av data: {alerts_data["error"]}'}), 500
        
        # Organisera data
        alerts_by_risk = alerts_data.get('alerts_by_risk', {})
        organized_data = organize_alerts_by_type_and_risk(alerts_by_risk)
        
        # Räkna sårbarheter
        risk_counts = {
            'high': len(alerts_by_risk.get('highAlerts', [])),
            'medium': len(alerts_by_risk.get('mediumAlerts', [])),
            'low': len(alerts_by_risk.get('lowAlerts', [])),
            'info': len(alerts_by_risk.get('infoAlerts', []))
        }
        
        # Välj rätt template baserat på rapporttyp
        template_mapping = {
            'basic': 'basic_pdf_report.html',
            'medium': 'medium_pdf_report.html',
            'full': 'full_pdf_report_improved.html'
        }
        
        template_name = template_mapping[report_type]
        
        # Generera rapport-ID
        report_id = str(uuid.uuid4())
        
        # Rendera HTML
        html_content = render_template(template_name,
            target_url=target_url,
            report_id=report_id,
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            risk_counts=risk_counts,
            organized_data=organized_data
        )
        
        # Generera PDF med CSS för den specifika rapporttypen
        pdf_bytes = generate_pdf_from_html_with_type(html_content, report_type)
        
        # Skapa svar
        response = make_response(pdf_bytes)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=sakerheterapport_{report_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        
        return response
        
    except Exception as e:
        app.logger.error(f"Error generating {report_type} PDF report: {str(e)}")
        return jsonify({'error': f'Kunde inte generera rapport: {str(e)}'}), 500


def generate_pdf_from_html_with_type(html_content, report_type):
    """Generera PDF med CSS anpassad för rapporttyp"""
    try:
        # Bas CSS som gäller för alla rapporter
        base_css = """
        body {
            font-family: Arial, sans-serif;
            color: #333;
            margin: 0;
            padding: 0;
        }
        
        .header {
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 30px;
            margin-bottom: 40px;
        }
        
        .header h1 {
            color: #007bff;
            margin-bottom: 20px;
        }
        
        .report-info {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 4px solid #007bff;
        }
        
        .report-info p {
            margin: 3px 0;
            font-size: 10pt;
        }
        
        .summary-grid {
            display: flex;
            justify-content: space-between;
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            flex: 1;
            text-align: center;
            padding: 20px 15px;
            border-radius: 10px;
            color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .summary-card.high-risk { background: linear-gradient(135deg, #dc3545, #c82333); }
        .summary-card.medium-risk { background: linear-gradient(135deg, #ffc107, #e0a800); color: #212529; }
        .summary-card.low-risk { background: linear-gradient(135deg, #17a2b8, #138496); }
        .summary-card.info-risk { background: linear-gradient(135deg, #6c757d, #5a6268); }
        
        .summary-card h3 {
            margin: 0 0 8px 0;
            font-weight: bold;
        }
        
        .summary-card p {
            margin: 0;
            font-weight: 500;
        }
        
        .risk-badge {
            display: inline-block;
            padding: 3px 6px;
            border-radius: 3px;
            font-size: 8pt;
            font-weight: bold;
            color: white;
            margin-right: 8px;
        }
        
        .risk-badge.high { background-color: #dc3545; }
        .risk-badge.medium { background-color: #ffc107; color: #212529; }
        .risk-badge.low { background-color: #17a2b8; }
        .risk-badge.info { background-color: #6c757d; }
        
        .confidence-badge {
            display: inline-block;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 8pt;
            font-weight: bold;
        }
        
        .confidence-high { background-color: #d4edda; color: #155724; }
        .confidence-medium { background-color: #fff3cd; color: #856404; }
        .confidence-low { background-color: #f8d7da; color: #721c24; }
        
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 9pt;
            color: #666;
            border-top: 1px solid #dee2e6;
            padding-top: 15px;
        }
        """
        
        # Specifik CSS för varje rapporttyp
        type_specific_css = {
            'basic': """
                @page {
                    size: A4;
                    margin: 2cm;
                    @top-center {
                        content: "Säkerhetsrapport - Basic";
                        font-size: 10pt;
                        color: #666;
                    }
                    @bottom-center {
                        content: counter(page) " av " counter(pages);
                        font-size: 10pt;
                        color: #666;
                    }
                }
                
                body { font-size: 12pt; line-height: 1.5; }
                .header h1 { font-size: 28pt; }
                .summary-card h3 { font-size: 48pt; }
                .summary-card p { font-size: 14pt; }
                
                .findings-overview {
                    background-color: #f8f9fa;
                    padding: 30px;
                    border-radius: 10px;
                    border-left: 5px solid #007bff;
                }
                
                .findings-overview h2 {
                    color: #007bff;
                    margin-bottom: 20px;
                    font-size: 18pt;
                }
                
                .findings-list {
                    list-style: none;
                    padding: 0;
                }
                
                .findings-list li {
                    padding: 10px 0;
                    border-bottom: 1px solid #dee2e6;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .findings-list li:last-child {
                    border-bottom: none;
                }
                
                .finding-name {
                    font-weight: 500;
                    flex-grow: 1;
                }
                
                .finding-count {
                    background-color: #007bff;
                    color: white;
                    padding: 5px 10px;
                    border-radius: 20px;
                    font-size: 10pt;
                    font-weight: bold;
                    margin-left: 10px;
                }
                
                .conclusion {
                    background-color: #e8f5e8;
                    padding: 25px;
                    border-radius: 10px;
                    border-left: 5px solid #28a745;
                    margin-top: 40px;
                }
                
                .conclusion h2 {
                    color: #28a745;
                    margin-bottom: 15px;
                }
            """,
            
            'medium': """
                @page {
                    size: A4;
                    margin: 2cm;
                    @top-center {
                        content: "Säkerhetsrapport - Medium";
                        font-size: 10pt;
                        color: #666;
                    }
                    @bottom-center {
                        content: counter(page) " av " counter(pages);
                        font-size: 10pt;
                        color: #666;
                    }
                }
                
                body { font-size: 11pt; line-height: 1.4; }
                .header h1 { font-size: 24pt; }
                .summary-card h3 { font-size: 32pt; }
                .summary-card p { font-size: 12pt; }
                
                .vulnerability-section {
                    margin-bottom: 30px;
                    border: 1px solid #dee2e6;
                    border-radius: 8px;
                    padding: 20px;
                    background-color: #fff;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                    page-break-inside: avoid;
                }
                
                .vulnerability-header {
                    border-bottom: 2px solid #e9ecef;
                    margin-bottom: 15px;
                    padding-bottom: 10px;
                }
                
                .vulnerability-header h3 {
                    margin: 0;
                    color: #333;
                    font-size: 14pt;
                }
                
                .detail-grid {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 15px;
                    margin-bottom: 15px;
                }
                
                .detail-item {
                    margin-bottom: 15px;
                }
                
                .detail-item h4 {
                    margin: 0 0 5px 0;
                    color: #495057;
                    font-size: 11pt;
                    font-weight: 600;
                }
                
                .detail-item p {
                    margin: 0;
                    font-size: 10pt;
                    line-height: 1.4;
                }
            """,
            
            'full': """
                @page {
                    size: A4;
                    margin: 1.2cm;
                    @top-center {
                        content: "Fullständig Säkerhetsrapport";
                        font-size: 9pt;
                        color: #666;
                    }
                    @bottom-center {
                        content: counter(page) " av " counter(pages);
                        font-size: 9pt;
                        color: #666;
                    }
                }
                
                body { font-size: 10pt; line-height: 1.3; }
                .header h1 { font-size: 20pt; }
                .summary-card h3 { font-size: 24pt; }
                .summary-card p { font-size: 10pt; }
                
                .vulnerability-section {
                    margin-bottom: 20px;
                    border: 1px solid #dee2e6;
                    border-radius: 6px;
                    padding: 15px;
                    background-color: #fff;
                    page-break-inside: avoid;
                }
                
                .vulnerability-header {
                    border-bottom: 1px solid #e9ecef;
                    margin-bottom: 10px;
                    padding-bottom: 8px;
                }
                
                .vulnerability-header h3 {
                    margin: 0;
                    color: #333;
                    font-size: 12pt;
                    display: flex;
                    align-items: center;
                }
                
                .detail-grid {
                    display: grid;
                    grid-template-columns: 1fr 1fr 1fr;
                    gap: 10px;
                    margin-bottom: 10px;
                }
                
                .detail-item h4 {
                    margin: 0 0 3px 0;
                    color: #495057;
                    font-size: 9pt;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                
                .detail-item p {
                    margin: 0;
                    font-size: 9pt;
                    line-height: 1.3;
                }
                
                .description-text {
                    background-color: #f8f9fa;
                    padding: 8px;
                    border-radius: 4px;
                    border-left: 3px solid #007bff;
                    font-size: 9pt;
                    line-height: 1.3;
                    margin-bottom: 10px;
                }
                
                .instances-section {
                    margin-top: 12px;
                }
                
                .instances-header {
                    background-color: #e9ecef;
                    padding: 6px 8px;
                    border-radius: 4px;
                    font-weight: 600;
                    font-size: 9pt;
                    margin-bottom: 5px;
                }
                
                .instance-row {
                    background-color: #f8f9fa;
                    margin-bottom: 3px;
                    border-radius: 3px;
                    overflow: hidden;
                    border-left: 3px solid #6c757d;
                }
                
                .instance-url {
                    background-color: #e9ecef;
                    padding: 4px 8px;
                    font-size: 8pt;
                    font-weight: 500;
                    word-break: break-all;
                }
                
                .instance-details {
                    padding: 4px 8px;
                    font-size: 8pt;
                }
                
                .param-attack-row {
                    display: flex;
                    gap: 15px;
                }
                
                .param-section, .attack-section {
                    flex: 1;
                }
                
                .param-label, .attack-label {
                    font-weight: 600;
                    color: #495057;
                    margin-bottom: 2px;
                }
                
                .param-value, .attack-value {
                    background-color: #fff;
                    padding: 3px 5px;
                    border-radius: 2px;
                    border: 1px solid #dee2e6;
                    word-break: break-all;
                    font-family: monospace;
                }
                
                .more-instances {
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 6px 8px;
                    border-radius: 4px;
                    margin-top: 5px;
                    font-size: 8pt;
                    font-style: italic;
                    color: #856404;
                }
                
                .section-header {
                    color: #333;
                    font-size: 14pt;
                    margin: 20px 0 15px 0;
                    padding-bottom: 5px;
                    border-bottom: 2px solid #007bff;
                }
            """
        }
        
        # Kombinera CSS
        css_content = base_css + type_specific_css.get(report_type, type_specific_css['full'])
        
        # Skapa CSS-objekt
        css = CSS(string=css_content)
        
        # Generera PDF
        html_doc = HTML(string=html_content)
        pdf_bytes = html_doc.write_pdf(stylesheets=[css])
        
        return pdf_bytes
        
    except Exception as e:
        app.logger.error(f"Error in PDF generation for {report_type}: {str(e)}")
        raise e

# Hjälp-endpoint för att rensa upp aktiva inspelningar vid behov
@app.route('/api/access-control/cleanup-recordings', methods=['POST'])
def api_access_control_cleanup_recordings():
    """Rensa upp gamla/hängande inspelningar (admin-funktion)"""
    try:
        global active_recordings
        
        # Rensa inspelningar äldre än 24 timmar
        current_time = time.time()
        cleanup_threshold = 24 * 60 * 60  # 24 timmar
        
        recordings_to_remove = []
        for recording_id, recording_data in active_recordings.items():
            if current_time - recording_data['start_timestamp'] > cleanup_threshold:
                recordings_to_remove.append(recording_id)
        
        for recording_id in recordings_to_remove:
            del active_recordings[recording_id]
        
        # Rensa även från session om den finns
        if 'active_recording_id' in session and session['active_recording_id'] in recordings_to_remove:
            del session['active_recording_id']
        
        return jsonify({
            'success': True,
            'cleaned_recordings': len(recordings_to_remove),
            'active_recordings': len(active_recordings),
            'message': f'Rensade {len(recordings_to_remove)} gamla inspelningar'
        })
        
    except Exception as e:
        app.logger.error(f"Error cleaning up recordings: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# I app.py - Kontrollera att denna route finns och använder rätt template:

@app.route('/access-control-report')
def access_control_report():
    """Access Control rapportvy som visar tillgängliga testresultat från data/tests"""
    try:
        # Hämta alla tillgängliga testresultat från access_control_manager
        test_results = access_control_manager.get_test_results()
        
        # Lägg till filename-attribut för varje testresultat för att göra det lättare i templaten
        for test_result in test_results:
            # Skapa filnamn baserat på test_id om det inte finns
            if not hasattr(test_result, 'filename'):
                test_result['filename'] = f"test_report_{test_result.get('test_id', 'unknown')}.json"
        
        # Kontrollera om det finns några test
        if not test_results:
            flash("Inga access control tester hittades. Kör först ett test från Access Control sidan.", "info")
        
        # Hämta vald testfil från query parametrar
        selected_test_file = request.args.get('test_file')
        selected_test_data = None
        
        if selected_test_file:
            # Validera filnamn för säkerhet
            if selected_test_file.endswith('.json') and '..' not in selected_test_file:
                try:
                    filepath = os.path.join(access_control_manager.tests_dir, selected_test_file)
                    if os.path.exists(filepath):
                        with open(filepath, 'r', encoding='utf-8') as f:
                            selected_test_data = json.load(f)
                except Exception as e:
                    flash(f"Kunde inte läsa testfil: {str(e)}", "error")
            else:
                flash("Ogiltig filnamn", "error")
        
        return render_template('access_control_report.html',  # <-- SE TILL ATT DET ÄR RÄTT FILNAMN
                             test_results=test_results,
                             selected_test_file=selected_test_file,
                             selected_test_data=selected_test_data,
                             datetime=datetime)  # Skicka datetime till templaten
        
    except Exception as e:
        flash(f"Ett fel uppstod: {str(e)}", "error")
        return render_template('access_control_report.html',  # <-- SE TILL ATT DET ÄR RÄTT FILNAMN
                        test_results=test_results,
                        selected_test_file=selected_test_file,
                        selected_test_data=selected_test_data,
                        datetime=datetime)  # Skicka datetime till templaten
        return redirect(url_for('access_control'))

@app.route('/api/download-pdf-report')
def download_pdf_report():
    """Generera och ladda ner PDF-rapport"""
    try:
        target_url = session.get('target_url', '')
        
        if not target_url:
            flash("Vänligen konfigurera ett mål först.", "warning")
            return redirect(url_for('target'))
        
        # Hämta sårbarhetsdata direkt från ZAP API (samma logik som api_zap_alerts_by_risk)
        try:
            alerts_data = get_zap_alerts_data(target_url)
            if 'error' in alerts_data:
                return jsonify({'error': f'Kunde inte hämta sårbarhetsdata: {alerts_data["error"]}'}), 500
        except Exception as e:
            return jsonify({'error': f'Fel vid hämtning av data: {str(e)}'}), 500
        
        # Skapa rapport-ID och datum
        report_id = str(uuid.uuid4())
        report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Få faktisk alerts data från alerts_by_risk objektet
        alerts_by_risk = alerts_data.get('alerts_by_risk', {})
        
        # Räkna sårbarheter per risknivå
        risk_counts = {
            'high': len(alerts_by_risk.get('highAlerts', [])),
            'medium': len(alerts_by_risk.get('mediumAlerts', [])),
            'low': len(alerts_by_risk.get('lowAlerts', [])),
            'info': len(alerts_by_risk.get('infoAlerts', []))
        }
        
        # Organisera data för PDF-template
        organized_data = organize_alerts_by_type_and_risk(alerts_by_risk)
        
        # Rendera HTML-template för PDF
        html_content = render_template('pdf_report.html',
            target_url=target_url,
            report_id=report_id,
            report_date=report_date,
            risk_counts=risk_counts,
            organized_data=organized_data
        )
        
        # Skapa PDF
        pdf_file = generate_pdf_from_html(html_content)
        
        # Skapa response med PDF
        response = make_response(pdf_file)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="sakerheterapport_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
        
        return response
        
    except Exception as e:
        app.logger.error(f"Error generating PDF report: {str(e)}")
        return jsonify({'error': f'Fel vid generering av PDF: {str(e)}'}), 500


def organize_alerts_by_type_and_risk(alerts_by_risk):
    """Organisera alerts efter typ och risk för PDF-rapporten"""
    organized = {
        'high': {},
        'medium': {},
        'low': {},
        'info': {}
    }
    
    risk_mappings = {
        'highAlerts': 'high',
        'mediumAlerts': 'medium', 
        'lowAlerts': 'low',
        'infoAlerts': 'info'
    }
    
    for risk_key, alerts in alerts_by_risk.items():
        if risk_key in risk_mappings:
            risk_level = risk_mappings[risk_key]
            
            # Gruppera alerts efter typ (namn)
            for alert in alerts:
                alert_name = alert.get('name', 'Okänd sårbarhet')
                
                if alert_name not in organized[risk_level]:
                    organized[risk_level][alert_name] = {
                        'description': alert.get('description', 'Ingen beskrivning tillgänglig'),
                        'risk': alert.get('risk', 'N/A'),
                        'confidence': alert.get('confidence', 'N/A'),
                        'solution': alert.get('solution', 'Inga åtgärdsförslag tillgängliga'),
                        'reference': alert.get('reference', ''),
                        'cweid': alert.get('cweid', ''),
                        'wascid': alert.get('wascid', ''),
                        'tags': alert.get('tags', {}),
                        'instances': []
                    }
                
                # Lägg till denna instans
                organized[risk_level][alert_name]['instances'].append({
                    'url': alert.get('url', 'N/A'),
                    'param': alert.get('param', 'N/A'),
                    'attack': alert.get('attack', 'N/A')
                })
    
    return organized


def get_zap_alerts_data(target_url):
    return get_zap_alerts_data_fixed(target_url)
    """Hämta sårbarhetsdata från ZAP API direkt (samma logik som api_zap_alerts_by_risk)"""
    try:
        # Kontrollera om ZAP är tillgänglig
        if not zap.is_available():
            return {'error': 'ZAP is not available'}
        
        # Anropa ZAP API för att hämta sårbarheter efter risk
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alertsByRisk/"
        response = requests.get(api_url, params={
            'apikey': ZAP_API_KEY,
            'url': target_url,
            'recurse': 'true'
        }, timeout=10)
        
        if response.status_code != 200:
            return {'error': f'ZAP API returned status code {response.status_code}'}
        
        # Få rådata
        raw_data = response.json()
        
        # Omstrukturera data för att matcha förväntad format
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
                                alert['name'] = alert_name
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
            return {'error': f'ZAP API returned status code {summary_response.status_code}'}
        
        # Extrahera summary från nästlad struktur
        raw_summary = summary_response.json()
        summary = {}
        
        if 'alertsSummary' in raw_summary:
            summary = raw_summary['alertsSummary']
        
        # Kombinera resultaten
        return {
            'alerts_by_risk': processed_data,
            'summary': summary
        }
        
    except Exception as e:
        app.logger.error(f"Error fetching ZAP alerts for PDF: {str(e)}")
        return {'error': f'Error fetching ZAP alerts: {str(e)}'}


def generate_pdf_from_html(html_content):
    """Generera PDF från HTML-innehåll med WeasyPrint"""
    try:
        # CSS för PDF-styling
        css_content = """
        @page {
            size: A4;
            margin: 2cm;
            @top-center {
                content: "Säkerhetsrapport";
                font-size: 10pt;
                color: #666;
            }
            @bottom-center {
                content: counter(page) " av " counter(pages);
                font-size: 10pt;
                color: #666;
            }
        }
        
        body {
            font-family: Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.4;
            color: #333;
        }
        
        .header {
            border-bottom: 2px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #fd7e14; font-weight: bold; }
        .risk-low { color: #17a2b8; font-weight: bold; }
        .risk-info { color: #6c757d; font-weight: bold; }
        
        .vulnerability-section {
            margin-bottom: 30px;
            page-break-inside: avoid;
        }
        
        .vulnerability-header {
            background-color: #f8f9fa;
            padding: 10px;
            border-left: 4px solid #007bff;
            margin-bottom: 15px;
        }
        
        .vulnerability-details {
            margin-left: 20px;
            margin-bottom: 20px;
        }
        
        .detail-item {
            margin-bottom: 15px;
        }
        
        .detail-item h4 {
            margin-bottom: 5px;
            color: #495057;
        }
        
        .detail-grid {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
        }
        
        .detail-grid .detail-item {
            flex: 1;
        }
        
        .instances-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        
        .instances-table th,
        .instances-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
            word-break: break-all;
        }
        
        .instances-table th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        
        .summary-grid {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        
        .summary-card {
            text-align: center;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            flex: 1;
            margin: 0 10px;
        }
        
        .summary-card:first-child {
            margin-left: 0;
        }
        
        .summary-card:last-child {
            margin-right: 0;
        }
        
        .risk-category {
            page-break-before: auto;
            margin-bottom: 40px;
        }
        
        .risk-category h2 {
            border-bottom: 2px solid #ddd;
            padding-bottom: 10px;
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 40px;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
        }
        """
        
        # Skapa CSS-objekt
        css = CSS(string=css_content)
        
        # Generera PDF
        html_doc = HTML(string=html_content)
        pdf_bytes = html_doc.write_pdf(stylesheets=[css])
        
        return pdf_bytes
        
    except Exception as e:
        app.logger.error(f"Error in PDF generation: {str(e)}")
        raise e


@app.route('/debug-pdf')
def debug_pdf():
    """Debug-route för att testa PDF-generering"""
    try:
        target_url = session.get('target_url', 'http://example.com')
        
        # Testa att hämta data
        print("Testar att hämta ZAP data...")
        alerts_data = get_zap_alerts_data(target_url)
        
        debug_info = {
            'target_url': target_url,
            'zap_available': zap.is_available(),
            'alerts_data_keys': list(alerts_data.keys()) if isinstance(alerts_data, dict) else 'Not a dict',
            'has_error': 'error' in alerts_data if isinstance(alerts_data, dict) else False
        }
        
        if 'error' in alerts_data:
            debug_info['error'] = alerts_data['error']
            return jsonify(debug_info)
        
        # Visa debug-info från datahämtning
        if 'debug_info' in alerts_data:
            debug_info['data_fetch_debug'] = alerts_data['debug_info']
        
        # Testa att organisera data
        alerts_by_risk = alerts_data.get('alerts_by_risk', {})
        organized_data = organize_alerts_by_type_and_risk(alerts_by_risk)
        
        debug_info['organized_data_keys'] = {
            'high': len(organized_data.get('high', {})),
            'medium': len(organized_data.get('medium', {})),
            'low': len(organized_data.get('low', {})),
            'info': len(organized_data.get('info', {}))
        }
        
        # Visa detaljer om första högrisksårbarheten
        if organized_data.get('high'):
            first_vuln_name = list(organized_data['high'].keys())[0]
            first_vuln = organized_data['high'][first_vuln_name]
            debug_info['sample_vulnerability'] = {
                'name': first_vuln_name,
                'has_description': bool(first_vuln.get('description')),
                'has_solution': bool(first_vuln.get('solution')),
                'description_preview': first_vuln.get('description', 'missing')[:100] + '...',
                'solution_preview': first_vuln.get('solution', 'missing')[:100] + '...',
                'instances_count': len(first_vuln.get('instances', []))
            }
        
        # Testa att rendera HTML
        try:
            risk_counts = {
                'high': len(alerts_by_risk.get('highAlerts', [])),
                'medium': len(alerts_by_risk.get('mediumAlerts', [])),
                'low': len(alerts_by_risk.get('lowAlerts', [])),
                'info': len(alerts_by_risk.get('infoAlerts', []))
            }
            
            html_content = render_template('pdf_report.html',
                target_url=target_url,
                report_id="debug-test",
                report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                risk_counts=risk_counts,
                organized_data=organized_data
            )
            
            debug_info['html_length'] = len(html_content)
            debug_info['html_preview'] = html_content[:200] + "..." if len(html_content) > 200 else html_content
            
        except Exception as html_error:
            debug_info['html_error'] = str(html_error)
            return jsonify(debug_info)
        
        # Testa PDF-generering
        try:
            pdf_bytes = generate_pdf_from_html(html_content)
            debug_info['pdf_size'] = len(pdf_bytes)
            debug_info['pdf_generation'] = 'success'
            
        except Exception as pdf_error:
            debug_info['pdf_error'] = str(pdf_error)
            debug_info['pdf_generation'] = 'failed'
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'type': type(e).__name__,
            'traceback': traceback.format_exc()
        }), 500


# Lägg också till en enkel test-route som returnerar HTML istället för PDF
@app.route('/test-pdf-html')
def test_pdf_html():
    """Returnera HTML-versionen av PDF-rapporten för testning"""
    try:
        target_url = session.get('target_url', 'http://example.com')
        
        # Skapa testdata om ZAP inte är tillgänglig
        if not zap.is_available():
            # Skapa dummy-data för testning
            alerts_by_risk = {
                'highAlerts': [
                    {
                        'name': 'SQL Injection',
                        'description': 'En SQL injection-sårbarhet upptäcktes',
                        'risk': 'High',
                        'confidence': 'High',
                        'solution': 'Använd parameteriserade queries',
                        'reference': 'https://owasp.org/www-community/attacks/SQL_Injection',
                        'cweid': '89',
                        'wascid': '19',
                        'url': 'http://example.com/login',
                        'param': 'username',
                        'attack': "' OR '1'='1"
                    }
                ],
                'mediumAlerts': [],
                'lowAlerts': [],
                'infoAlerts': []
            }
        else:
            # Hämta riktig data
            alerts_data = get_zap_alerts_data(target_url)
            if 'error' in alerts_data:
                return f"<h1>Fel: {alerts_data['error']}</h1>"
            alerts_by_risk = alerts_data.get('alerts_by_risk', {})
        
        # Organisera data
        organized_data = organize_alerts_by_type_and_risk(alerts_by_risk)
        
        # Räkna sårbarheter
        risk_counts = {
            'high': len(alerts_by_risk.get('highAlerts', [])),
            'medium': len(alerts_by_risk.get('mediumAlerts', [])),
            'low': len(alerts_by_risk.get('lowAlerts', [])),
            'info': len(alerts_by_risk.get('infoAlerts', []))
        }
        
        # Rendera och returnera HTML
        return render_template('pdf_report.html',
            target_url=target_url,
            report_id="test-html",
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            risk_counts=risk_counts,
            organized_data=organized_data
        )
        
    except Exception as e:
        return f"<h1>Fel: {str(e)}</h1><pre>{traceback.format_exc()}</pre>"
    

def get_zap_alerts_data_simplified(target_url):
    """Förenklad datahämtning som använder befintliga Flask API-endpoints"""
    try:
        # Använd samma API-endpoint som webbrapporten använder
        from flask import current_app
        
        with current_app.test_request_context():
            # Simulera en request till vår egen API
            from flask import session as temp_session
            temp_session['target_url'] = target_url
            
            # Anropa samma funktion som webbrapporten använder
            api_response = api_zap_alerts_by_risk()
            
            # Hantera Flask Response-objekt
            if hasattr(api_response, 'json'):
                alerts_data = api_response.json
            elif isinstance(api_response, tuple):
                alerts_data = api_response[0]  # (data, status_code)
            else:
                alerts_data = api_response
            
            if 'error' in alerts_data:
                return alerts_data
            
            alerts_by_risk = alerts_data.get('alerts_by_risk', {})
            
            # Hämta detaljerad information för varje alert
            for risk_level in ['highAlerts', 'mediumAlerts', 'lowAlerts', 'infoAlerts']:
                for alert in alerts_by_risk.get(risk_level, []):
                    alert_id = alert.get('id')
                    if alert_id:
                        try:
                            # Använd vår befintliga API-endpoint
                            detail_response = api_alert_details(alert_id)
                            
                            if hasattr(detail_response, 'json'):
                                detail_data = detail_response.json
                            elif isinstance(detail_response, tuple):
                                detail_data = detail_response[0]
                            else:
                                detail_data = detail_response
                            
                            if 'alert' in detail_data:
                                detail = detail_data['alert']
                                # Uppdatera med detaljerad information
                                alert.update({
                                    'description': detail.get('description', ''),
                                    'solution': detail.get('solution', ''),
                                    'reference': detail.get('reference', ''),
                                    'cweid': detail.get('cweid', ''),
                                    'wascid': detail.get('wascid', ''),
                                    'attack': detail.get('attack', ''),
                                    'evidence': detail.get('evidence', ''),
                                    'tags': detail.get('tags', {})
                                })
                            
                        except Exception as detail_error:
                            app.logger.error(f"Error fetching details for alert {alert_id}: {str(detail_error)}")
            
            return alerts_data
            
    except Exception as e:
        app.logger.error(f"Error in simplified data fetch: {str(e)}")
        return {'error': f'Error fetching data: {str(e)}'}


# Alternativ 2: Direkta ZAP API-anrop med bättre felhantering
def get_zap_alerts_data_fixed(target_url):
    """Förbättrad version med bättre felhantering och loggning"""
    try:
        if not zap.is_available():
            return {'error': 'ZAP is not available'}
        
        # Hämta grundläggande alerts
        api_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alertsByRisk/"
        response = requests.get(api_url, params={
            'apikey': ZAP_API_KEY,
            'url': target_url,
            'recurse': 'true'
        }, timeout=10)
        
        if response.status_code != 200:
            return {'error': f'ZAP API returned status code {response.status_code}'}
        
        raw_data = response.json()
        processed_data = {
            'highAlerts': [],
            'mediumAlerts': [],
            'lowAlerts': [],
            'infoAlerts': []
        }
        
        # Extrahera alerts och samla IDs
        alert_ids = []
        if 'alertsByRisk' in raw_data:
            for risk_group in raw_data['alertsByRisk']:
                for risk_level in ['High', 'Medium', 'Low', 'Informational']:
                    if risk_level in risk_group:
                        target_list = {
                            'High': 'highAlerts',
                            'Medium': 'mediumAlerts', 
                            'Low': 'lowAlerts',
                            'Informational': 'infoAlerts'
                        }[risk_level]
                        
                        for alert_type in risk_group[risk_level]:
                            for alert_name, alerts in alert_type.items():
                                for alert in alerts:
                                    alert['name'] = alert_name
                                    processed_data[target_list].append(alert)
                                    if alert.get('id'):
                                        alert_ids.append(alert.get('id'))
        
        app.logger.info(f"Extraherade {len(alert_ids)} alert IDs: {alert_ids[:5]}...")  # Visa första 5
        
        # Hämta detaljer för varje alert
        details_fetched = 0
        for alert_id in alert_ids:
            try:
                detail_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alert/"
                detail_response = requests.get(detail_url, params={
                    'apikey': ZAP_API_KEY,
                    'id': str(alert_id)  # Försäkra att ID är string
                }, timeout=5)
                
                if detail_response.status_code == 200:
                    detail_json = detail_response.json()
                    app.logger.debug(f"Detail response för {alert_id}: {list(detail_json.keys())}")
                    
                    if 'alert' in detail_json:
                        detail = detail_json['alert']
                        
                        # Hitta och uppdatera motsvarande alert i processed_data
                        for risk_level in processed_data:
                            for alert in processed_data[risk_level]:
                                if str(alert.get('id')) == str(alert_id):
                                    alert.update({
                                        'description': detail.get('description', ''),
                                        'solution': detail.get('solution', ''),
                                        'reference': detail.get('reference', ''),
                                        'cweid': detail.get('cweid', ''),
                                        'wascid': detail.get('wascid', ''),
                                        'attack': detail.get('attack', ''),
                                        'evidence': detail.get('evidence', ''),
                                        'tags': detail.get('tags', {})
                                    })
                                    details_fetched += 1
                                    app.logger.debug(f"Uppdaterade alert {alert_id} med beskrivning: {detail.get('description', 'missing')[:50]}...")
                                    break
                else:
                    app.logger.warning(f"Detail API failed for {alert_id}: {detail_response.status_code}")
                    
            except Exception as detail_error:
                app.logger.error(f"Error fetching details for alert {alert_id}: {str(detail_error)}")
        
        app.logger.info(f"Uppdaterade {details_fetched} alerts med detaljerad information")
        
        # Hämta summary
        summary_url = f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/alert/view/alertsSummary/"
        summary_response = requests.get(summary_url, params={
            'apikey': ZAP_API_KEY,
            'baseurl': target_url
        }, timeout=10)
        
        summary = {}
        if summary_response.status_code == 200:
            raw_summary = summary_response.json()
            if 'alertsSummary' in raw_summary:
                summary = raw_summary['alertsSummary']
        
        return {
            'alerts_by_risk': processed_data,
            'summary': summary,
            'debug_info': {
                'total_alert_ids': len(alert_ids),
                'details_fetched': details_fetched,
                'sample_ids': alert_ids[:3]
            }
        }
        
    except Exception as e:
        app.logger.error(f"Error in fixed data fetch: {str(e)}")
        return {'error': f'Error fetching ZAP alerts: {str(e)}'}

@app.route('/api/download-access-control-pdf-report')
def download_access_control_pdf_report():
    """Generera och ladda ner PDF-rapport för Access Control test"""
    try:
        # Hämta test_file parameter
        test_file = request.args.get('test_file')
        
        if not test_file:
            return jsonify({'error': 'test_file parameter krävs'}), 400
        
        # Validera filnamn för säkerhet
        if not test_file.endswith('.json') or '..' in test_file:
            return jsonify({'error': 'Ogiltigt filnamn'}), 400
        
        # Läs testdata från fil
        try:
            filepath = os.path.join(access_control_manager.tests_dir, test_file)
            if not os.path.exists(filepath):
                return jsonify({'error': 'Testfil hittades inte'}), 404
                
            with open(filepath, 'r', encoding='utf-8') as f:
                test_data = json.load(f)
        except Exception as e:
            return jsonify({'error': f'Kunde inte läsa testfil: {str(e)}'}), 500
        
        # Skapa rapport-datum
        report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        test_date = datetime.fromtimestamp(test_data.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S') if test_data.get('timestamp') else 'N/A'
        
        # Beräkna sammanfattningsstatistik
        summary = {
            'unauthorized_count': 0,
            'redirect_count': 0,
            'access_denied_count': 0
        }
        
        if test_data.get('analysis') and test_data['analysis'].get('by_finding'):
            summary = {
                'unauthorized_count': test_data['analysis']['by_finding'].get('UNAUTHORIZED_ACCESS', 0),
                'redirect_count': test_data['analysis']['by_finding'].get('REDIRECT_RESPONSE', 0),
                'access_denied_count': test_data['analysis']['by_finding'].get('ACCESS_DENIED', 0)
            }
        
        # Rendera HTML-template för PDF
        html_content = render_template('access_control_pdf_report.html',
            test_data=test_data,
            report_date=report_date,
            test_date=test_date,
            summary=summary
        )
        
        # Skapa PDF
        pdf_file = generate_pdf_from_html(html_content)
        
        # Skapa response med PDF
        response = make_response(pdf_file)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="access_control_rapport_{test_data.get("test_id", "unknown")}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
        
        return response
        
    except Exception as e:
        app.logger.error(f"Error generating Access Control PDF report: {str(e)}")
        return jsonify({'error': f'Fel vid generering av PDF: {str(e)}'}), 500


if __name__ == '__main__':
    test_zap_functionality()
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=True)


