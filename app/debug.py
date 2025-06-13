
'''
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

'''

'''
@app.route('/api/start-sqlmap', methods=['POST'])
def api_start_sqlmap():
    """API-endpoint för att starta SQL injection-scanning"""
    print("/api/start-sqlmap")
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
'''
'''
@app.route('/api/sqlmap-status/<scan_id>')
def api_sqlmap_status(scan_id):
    print("api/sqlmap-status/<scan_id>")
    """API-endpoint för att hämta SQL injection-status"""
    status = sql_tester.get_status(scan_id)
    return jsonify(status)
'''
'''
@app.route('/api/sqlmap-results/<scan_id>')
def sqlmap_results(scan_id):
    print("/api/sqlmap-results/<scan_id>")
    """API-endpoint för att hämta SQL injection-resultat"""
    if not scan_id:
        return jsonify({'error': 'No scan ID provided'}), 400
        
    results = sql_tester.get_results(scan_id)
    summary = sql_tester.get_summary(scan_id)
    
    return jsonify({
        'results': results,
        'summary': summary
    })
'''


'''
@app.route('/api/scan-from-zap', methods=['POST'])
def api_scan_from_zap():
    """API-endpoint för att starta SQL injection scan baserat på ZAP-resultat"""
    print('/api/scan-from-zap')
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
'''

'''
@app.route('/api/sql-zap-status/<scan_id>')
def api_sql_zap_status(scan_id):
    """API-endpoint för att hämta status för SQL injection scan baserat på ZAP-data"""
    status = sql_tester.get_status(scan_id)
    return jsonify(status)
'''
'''
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
'''


'''
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
'''

'''
@app.route('/scan-details/<scan_id>')
def scan_details(scan_id):
    """Visa detaljerad information om en SQL injection scanning"""
    
    # Kontrollera att scanningen finns
    scan_dir = os.path.join(app.config['RESULTS_DIR'], 'sql_tester', scan_id)
    if not os.path.exists(scan_dir):
        flash('Scanning med angivet ID hittades inte.', 'danger')
        return redirect(url_for('scan'))
    
    return render_template('scan_details.html', scan_id=scan_id)
'''


'''
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
'''


'''
@app.route('/api/save-session', methods=['POST'])
def save_session():
    """API-endpoint för att spara en session"""
    print("/api/save-session")
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
'''

'''
@app.route('/scan-zap-urls')
def scan_zap_urls():
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!/scan-zap-urls")
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
'''
'''
@app.route('/test-sql-injection')
def test_sql_injection():
    print("/test-sql-injection")
    """Testrutt för SQL injection-testern"""
    target_url = request.args.get('url', 'http://192.168.2.148:3000')
    
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
'''


'''
@app.route('/api/extract-cookies', methods=['GET', 'POST'])
def api_extract_cookies():
    print("/api/extract-cookies")
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
'''

@app.route('/debug-zap-urls')
def debug_zap_urls():
    """Visar debug-sidan för ZAP URLs"""
    return render_template('debug_zap_urls.html')



@app.route('/api/debug-zap-urls')
def api_debug_zap_urls():
    """API endpoint för att hämta information om ZAP URLs och parametrar"""
    result = {
        'zap_available': False,
        'sites': [],
        'urls': [],
        'forms': [],
        'alerts': [],
        'urls_from_alerts': [],
        'history_count': 0,
        'timestamp': time.time()
    }



def start_ajax_spider(target_url):
    """Start ZAP Ajax Spider against the target URL using direct HTTP calls"""
    app.logger.info(f'Starting Ajax Spider for target: {target_url}')
    
    try:
        # Direct API call to start Ajax Spider
        result = _direct_api_call('ajaxSpider/action/scan', {'url': target_url})
        
        if result['success']:
            app.logger.info(f'Ajax Spider scan started for: {target_url}')
            return {
                'success': True,
                'status': 'started',
                'target': target_url
            }
        else:
            error_msg = f"Failed to start Ajax Spider: {result.get('response', 'Unknown error')}"
            app.logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    except Exception as e:
        app.logger.error(f'Error starting Ajax Spider scan: {str(e)}')
        return {
            'success': False,
            'error': str(e)
        }

@app.route('/explore-sqlmap-image')
def api_explore_sqlmap_image():
    """API-route för att utforska local-sqlmap imagen"""
    result = explore_sqlmap_image()
    return jsonify({'output': result})

def explore_sqlmap_image():
    """Utforska local-sqlmap imagen för att se dess struktur"""
    try:
        # Kör en tillfällig container för att utforska strukturen
        cmd = [
            'docker', 'run', '--rm', '--entrypoint', '/bin/sh',
            'local-sqlmap', '-c', 'find / -name "sqlmap.py" 2>/dev/null; ls -la /app 2>/dev/null; echo "WORKDIR: $PWD"'
        ]
        
        output = subprocess.check_output(cmd, text=True)
        print("Docker image structure exploration:")
        print(output)
        
        return output
    except Exception as e:
        print(f"Error exploring Docker image: {str(e)}")
        return None
    

def cleanup_old_scans():
    """Rensa gamla skanningsstatusdata för att förhindra minnesläckor"""
    while True:
        try:
            now = time.time()
            with scan_status_lock:
                # Ta bort skanningar äldre än 24 timmar
                to_remove = []
                for scan_id, status in scan_statuses.items():
                    # Kontrollera slutförandetid eller starttid (om den inte slutfördes)
                    end_time = status.get('completion_time') or status.get('cancellation_time') or 0
                    if end_time > 0 and now - end_time > 86400:  # 24 timmar
                        to_remove.append(scan_id)
                    # För skanningar som aldrig slutförde
                    elif status.get('status') != 'completed' and status.get('status') != 'cancelled':
                        start_time = status.get('start_time', 0)
                        if start_time > 0 and now - start_time > 86400 * 2:  # 48 timmar för aktiva
                            to_remove.append(scan_id)
                
                # Ta bort identifierade skanningar
                for scan_id in to_remove:
                    del scan_statuses[scan_id]
                    print(f"Removed old scan: {scan_id}")
        except Exception as e:
            print(f"Error in cleanup_old_scans: {str(e)}")
        
        # Kör var 6:e timme
        time.sleep(21600)


def check_sqlmap_image():
    """Kontrollera om local-sqlmap imagen finns och bygg den om den inte finns"""
    try:
        # Kontrollera om local-sqlmap imagen finns
        result = subprocess.run(['docker', 'images', 'local-sqlmap', '--format', '{{.Repository}}'], 
                               capture_output=True, text=True)
        
        if 'local-sqlmap' not in result.stdout:
            app.logger.warning("local-sqlmap Docker image not found, building it...")
            
            # Skapa en tillfällig Dockerfile
            dockerfile_dir = os.path.join(app.config['RESULTS_DIR'], 'sqlmap-dockerfile')
            os.makedirs(dockerfile_dir, exist_ok=True)
            
            with open(os.path.join(dockerfile_dir, 'Dockerfile'), 'w') as f:
                f.write("""FROM python:3.9-slim

RUN apt-get update && \\
    apt-get install -y git && \\
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /sqlmap && \\
    apt-get remove -y git && \\
    apt-get autoremove -y && \\
    apt-get clean && \\rm 
    rm -rf /var/lib/apt/lists/*

WORKDIR /sqlmap

EXPOSE 8775

CMD ["python3", "-m", "sqlmapapi", "-s", "-H", "0.0.0.0"]
""")
            
            # Bygg imagen
            build_result = subprocess.run(['docker', 'build', '-t', 'local-sqlmap', dockerfile_dir], 
                                        capture_output=True, text=True)
            
            if build_result.returncode == 0:
                app.logger.info("Successfully built local-sqlmap Docker image")
            else:
                app.logger.error(f"Failed to build local-sqlmap Docker image: {build_result.stderr}")
        else:
            app.logger.info("local-sqlmap Docker image found")
    except Exception as e:
        app.logger.error(f"Error checking/building local-sqlmap Docker image: {str(e)}")

@app.route('/api/maintenance')
def api_maintenance():
    """API-endpoint för att utföra underhåll på ZAP"""
    result = zap.cleanup_resources()
    return jsonify({
        'success': result,
        'timestamp': time.time()
    })


@app.route('/debug-zap')
def debug_zap():
    """Debug-sida för ZAP-anslutning"""
    results = {
        'status': 'unknown',
        'details': {},
        'errors': []
    }
    
    try:
        # Testa generell anslutning
        version = zap.zap.core.version
        results['status'] = 'available'
        results['details']['version'] = version
        
        # Hämta alla tillgängliga platser
        try:
            sites = zap.zap.core.sites
            results['details']['sites'] = sites
        except Exception as e:
            results['errors'].append(f"Failed to get sites: {str(e)}")
        
        # Testa proxy-anslutningen
        try:
            proxy_url = f"http://{ZAP_HOST}:{ZAP_PROXY_PORT}"
            
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            # Gör en testförfrågan via proxyn
            response = requests.get('http://example.com', proxies=proxies, timeout=5)
            results['details']['proxy_test'] = {
                'status_code': response.status_code,
                'content_length': len(response.content)
            }
        except Exception as e:
            results['errors'].append(f"Failed proxy test: {str(e)}")
            
    except Exception as e:
        results['status'] = 'unavailable'
        results['errors'].append(f"General connection error: {str(e)}")
    
    return render_template('debug_zap.html', results=results)


@app.route('/api/reconnect-zap', methods=['POST'])
def api_reconnect_zap():
    """Försök att återansluta till ZAP"""
    global zap
    
    try:
        # Försök återansluta med samma konfiguration
        from modules.zap_controller import ZAPController
        new_zap = ZAPController(
            api_key=ZAP_API_KEY, 
            host=ZAP_HOST, 
            port=ZAP_API_PORT
        )
        
        if new_zap.is_available():
            # Uppdatera den globala referensen
            zap = new_zap
            return jsonify({
                'success': True,
                'message': 'Successfully reconnected to ZAP',
                'version': new_zap.zap.core.version
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to reconnect to ZAP'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error during reconnection: {str(e)}'
        }), 500

def periodic_cleanup():
    """Kör periodisk rensning av ZAP-resurser"""
    while True:
        try:
            app.logger.info("Running scheduled ZAP resource cleanup")
            result = zap.enforce_resource_limits()
            app.logger.info(f"Resource cleanup completed: {result}")
        except Exception as e:
            app.logger.error(f"Error in periodic cleanup: {str(e)}")
        
        # Vänta 5 minuter innan nästa rensning
        time.sleep(300)

@app.route('/debug-session')
def debug_session():
    """Hjälproute för att debugga sessionshanteringen"""
    session_data = {k: session.get(k) for k in session}
    return jsonify({
        'session_data': session_data,
        'has_target_url': 'target_url' in session,
        'has_spider_scan_id': 'spider_scan_id' in session,
        'has_active_scan_id': 'active_scan_id' in session,
        'spider_scan_id': session.get('spider_scan_id'),
        'active_scan_id': session.get('active_scan_id')
    })



def get_ajax_spider_results():
    """Get the results of the Ajax Spider scan using direct HTTP calls"""
    try:
        # Direct API call to get Ajax Spider results
        result = _direct_api_call('ajaxSpider/view/results')
        
        if result['success']:
            results = result['data'].get('results', [])
            return {
                'success': True,
                'results': results,
                'count': len(results)
            }
        else:
            error_msg = f"Failed to get Ajax Spider results: {result.get('response', 'Unknown error')}"
            app.logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    except Exception as e:
        app.logger.error(f'Error getting Ajax Spider results: {str(e)}')
        return {
            'success': False,
            'error': str(e)
        }


@app.route('/debug-zap-sites')
def debug_zap_sites():
    """Debuggar ZAP sites för att hitta varför target URL inte kan hittas"""
    result = {
        'timestamp': time.time(),
        'zap_available': False,
        'sites': [],
        'juiceshop_detected': False
    }
    
    try:
        # Kontrollera om ZAP är tillgänglig
        if not zap.is_available():
            return jsonify(result), 500
            
        result['zap_available'] = True
        
        # Hämta alla sites
        sites = zap.zap.core.sites
        result['sites'] = sites
        
        # Kontrollera om Juice Shop finns bland sites
        juice_shop_patterns = [
            '192.168.2.148:3000',
            'juice-shop',
            'juiceshop'
        ]
        
        for site in sites:
            for pattern in juice_shop_patterns:
                if pattern in site:
                    result['juiceshop_detected'] = True
                    result['juiceshop_site'] = site
                    break
        
        # Försök hämta alla URL:er från ZAP för första siten
        if sites:
            try:
                site = sites[0]
                result['example_site'] = site
                
                # Hämta meddelanden för denna site
                messages = zap.zap.core.messages(baseurl=site)
                
                # Hantera olika responsformat i ZAP API
                if isinstance(messages, dict) and 'messages' in messages:
                    messages = messages['messages']
                
                urls = []
                for message in messages:
                    if isinstance(message, dict) and 'url' in message:
                        urls.append(message['url'])
                        
                result['example_urls'] = urls[:10]  # Begränsa antalet för att undvika för stort svar
                result['example_urls_count'] = len(urls)
            except Exception as e:
                result['example_error'] = str(e)
                
        return jsonify(result)
    except Exception as e:
        result['error'] = str(e)
        return jsonify(result), 500
    
@app.route('/debug-zap-view')
def debug_zap_view():
    """Visa debug-vy för ZAP sites"""
    return render_template('debug_zap_sites.html')



@app.route('/api/test-zap-api')
def api_test_zap_api():
    """Test API call för att direkt kolla ZAP API:n"""
    try:
        # Basic API call
        sites_response = zap._direct_api_call('core/view/sites')
        
        if sites_response:
            return jsonify({
                'success': True,
                'sites': sites_response.get('sites', []),
                'api_url': f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/",
                'methods_tested': ['sites']
            })
        else:
            return jsonify({
                'success': False,
                'error': 'API call returned no data',
                'api_url': f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/"
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'api_url': f"http://{ZAP_HOST}:{ZAP_API_PORT}/JSON/"
        })



@app.route('/api/test-cookies/<path:url>')
def api_test_cookies(url):
    """Testar att hämta cookies för en specifik URL direkt"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        cookies = zap.get_cookies(url)
        
        # Lägg även till debug-information
        domain = zap._extract_domain_or_ip(url)
        sites = zap.zap.core.sites if zap.is_available() else []
        matching_sites = [s for s in sites if domain in s]
        
        return jsonify({
            'success': True,
            'url': url,
            'domain': domain,
            'cookies': cookies,
            'matching_sites': matching_sites,
            'all_sites': sites
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'url': url,
            'error': str(e)
        })
    

@app.route('/api/zap-version-info')
def api_zap_version_info():
    """Get detailed ZAP version and API information"""
    try:
        if not zap.is_available():
            return jsonify({'error': 'ZAP is not available'}), 503
            
        # Get ZAP version
        version = zap.zap.core.version
        
        # Try to get additional version details
        additional_info = {}
        
        # Check available core methods
        core_methods = dir(zap.zap.core)
        
        # Check for specific methods to determine API version
        has_delete_site_node = 'delete_site_node' in core_methods
        has_delete_all_alerts = 'delete_all_alerts' in core_methods
        has_new_session = 'new_session' in core_methods
        
        return jsonify({
            'version': version,
            'api_methods': {
                'delete_site_node': has_delete_site_node,
                'delete_all_alerts': has_delete_all_alerts,
                'new_session': has_new_session
            },
            'core_methods': core_methods
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/test-cookies-direct')
def test_cookies_direct():
    """Test-URL för att direkt visa cookies för target_url"""
    target_url = session.get('target_url', '')
    
    if not target_url:
        return render_template('test_cookies.html', 
                              target_url="No target URL in session",
                              cookies="",
                              zap_available=False)
    
    if not zap.is_available():
        return render_template('test_cookies.html', 
                              target_url=target_url,
                              cookies="ZAP is not available",
                              zap_available=False)
    
    # Hämta domännamn
    domain = zap._extract_domain_or_ip(target_url)
    
    # Hämta alla sites
    sites = zap.zap.core.sites
    matching_sites = [s for s in sites if domain in s]
    
    # Hämta cookies direkt
    cookies = zap.get_cookies(target_url)
    
    return render_template('test_cookies.html', 
                          target_url=target_url,
                          domain=domain,
                          sites=sites,
                          matching_sites=matching_sites,
                          cookies=cookies,
                          zap_available=True)


def run_scan_in_background(scan_id, target_url):
    print("def run_scan_in_background")
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

