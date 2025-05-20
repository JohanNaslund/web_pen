

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
