document.addEventListener('DOMContentLoaded', function() {
    // Element referenser
    const resetZapBtn = document.getElementById('reset-zap-btn');
    const startSessionBtn = document.getElementById('start-session-btn');
    const stopSessionBtn = document.getElementById('stop-session-btn');
    const refreshSessionsBtn = document.getElementById('refresh-sessions-btn');
    const startAccessTestBtn = document.getElementById('start-access-test-btn');
    const refreshResultsBtn = document.getElementById('refresh-results-btn');
    
    const currentSessionLabelInput = document.getElementById('current-session-label');
    const targetUrlInput = document.getElementById('target-url');
    const urlsFromSessionSelect = document.getElementById('urls-from-session');
    const credentialsFromSessionSelect = document.getElementById('credentials-from-session');
    const testDescriptionInput = document.getElementById('test-description');
    
    const resetStatus = document.getElementById('reset-status');
    const sessionRecordingStatus = document.getElementById('session-recording-status');
    const testStatus = document.getElementById('test-status');
    const savedSessions = document.getElementById('saved-sessions');
    const testResults = document.getElementById('test-results');
    const recordingInstructions = document.getElementById('recording-instructions');
    const targetDisplay = document.getElementById('target-display');
    const roleDisplay = document.getElementById('role-display');
    
    // State management
    let isRecording = false;
    let currentRecordingSession = null;
    
    // Event Listeners
    resetZapBtn.addEventListener('click', resetZAP);
    startSessionBtn.addEventListener('click', startSessionRecording);
    stopSessionBtn.addEventListener('click', stopSessionRecording);
    refreshSessionsBtn.addEventListener('click', loadSavedSessions);
    startAccessTestBtn.addEventListener('click', startAccessControlTest);
    refreshResultsBtn.addEventListener('click', loadTestResults);
    
    // Validering för att aktivera test-knappen
    urlsFromSessionSelect.addEventListener('change', validateTestConfiguration);
    credentialsFromSessionSelect.addEventListener('change', validateTestConfiguration);
    
    // Initial load
    loadSavedSessions();
    loadTestResults();
    
    // Auto-refresh
    setInterval(loadSavedSessions, 30000);
    setInterval(loadTestResults, 30000);
    
    /**
     * Nollställ ZAP för Access Control Testing
     */
    function resetZAP() {
        setButtonLoading(resetZapBtn, 'Nollställer ZAP...');
        resetStatus.innerHTML = '';
        
        fetch('/api/access-control/reset-zap', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showSuccess(resetStatus, data.message, 'ZAP Nollställt');
                // Rensa alla formulärfält
                clearAllForms();
                loadSavedSessions();
                loadTestResults();
            } else {
                showError(resetStatus, data.error);
            }
        })
        .catch(error => {
            console.error('Error resetting ZAP:', error);
            showError(resetStatus, `Nätverksfel: ${error.message}`);
        })
        .finally(() => {
            resetButtonLoading(resetZapBtn, '<i class="bi bi-arrow-clockwise"></i> Nollställ ZAP');
        });
    }
    
    /**
     * Starta session-inspelning
     */
    function startSessionRecording() {
        const sessionLabel = currentSessionLabelInput.value.trim();
        const targetUrl = targetUrlInput.value.trim();
        
        if (!sessionLabel) {
            showError(sessionRecordingStatus, 'Sessionsetikett krävs');
            currentSessionLabelInput.focus();
            return;
        }
        
        if (!targetUrl) {
            showError(sessionRecordingStatus, 'Target URL krävs');
            return;
        }
        
        setButtonLoading(startSessionBtn, 'Startar inspelning...');
        sessionRecordingStatus.innerHTML = '';
        
        fetch('/api/access-control/start-session-recording', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            },
            body: JSON.stringify({
                session_label: sessionLabel,
                target_url: targetUrl
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                isRecording = true;
                currentRecordingSession = {
                    label: sessionLabel,
                    target_url: targetUrl,
                    start_time: new Date()
                };
                
                // Uppdatera UI för inspelningsläge
                startSessionBtn.style.display = 'none';
                stopSessionBtn.style.display = 'inline-block';
                recordingInstructions.style.display = 'block';
                targetDisplay.textContent = targetUrl;
                roleDisplay.textContent = sessionLabel;
                
                // Disable andra kontroller under inspelning
                currentSessionLabelInput.disabled = true;
                resetZapBtn.disabled = true;
                
                showSuccess(sessionRecordingStatus, 
                    `Session-inspelning startad för "${sessionLabel}"`, 
                    'Inspelning aktiv', 0);
                    
                // Lägg till pulsande effekt
                sessionRecordingStatus.classList.add('recording-active');
                
            } else {
                showError(sessionRecordingStatus, data.error);
            }
        })
        .catch(error => {
            console.error('Error starting session recording:', error);
            showError(sessionRecordingStatus, `Nätverksfel: ${error.message}`);
        })
        .finally(() => {
            resetButtonLoading(startSessionBtn, '<i class="bi bi-play"></i> Starta session-inspelning');
        });
    }
    
    /**
     * Stoppa session-inspelning och spara data
     */
    function stopSessionRecording() {
        if (!currentRecordingSession) {
            showError(sessionRecordingStatus, 'Ingen aktiv session att stoppa');
            return;
        }
        
        setButtonLoading(stopSessionBtn, 'Stoppar och sparar...');
        
        fetch('/api/access-control/stop-session-recording', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            },
            body: JSON.stringify({
                session_label: currentRecordingSession.label,
                target_url: currentRecordingSession.target_url
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                isRecording = false;
                currentRecordingSession = null;
                
                // Återställ UI
                startSessionBtn.style.display = 'inline-block';
                stopSessionBtn.style.display = 'none';
                recordingInstructions.style.display = 'none';
                
                // Återaktivera kontroller
                currentSessionLabelInput.disabled = false;
                resetZapBtn.disabled = false;
                
                // Rensa sessionsetikett för nästa session
                currentSessionLabelInput.value = '';
                
                sessionRecordingStatus.classList.remove('recording-active');
                
                showSuccess(sessionRecordingStatus, 
                    `Session sparad: ${data.url_count} URL:er och ${data.cookies_found ? 'cookies' : 'inga cookies'} från "${data.session_label}"`,
                    'Session sparad', 5000);
                
                // Uppdatera listor
                loadSavedSessions();
                
            } else {
                showError(sessionRecordingStatus, data.error);
            }
        })
        .catch(error => {
            console.error('Error stopping session recording:', error);
            showError(sessionRecordingStatus, `Nätverksfel: ${error.message}`);
        })
        .finally(() => {
            resetButtonLoading(stopSessionBtn, '<i class="bi bi-stop"></i> Stoppa och spara session');
        });
    }
    
    /**
     * Ladda sparade sessioner
     */
    function loadSavedSessions() {
        fetch('/api/access-control/sessions')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displaySavedSessions(data.sessions);
                populateSessionDropdowns(data.sessions);
            } else {
                savedSessions.innerHTML = `<div class="alert alert-warning">Fel vid laddning: ${data.error}</div>`;
            }
        })
        .catch(error => {
            console.error('Error loading sessions:', error);
            savedSessions.innerHTML = `<div class="alert alert-danger">Nätverksfel: ${error.message}</div>`;
        });
    }
    
    /**
     * Visa sparade sessioner
     */
    function displaySavedSessions(sessions) {
        if (sessions.length === 0) {
            savedSessions.innerHTML = `
                <div class="text-center text-muted">
                    <i class="bi bi-folder"></i>
                    <p>Inga sparade sessioner ännu</p>
                </div>
            `;
            return;
        }
        
        let html = '';
        sessions.forEach(session => {
            const sessionClass = getSessionClass(session.session_label);
            html += `
                <div class="card mb-2 session-card ${sessionClass}">
                    <div class="card-body p-2">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="mb-1">${escapeHtml(session.session_label)}</h6>
                                <small class="text-muted">${formatDate(session.timestamp)}</small>
                            </div>
                            <div class="text-end">
                                <span class="badge bg-primary">${session.url_count} URLs</span>
                                ${session.has_cookies ? '<span class="badge bg-success ms-1">🍪</span>' : '<span class="badge bg-secondary ms-1">No cookies</span>'}
                            </div>
                        </div>
                        <div class="mt-1">
                            <small class="text-muted">${escapeHtml(session.target_url)}</small>
                        </div>
                    </div>
                </div>
            `;
        });
        
        savedSessions.innerHTML = html;
    }
    
    /**
     * Populera dropdown-menyer med sessioner
     */
    function populateSessionDropdowns(sessions) {
        // Rensa och populera URL dropdown
        const currentUrlValue = urlsFromSessionSelect.value;
        urlsFromSessionSelect.innerHTML = '<option value="">Välj session med URL:er...</option>';
        
        // Rensa och populera credentials dropdown  
        const currentCredValue = credentialsFromSessionSelect.value;
        credentialsFromSessionSelect.innerHTML = '<option value="">Välj session med credentials...</option>';
        
        sessions.forEach(session => {
            // URL dropdown - alla sessioner med URLs
            if (session.url_count > 0) {
                const urlOption = document.createElement('option');
                urlOption.value = session.filename;
                urlOption.textContent = `${session.session_label} (${session.url_count} URL:er)`;
                if (session.filename === currentUrlValue) {
                    urlOption.selected = true;
                }
                urlsFromSessionSelect.appendChild(urlOption);
            }
            
            // Credentials dropdown - alla sessioner (även utan cookies för "ej inloggad" test)
            const credOption = document.createElement('option');
            credOption.value = session.filename;
            const cookieText = session.has_cookies ? '🍪' : '(ej inloggad)';
            credOption.textContent = `${session.session_label} ${cookieText}`;
            if (session.filename === currentCredValue) {
                credOption.selected = true;
            }
            credentialsFromSessionSelect.appendChild(credOption);
        });
        
        // Validera test-konfiguration
        validateTestConfiguration();
    }
    
    /**
     * Validera test-konfiguration och aktivera/inaktivera test-knappen
     */
    function validateTestConfiguration() {
        const hasUrls = urlsFromSessionSelect.value !== '';
        const hasCredentials = credentialsFromSessionSelect.value !== '';
        
        startAccessTestBtn.disabled = !(hasUrls && hasCredentials);
        
        if (hasUrls && hasCredentials) {
            const urlSession = urlsFromSessionSelect.options[urlsFromSessionSelect.selectedIndex].text;
            const credSession = credentialsFromSessionSelect.options[credentialsFromSessionSelect.selectedIndex].text;
            
            // Automatisk testbeskrivning om inget angivet
            if (!testDescriptionInput.value.trim()) {
                testDescriptionInput.value = `Testa åtkomst: URL:er från ${urlSession.split(' (')[0]} med credentials från ${credSession.split(' ')[0]}`;
            }
        }
    }
    
    /**
     * Starta Access Control Test
     */
    function startAccessControlTest() {
        const urlsFromSession = urlsFromSessionSelect.value;
        const credentialsFromSession = credentialsFromSessionSelect.value;
        const testDescription = testDescriptionInput.value.trim();
        
        if (!urlsFromSession || !credentialsFromSession) {
            showError(testStatus, 'Både URL-session och credentials-session måste väljas');
            return;
        }
        
        setButtonLoading(startAccessTestBtn, 'Startar Access Control Test...');
        testStatus.innerHTML = '';
        
        fetch('/api/access-control/test-with-sessions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            },
            body: JSON.stringify({
                urls_from_session: urlsFromSession,
                credentials_from_session: credentialsFromSession,
                test_description: testDescription
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showSuccess(testStatus, 
                    `Access Control Test startat: ${data.test_count} URL:er att testa`,
                    'Test startat', 5000);
                
                // Uppdatera resultat efter en kort fördröjning
                setTimeout(loadTestResults, 2000);
            } else {
                showError(testStatus, data.error);
            }
        })
        .catch(error => {
            console.error('Error starting access control test:', error);
            showError(testStatus, `Nätverksfel: ${error.message}`);
        })
        .finally(() => {
            resetButtonLoading(startAccessTestBtn, '<i class="bi bi-shield-check"></i> Starta Access Control Test');
        });
    }
    
    /**
     * Ladda testresultat
     */
    function loadTestResults() {
        fetch('/api/access-control/test-results')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayTestResults(data.results);
            } else {
                testResults.innerHTML = `<div class="alert alert-warning">Fel vid laddning av resultat: ${data.error}</div>`;
            }
        })
        .catch(error => {
            console.error('Error loading test results:', error);
            testResults.innerHTML = `<div class="alert alert-danger">Nätverksfel vid laddning av resultat: ${error.message}</div>`;
        });
    }
    
    /**
     * Visa testresultat
     */
    /**
     * Visa testresultat - uppdaterad för att matcha rapporten
     */
    function displayTestResults(results) {
        if (results.length === 0) {
            testResults.innerHTML = `
                <div class="text-center text-muted">
                    <i class="bi bi-clipboard-data"></i>
                    <p>Inga testresultat ännu. Kör ett Access Control Test för att se resultat.</p>
                </div>
            `;
            return;
        }
        
        let html = '';
        results.forEach(result => {
            // Beräkna rätt antal problem från analysis
            const unauthorizedCount = result.analysis && result.analysis.by_finding ? 
                result.analysis.by_finding['UNAUTHORIZED_ACCESS'] || 0 : 0;
            const redirectCount = result.analysis && result.analysis.by_finding ? 
                result.analysis.by_finding['REDIRECT_RESPONSE'] || 0 : 0;
            const accessDeniedCount = result.analysis && result.analysis.by_finding ? 
                result.analysis.by_finding['ACCESS_DENIED'] || 0 : 0;
            
            // Bestäm status baserat på unauthorized count
            let statusClass, statusText, statusIcon;
            if (unauthorizedCount > 0) {
                statusClass = 'bg-danger';
                statusText = 'KRÄVER GRANSKNING';
                statusIcon = 'bi-shield-exclamation';
            } else if (redirectCount > 0) {
                statusClass = 'bg-warning';
                statusText = 'KONTROLLERA OMDIRIGERINGAR';
                statusIcon = 'bi-arrow-repeat';
            } else {
                statusClass = 'bg-success';
                statusText = 'PASSED';
                statusIcon = 'bi-shield-check';
            }
            
            html += `
                <div class="card mb-3">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0">${escapeHtml(result.test_description || 'Access Control Test')}</h6>
                        <div>
                            <span class="badge ${statusClass}">
                                <i class="${statusIcon}"></i> ${statusText}
                            </span>
                            <small class="text-muted ms-2">${formatDate(result.timestamp)}</small>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <p><strong>URL:er testade:</strong> ${result.total_tests}</p>
                                ${unauthorizedCount > 0 ? 
                                    `<p><strong style="color: #dc3545;">🚨 Obehöriga åtkomster:</strong> <span class="badge bg-danger">${unauthorizedCount}</span></p>` :
                                    `<p><strong style="color: #28a745;">✅ Inga access control-problem upptäckta</strong></p>`
                                }
                            </div>
                            <div class="col-md-6">
                                <p><strong>URL-session:</strong> ${escapeHtml(result.urls_session || result.url_session || 'N/A')}</p>
                                <p><strong>Credentials-session:</strong> ${escapeHtml(result.credentials_session || 'N/A')}</p>
                            </div>
                        </div>
                        
                        <!-- Visa detaljerad analys -->
                        ${result.analysis && result.analysis.by_finding ? `
                            <div class="mt-3">
                                <h6>Detaljerad analys:</h6>
                                <div class="row">
                                    ${Object.entries(result.analysis.by_finding).map(([finding, count]) => {
                                        let badgeClass = 'bg-secondary';
                                        let displayText = finding.replace(/_/g, ' ').toLowerCase();
                                        
                                        if (finding === 'UNAUTHORIZED_ACCESS') {
                                            badgeClass = 'bg-danger';
                                            displayText = 'obehöriga åtkomster';
                                        } else if (finding === 'REDIRECT_RESPONSE') {
                                            badgeClass = 'bg-warning';
                                            displayText = 'omdirigeringar';
                                        } else if (finding === 'ACCESS_DENIED') {
                                            badgeClass = 'bg-success';
                                            displayText = 'åtkomst nekad (korrekt)';
                                        }
                                        
                                        return `
                                            <div class="col-auto mb-2">
                                                <span class="badge ${badgeClass}">${count} ${displayText}</span>
                                            </div>
                                        `;
                                    }).join('')}
                                </div>
                            </div>
                        ` : ''}
                        
                        <div class="mt-3">
                            <a href="/access-control-report?test_file=test_report_${result.test_id}.json" 
                            class="btn btn-primary btn-sm">
                                <i class="bi bi-file-text"></i> Visa fullständig rapport
                            </a>
                        </div>
                    </div>
                </div>
            `;
        });
        
        testResults.innerHTML = html;
    }
    
    // Helper functions
    function clearAllForms() {
        currentSessionLabelInput.value = '';
        testDescriptionInput.value = '';
        urlsFromSessionSelect.innerHTML = '<option value="">Välj session med URL:er...</option>';
        credentialsFromSessionSelect.innerHTML = '<option value="">Välj session med credentials...</option>';
        startAccessTestBtn.disabled = true;
    }
    
    function setButtonLoading(button, text) {
        button.disabled = true;
        button.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status"></span>${text}`;
    }
    
    function resetButtonLoading(button, originalHtml) {
        button.disabled = false;
        button.innerHTML = originalHtml;
    }
    
    function showSuccess(element, message, title = 'Framgång', duration = 5000) {
        element.innerHTML = `
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <strong>${title}:</strong> ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        if (duration > 0) {
            setTimeout(() => {
                element.innerHTML = '';
            }, duration);
        }
    }
    
    function showError(element, message) {
        element.innerHTML = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <strong>Fel:</strong> ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
    }
    
    function getCSRFToken() {
        return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    function formatDate(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleDateString('sv-SE') + ' ' + date.toLocaleTimeString('sv-SE');
    }
    
    function getSessionClass(sessionLabel) {
        const label = sessionLabel.toLowerCase();
        if (label.includes('admin') || label.includes('root')) return 'session-critical';
        if (label.includes('manager') || label.includes('supervisor')) return 'session-high';
        if (label.includes('user') || label.includes('member')) return 'session-medium';
        return 'session-low';
    }
    
    function getRiskBadgeClass(risk) {
        const riskClasses = {
            'CRITICAL': 'bg-danger',
            'HIGH': 'bg-warning',
            'MEDIUM': 'bg-info',
            'LOW': 'bg-success',
            'ERROR': 'bg-secondary'
        };
        return riskClasses[risk] || 'bg-secondary';
    }
});