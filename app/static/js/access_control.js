// app/static/js/access_control.js
/**
 * JavaScript för Access Control Testing
 */

document.addEventListener('DOMContentLoaded', function() {
    // Element referenser
    const resetZapBtn = document.getElementById('reset-zap-btn');
    const collectUrlsBtn = document.getElementById('collect-urls-btn');
    const targetUrlInput = document.getElementById('target-url');
    const sessionLabelInput = document.getElementById('session-label');
    const startTestBtn = document.getElementById('start-test-btn');
    const extractCookiesBtn = document.getElementById('extract-cookies-btn');
    const refreshSessionsBtn = document.getElementById('refresh-sessions-btn');
    const refreshResultsBtn = document.getElementById('refresh-results-btn');
    
    const sourceSessionSelect = document.getElementById('source-session-select');
    const testLabelInput = document.getElementById('test-label');
    const testCookiesInput = document.getElementById('test-cookies');
    
    const resetStatus = document.getElementById('reset-status');
    const collectionStatus = document.getElementById('collection-status');
    const testStatus = document.getElementById('test-status');
    const sessionsList = document.getElementById('sessions-list');
    const testResults = document.getElementById('test-results');
    
    // Event Listeners
    resetZapBtn.addEventListener('click', resetZAP);
    collectUrlsBtn.addEventListener('click', collectURLs);
    startTestBtn.addEventListener('click', startAccessControlTest);
    extractCookiesBtn.addEventListener('click', extractCookies);
    refreshSessionsBtn.addEventListener('click', loadSessions);
    refreshResultsBtn.addEventListener('click', loadTestResults);
    
    // Auto-refresh sessions and results every 30 seconds
    setInterval(loadSessions, 30000);
    setInterval(loadTestResults, 30000);
    
    // Initial load
    loadSessions();
    loadTestResults();
    
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
                showSuccess(resetStatus, data.message, 'ZAP har nollställts framgångsrikt!');
                // Rensa formulärfält
                targetUrlInput.value = '';
                sessionLabelInput.value = '';
                testCookiesInput.value = '';
                testLabelInput.value = '';
                // Uppdatera listor
                loadSessions();
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
            resetButtonLoading(resetZapBtn, '<i class="bi bi-arrow-clockwise"></i> Nollställ ZAP för Access Control Testing');
        });
    }
    
    /**
     * Samla URL:er från nuvarande ZAP-session
     */
    function collectURLs() {
        const targetUrl = targetUrlInput.value.trim();
        const sessionLabel = sessionLabelInput.value.trim();
        
        // Validering
        if (!targetUrl) {
            showError(collectionStatus, 'Target URL krävs');
            targetUrlInput.focus();
            return;
        }
        
        if (!sessionLabel) {
            showError(collectionStatus, 'Sessionsetikett krävs');
            sessionLabelInput.focus();
            return;
        }
        
        // Validera URL-format
        try {
            new URL(targetUrl.startsWith('http') ? targetUrl : 'http://' + targetUrl);
        } catch {
            showError(collectionStatus, 'Ogiltig URL-format');
            targetUrlInput.focus();
            return;
        }
        
        setButtonLoading(collectUrlsBtn, 'Samlar URL:er...');
        collectionStatus.innerHTML = '';
        
        fetch('/api/access-control/collect-urls', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            },
            body: JSON.stringify({
                target_url: targetUrl,
                session_label: sessionLabel
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Skapa framgångsmeddelande med detaljer
                let successHtml = `
                    <div class="alert alert-success">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-check-circle-fill me-2"></i>
                            <div>
                                <strong>Framgång!</strong> Samlade ${data.url_count} URL:er för session "${data.session_label}"
                                <br><small class="text-muted">Fil: ${data.filename}</small>
                            </div>
                        </div>
                `;
                
                // Visa kategorier om tillgängliga
                if (data.categories && Object.keys(data.categories).length > 0) {
                    successHtml += '<div class="mt-2"><strong>Kategorier:</strong><br>';
                    for (const [category, count] of Object.entries(data.categories)) {
                        successHtml += `<span class="badge bg-info category-badge">${category}: ${count}</span>`;
                    }
                    successHtml += '</div>';
                }
                
                // Visa preview av URL:er
                if (data.preview_urls && data.preview_urls.length > 0) {
                    successHtml += '<div class="mt-2"><strong>Exempel URL:er:</strong><ul class="list-unstyled mt-1">';
                    data.preview_urls.slice(0, 3).forEach(url => {
                        const categoryClass = getCategoryClass(url.category);
                        successHtml += `
                            <li class="mb-1">
                                <span class="badge ${categoryClass} me-1">${url.method}</span>
                                <code class="url-display">${truncateUrl(url.url, 60)}</code>
                            </li>
                        `;
                    });
                    if (data.preview_urls.length > 3) {
                        successHtml += `<li class="text-muted">...och ${data.preview_urls.length - 3} till</li>`;
                    }
                    successHtml += '</ul></div>';
                }
                
                successHtml += '</div>';
                collectionStatus.innerHTML = successHtml;
                
                // Uppdatera sessionslistan
                loadSessions();
                
                // Rensa formuläret för nästa session
                sessionLabelInput.value = '';
                sessionLabelInput.focus();
            } else {
                showError(collectionStatus, data.error);
            }
        })
        .catch(error => {
            console.error('Error collecting URLs:', error);
            showError(collectionStatus, `Nätverksfel: ${error.message}`);
        })
        .finally(() => {
            resetButtonLoading(collectUrlsBtn, '<i class="bi bi-collection"></i> Samla URL:er från nuvarande ZAP-session');
        });
    }
    
    /**
     * Ladda lista över insamlade sessioner
     */
    function loadSessions() {
        sessionsList.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm" role="status"></div> Laddar sessioner...</div>';
        
        fetch('/api/access-control/sessions')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displaySessions(data.sessions);
                populateSessionSelect(data.sessions);
            } else {
                sessionsList.innerHTML = `<div class="alert alert-danger">Fel: ${data.error}</div>`;
            }
        })
        .catch(error => {
            console.error('Error loading sessions:', error);
            sessionsList.innerHTML = `<div class="alert alert-danger">Nätverksfel: ${error.message}</div>`;
        });
    }
    
    /**
     * Visa sessioner i UI med förbättrad styling
     */
    function displaySessions(sessions) {
        if (sessions.length === 0) {
            sessionsList.innerHTML = `
                <div class="alert alert-info">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-info-circle me-2"></i>
                        <div>
                            <strong>Inga sessioner ännu</strong>
                            <br>Börja med att logga in som en användare och samla URL:er.
                        </div>
                    </div>
                </div>
            `;
            return;
        }
        
        let html = '';
        
        sessions.forEach((session, index) => {
            const date = new Date(session.collection_time * 1000);
            const relativeTime = getRelativeTime(date);
            const sessionClass = getSessionClass(session.session_label);
            
            html += `
                <div class="session-card mb-3">
                    <div class="session-header">
                        <div class="d-flex justify-content-between align-items-center">
                            <div class="d-flex align-items-center">
                                <span class="risk-indicator ${sessionClass}"></span>
                                <h6 class="mb-0">
                                    <span class="badge bg-primary">${escapeHtml(session.session_label)}</span>
                                    <span class="text-muted ms-2">${session.url_count} URL:er</span>
                                </h6>
                            </div>
                            <small class="text-muted">${relativeTime}</small>
                        </div>
                    </div>
                    <div class="session-body">
                        <div class="mb-2">
                            <strong>Target:</strong> 
                            <code class="url-display">${escapeHtml(session.target_url)}</code>
                        </div>
            `;
            
            // Visa kategorier
            if (session.categories && Object.keys(session.categories).length > 0) {
                html += '<div><strong>Kategorier:</strong><br>';
                for (const [category, count] of Object.entries(session.categories)) {
                    const categoryClass = getCategoryClass(category);
                    html += `<span class="badge ${categoryClass} category-badge">${category}: ${count}</span>`;
                }
                html += '</div>';
            }
            
            html += `
                    </div>
                </div>
            `;
        });
        
        sessionsList.innerHTML = html;
    }
    
    /**
     * Populera session select dropdown
     */
    function populateSessionSelect(sessions) {
        const currentValue = sourceSessionSelect.value;
        sourceSessionSelect.innerHTML = '<option value="">Välj session...</option>';
        
        sessions.forEach(session => {
            const option = document.createElement('option');
            option.value = session.filename;
            option.textContent = `${session.session_label} (${session.url_count} URL:er)`;
            if (session.filename === currentValue) {
                option.selected = true;
            }
            sourceSessionSelect.appendChild(option);
        });
    }
    
    /**
     * Extrahera cookies från ZAP
     */
    function extractCookies() {
        setButtonLoading(extractCookiesBtn, 'Hämtar cookies...');
        
        fetch('/api/access-control/extract-cookies')
        .then(response => {
            // Hantera både lyckade och misslyckade HTTP-svar
            if (!response.ok) {
                return response.json().then(errorData => {
                    throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.success && data.cookies) {
                testCookiesInput.value = data.cookies;
                testCookiesInput.classList.add('is-valid');
                setTimeout(() => testCookiesInput.classList.remove('is-valid'), 3000);
                
                showSuccess(testStatus, 
                    `Cookies extraherade från ${data.target_url || 'ZAP'}`, 
                    'Framgång', 5000);
            } else {
                testCookiesInput.classList.add('is-invalid');
                setTimeout(() => testCookiesInput.classList.remove('is-invalid'), 3000);
                
                // Visa förslag om de finns
                let errorMessage = data.error || 'Inga cookies hittades i ZAP';
                if (data.suggestions && data.suggestions.length > 0) {
                    errorMessage += '<br><br><strong>Förslag:</strong><ul>';
                    data.suggestions.forEach(suggestion => {
                        errorMessage += `<li>${suggestion}</li>`;
                    });
                    errorMessage += '</ul>';
                }
                
                // Lägg till debug-knapp för felsökning
                errorMessage += '<br><button id="debug-cookies-btn" class="btn btn-sm btn-outline-secondary mt-2">Debug cookie-extraktion</button>';
                
                showError(testStatus, errorMessage, 'Inga cookies hittades', 10000);
                
                // Lägg till event listener för debug-knappen
                setTimeout(() => {
                    const debugBtn = document.getElementById('debug-cookies-btn');
                    if (debugBtn) {
                        debugBtn.addEventListener('click', debugCookieExtraction);
                    }
                }, 100);
            }
        })
        .catch(error => {
            console.error('Error extracting cookies:', error);
            testCookiesInput.classList.add('is-invalid');
            setTimeout(() => testCookiesInput.classList.remove('is-invalid'), 3000);
            
            let errorMessage = `Fel vid cookie-extraktion: ${error.message}`;
            
            // Lägg till specifika felmeddelanden för vanliga problem
            if (error.message.includes('Target URL')) {
                errorMessage += '<br><br><strong>Lösning:</strong> Gå till startsidan och konfigurera ett mål-URL först.';
            } else if (error.message.includes('ZAP är inte tillgänglig')) {
                errorMessage += '<br><br><strong>Lösning:</strong> Kontrollera att ZAP körs och är ansluten.';
            }
            
            errorMessage += '<br><button id="debug-cookies-btn" class="btn btn-sm btn-outline-secondary mt-2">Debug cookie-extraktion</button>';
            
            showError(testStatus, errorMessage, 'Fel', 10000);
            
            // Lägg till event listener för debug-knappen
            setTimeout(() => {
                const debugBtn = document.getElementById('debug-cookies-btn');
                if (debugBtn) {
                    debugBtn.addEventListener('click', debugCookieExtraction);
                }
            }, 100);
        })
        .finally(() => {
            resetButtonLoading(extractCookiesBtn, '<i class="bi bi-download"></i> Extrahera från ZAP');
        });
    }
    
    /**
     * Debug-funktion för cookie-extraktion
     */
    function debugCookieExtraction() {
        const debugBtn = document.getElementById('debug-cookies-btn');
        if (debugBtn) {
            debugBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Analyserar...';
            debugBtn.disabled = true;
        }
        
        fetch('/api/access-control/debug-cookies')
        .then(response => response.json())
        .then(data => {
            // Skapa debug-modal
            const modalHtml = `
                <div class="modal fade" id="debugModal" tabindex="-1">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Cookie-extraktion Debug Information</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <h6>ZAP Status</h6>
                                <p><strong>Tillgänglig:</strong> ${data.zap_available ? '✅ Ja' : '❌ Nej'}</p>
                                
                                <h6>Session Data</h6>
                                <p><strong>Har target_url:</strong> ${data.session_data.has_target_url ? '✅ Ja' : '❌ Nej'}</p>
                                <p><strong>Target URL:</strong> <code>${data.session_data.target_url}</code></p>
                                <p><strong>Session-nycklar:</strong> ${data.session_data.all_keys.join(', ')}</p>
                                
                                <h6>ZAP Sites</h6>
                                ${data.zap_sites.length > 0 ? 
                                    `<ul>${data.zap_sites.map(site => `<li><code>${site}</code></li>`).join('')}</ul>` : 
                                    '<p>Inga sites hittades i ZAP</p>'
                                }
                                
                                <h6>Target URL Källor</h6>
                                <ul>
                                    <li><strong>Session:</strong> ${data.target_url_sources.session || 'Ingen'}</li>
                                    <li><strong>Query parameter:</strong> ${data.target_url_sources.query_param || 'Ingen'}</li>
                                    <li><strong>Första ZAP site:</strong> ${data.target_url_sources.first_zap_site || 'Ingen'}</li>
                                </ul>
                                
                                ${data.cookie_test ? `
                                    <h6>Cookie Test</h6>
                                    <p><strong>Framgång:</strong> ${data.cookie_test.success ? '✅ Ja' : '❌ Nej'}</p>
                                    ${data.cookie_test.success ? 
                                        `<p><strong>Cookies längd:</strong> ${data.cookie_test.cookies_length} tecken</p>
                                        <p><strong>Preview:</strong> <code>${data.cookie_test.cookies_preview}</code></p>` :
                                        `<p><strong>Fel:</strong> ${data.cookie_test.error}</p>`
                                    }
                                ` : ''}
                                
                                ${data.error ? `<div class="alert alert-danger mt-3">Fel: ${data.error}</div>` : ''}
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Stäng</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Ta bort befintlig modal om den finns
            const existingModal = document.getElementById('debugModal');
            if (existingModal) {
                existingModal.remove();
            }
            
            // Lägg till ny modal
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            // Visa modal
            const modal = new bootstrap.Modal(document.getElementById('debugModal'));
            modal.show();
            
            // Rensa modal när den stängs
            document.getElementById('debugModal').addEventListener('hidden.bs.modal', function() {
                this.remove();
            });
        })
        .catch(error => {
            console.error('Error getting debug info:', error);
            alert('Kunde inte hämta debug-information: ' + error.message);
        })
        .finally(() => {
            if (debugBtn) {
                debugBtn.innerHTML = 'Debug cookie-extraktion';
                debugBtn.disabled = false;
            }
        });
    }

    /**
     * Starta Access Control Test
     */
    function startAccessControlTest() {
        const sourceSessionFile = sourceSessionSelect.value;
        const testLabel = testLabelInput.value.trim();
        const testCookies = testCookiesInput.value.trim();
        
        // Validering
        if (!sourceSessionFile) {
            showError(testStatus, 'Välj en käll-session att testa');
            sourceSessionSelect.focus();
            return;
        }
        
        if (!testLabel) {
            showError(testStatus, 'Test-etikett krävs');
            testLabelInput.focus();
            return;
        }
        
        setButtonLoading(startTestBtn, 'Kör test...');
        testStatus.innerHTML = '';
        
        // Visa testflöde
        showTestProgress();
        
        fetch('/api/access-control/test', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            },
            body: JSON.stringify({
                source_session_file: sourceSessionFile,
                test_cookies: testCookies,
                test_label: testLabel
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayTestResult(data);
                loadTestResults();
            } else {
                showError(testStatus, data.error);
            }
        })
        .catch(error => {
            console.error('Error starting test:', error);
            showError(testStatus, `Nätverksfel: ${error.message}`);
        })
        .finally(() => {
            resetButtonLoading(startTestBtn, '<i class="bi bi-shield-exclamation"></i> Starta Access Control Test');
        });
    }
    
    /**
     * Visa testresultat med förbättrad styling
     */
    function displayTestResult(data) {
        let alertClass = 'alert-success';
        let icon = 'bi-check-circle-fill';
        let riskClass = 'low';
        
        // Bestäm stil baserat på resultat
        if (data.analysis && data.analysis.by_risk_level) {
            const criticalCount = data.analysis.by_risk_level.CRITICAL || 0;
            const highCount = data.analysis.by_risk_level.HIGH || 0;
            
            if (criticalCount > 0) {
                alertClass = 'alert-danger';
                icon = 'bi-exclamation-triangle-fill';
                riskClass = 'critical';
            } else if (highCount > 0) {
                alertClass = 'alert-warning';
                icon = 'bi-exclamation-circle-fill';
                riskClass = 'high';
            }
        }
        
        let html = `
            <div class="alert ${alertClass} test-result-card">
                <div class="d-flex align-items-start">
                    <div class="risk-indicator ${riskClass} mt-1"></div>
                    <div class="flex-grow-1">
                        <div class="d-flex justify-content-between align-items-start">
                            <h5 class="alert-heading mb-2">
                                <i class="${icon}"></i> Test slutfört!
                            </h5>
                            <span class="badge bg-light text-dark">${data.total_tested} URL:er testade</span>
                        </div>
                        <p class="mb-2"><strong>${data.analysis ? data.analysis.summary : 'Test slutfört'}</strong></p>
                        <small class="text-muted">Resultat sparade i: ${data.test_filename}</small>
        `;
        
        // Visa risk-fördelning
        if (data.analysis && data.analysis.by_risk_level) {
            html += '<div class="mt-3"><strong>Risk-fördelning:</strong><br>';
            for (const [risk, count] of Object.entries(data.analysis.by_risk_level)) {
                if (count > 0) {
                    const badgeClass = getRiskBadgeClass(risk);
                    html += `<span class="badge ${badgeClass} me-1">${risk}: ${count}</span>`;
                }
            }
            html += '</div>';
        }
        
        // Visa kritiska fynd
        if (data.high_risk_findings && data.high_risk_findings.length > 0) {
            html += '<div class="mt-3"><strong>Kritiska fynd:</strong><ul class="mb-0">';
            data.high_risk_findings.slice(0, 3).forEach(finding => {
                html += `<li><code>${truncateUrl(finding.url, 50)}</code> - ${finding.description}</li>`;
            });
            if (data.high_risk_findings.length > 3) {
                html += `<li class="text-muted">...och ${data.high_risk_findings.length - 3} till</li>`;
            }
            html += '</ul></div>';
        }
        
        html += '</div></div></div>';
        testStatus.innerHTML = html;
    }
    
    /**
     * Visa testframsteg
     */
    function showTestProgress() {
        const progressHtml = `
            <div class="test-progress mb-3">
                <div class="progress">
                    <div class="progress-bar test-running" role="progressbar" style="width: 100%">
                        <span class="spinner-border spinner-border-sm me-2"></span>Testar URL:er...
                    </div>
                </div>
            </div>
        `;
        testStatus.innerHTML = progressHtml;
    }
    
    /**
     * Ladda testresultat
     */
    function loadTestResults() {
        if (!testResults) return;
        
        testResults.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm" role="status"></div> Laddar testresultat...</div>';
        
        fetch('/api/access-control/test-results')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayTestResults(data.tests);
            } else {
                testResults.innerHTML = `<div class="alert alert-danger">Fel: ${data.error}</div>`;
            }
        })
        .catch(error => {
            console.error('Error loading test results:', error);
            testResults.innerHTML = `<div class="alert alert-danger">Nätverksfel: ${error.message}</div>`;
        });
    }
    
    /**
     * Visa testresultat med förbättrad styling
     */
    function displayTestResults(tests) {
        if (tests.length === 0) {
            testResults.innerHTML = `
                <div class="alert alert-info">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-info-circle me-2"></i>
                        <span>Inga testresultat ännu.</span>
                    </div>
                </div>
            `;
            return;
        }
        
        let html = '';
        
        // Visa bara de 5 senaste testerna här
        const recentTests = tests.slice(0, 5);
        
        recentTests.forEach(test => {
            const date = new Date(test.test_time * 1000);
            const relativeTime = getRelativeTime(date);
            
            // Bestäm övergripande risk-status
            let cardClass = 'border-success';
            let riskClass = 'low';
            let statusIcon = 'bi-shield-check';
            
            if (test.risk_counts.CRITICAL > 0) {
                cardClass = 'border-danger';
                riskClass = 'critical';
                statusIcon = 'bi-shield-exclamation';
            } else if (test.risk_counts.HIGH > 0) {
                cardClass = 'border-warning';
                riskClass = 'high';
                statusIcon = 'bi-shield-x';
            } else if (test.risk_counts.MEDIUM > 0) {
                cardClass = 'border-info';
                riskClass = 'medium';
                statusIcon = 'bi-shield-minus';
            }
            
            html += `
                <div class="card mb-3 test-result-card ${cardClass}">
                    <div class="card-body">
                        <div class="d-flex align-items-center justify-content-between">
                            <div class="d-flex align-items-center">
                                <div class="risk-indicator ${riskClass} me-2"></div>
                                <div>
                                    <h6 class="mb-1">
                                        <span class="badge bg-info">${escapeHtml(test.source_session_label)}</span>
                                        <i class="bi bi-arrow-right mx-1"></i>
                                        <span class="badge bg-secondary">${escapeHtml(test.test_label)}</span>
                                    </h6>
                                    <small class="text-muted">${test.total_tested} URL:er testade • ${relativeTime}</small>
                                </div>
                            </div>
                            <i class="${statusIcon}" style="font-size: 1.5rem;"></i>
                        </div>
            `;
            
            // Visa risk-badges
            if (test.risk_counts && Object.keys(test.risk_counts).length > 0) {
                html += '<div class="mt-2">';
                for (const [risk, count] of Object.entries(test.risk_counts)) {
                    if (count > 0) {
                        const badgeClass = getRiskBadgeClass(risk);
                        html += `<span class="badge ${badgeClass} me-1">${risk}: ${count}</span>`;
                    }
                }
                html += '</div>';
            }
            
            html += '</div></div>';
        });
        
        testResults.innerHTML = html;
    }
    
    // === Hjälpfunktioner ===
    
    function setButtonLoading(button, text) {
        button.disabled = true;
        button.innerHTML = `<span class="spinner-border spinner-border-sm" role="status"></span> ${text}`;
    }
    
    function resetButtonLoading(button, originalHtml) {
        button.disabled = false;
        button.innerHTML = originalHtml;
    }
    
    function showError(element, message, title = 'Fel', timeout = 0) {
        const html = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-circle"></i> <strong>${title}:</strong> ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        element.innerHTML = html;
        
        if (timeout > 0) {
            setTimeout(() => {
                const alert = element.querySelector('.alert');
                if (alert) {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }
            }, timeout);
        }
    }
    
    function showSuccess(element, message, title = 'Framgång', timeout = 0) {
        const html = `
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle"></i> <strong>${title}:</strong> ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        element.innerHTML = html;
        
        if (timeout > 0) {
            setTimeout(() => {
                const alert = element.querySelector('.alert');
                if (alert) {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }
            }, timeout);
        }
    }
    
    function getCSRFToken() {
        return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    function truncateUrl(url, maxLength) {
        if (url.length <= maxLength) return url;
        return url.substring(0, maxLength - 3) + '...';
    }
    
    function getRelativeTime(date) {
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Just nu';
        if (diffMins < 60) return `${diffMins} min sedan`;
        if (diffHours < 24) return `${diffHours} tim sedan`;
        if (diffDays < 7) return `${diffDays} dag${diffDays > 1 ? 'ar' : ''} sedan`;
        return date.toLocaleDateString();
    }
    
    function getCategoryClass(category) {
        const categoryClasses = {
            'admin': 'bg-danger',
            'user_data': 'bg-warning',
            'api': 'bg-info',
            'file_operations': 'bg-primary',
            'authentication': 'bg-success',
            'reports': 'bg-secondary',
            'other': 'bg-light text-dark'
        };
        return categoryClasses[category] || 'bg-light text-dark';
    }
    
    function getSessionClass(sessionLabel) {
        const label = sessionLabel.toLowerCase();
        if (label.includes('admin') || label.includes('root')) return 'critical';
        if (label.includes('manager') || label.includes('supervisor')) return 'high';
        if (label.includes('user') || label.includes('member')) return 'medium';
        return 'low';
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