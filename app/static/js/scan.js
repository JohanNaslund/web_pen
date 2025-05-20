/**
 * JavaScript för scanningssidan
 */
document.addEventListener('DOMContentLoaded', function() {
    // Referens till knappar och status-element
    const startSpiderBtn = document.getElementById('start-spider-btn');
    const startActiveScanBtn = document.getElementById('start-active-scan-btn');
    const startSqlmapBtn = document.getElementById('start-sqlmap-btn');
    const viewReportBtn = document.getElementById('view-report-btn');
    
    const spiderStatusElem = document.getElementById('spider-status');
    const activeScanStatusElem = document.getElementById('active-scan-status');
    const sqlmapStatusElem = document.getElementById('sqlmap-status');
    const totalStatusBadge = document.getElementById('total-status-badge');
    
    const spiderProgressContainer = document.getElementById('spider-progress-container');
    const spiderProgressBar = document.getElementById('spider-progress');
    const activeScanProgressContainer = document.getElementById('active-scan-progress-container');
    const activeScanProgressBar = document.getElementById('active-scan-progress');
    
    const zapAlertsCount = document.getElementById('zap-alerts-count');
    const sqlmapFindingsCount = document.getElementById('sqlmap-findings-count');
    
    if (!startSpiderBtn) return; // Kontrollera om vi är på rätt sida
    
    // Session-select hantering för SQLMap
    const sessionSelect = document.getElementById('session_select');
    const sqlmapSessionNameInput = document.getElementById('sqlmap_session_name');
    
    if (sessionSelect) {
        sessionSelect.addEventListener('change', function() {
            sqlmapSessionNameInput.value = this.value;
        });
    }
    
    // Statuspolling-variabel
    let statusPollInterval = null;
    
    // I app/static/js/scan.js
    function updateStatus() {
        APP.fetch(APP.API.SCAN_STATUS)
            .then(response => {
                // Kontrollera om svaret är giltigt JSON
                if (typeof response === 'object') {
                    updateSpiderStatus(response.spider);
                    updateActiveScanStatus(response.active_scan);
                    updateSqlmapStatus(response.sqlmap);
                    updateTotalStatus(response);
                } else {
                    console.error('Invalid response format:', response);
                    APP.showToast('Ogiltigt svarsformat från servern', 'warning');
                }
            })
            .catch(error => {
                console.error('Error fetching status:', error);
                APP.showToast('Kunde inte uppdatera status: ' + error.message, 'warning');
            });
    }
    
    // Uppdatera Spider status
    function updateSpiderStatus(status) {
        if (!status) return;
        
        const spiderPercent = parseInt(status.status);
        
        // Only show progress bar if we've started the spider
        if (spiderPercent > 0 || status.running === true) {
            spiderProgressContainer.classList.remove('d-none');
            spiderProgressBar.style.width = spiderPercent + '%';
            spiderProgressBar.textContent = spiderPercent + '%';
            
            // Only mark as complete if we explicitly started this scan AND it's at 100%
            if (spiderPercent >= 100 && session.hasOwnProperty('spider_scan_id')) {
                startActiveScanBtn.disabled = false;
                window.spiderComplete = true;
                startSpiderBtn.classList.remove('btn-primary');
                startSpiderBtn.classList.add('btn-success');
                startSpiderBtn.innerHTML = 'Spider Klar <i class="bi bi-check-circle"></i>';
                spiderStatusElem.innerHTML = `Status: <span class="badge bg-success">Slutförd</span>`;
            } else if (spiderPercent < 100) {
                spiderStatusElem.innerHTML = `Status: <span class="badge bg-info">Pågår (${spiderPercent}%)</span>`;
            }
        }
    }

    function updateActiveScanStatus(status) {
        if (!status) return;
        
        const scanPercent = parseInt(status.status);
        
        // Only show progress bar if we've started the active scan
        if (scanPercent > 0 || status.running === true) {
            activeScanProgressContainer.classList.remove('d-none');
            activeScanProgressBar.style.width = scanPercent + '%';
            activeScanProgressBar.textContent = scanPercent + '%';
            
            // Uppdatera status text and badge
            const isCompleted = scanPercent >= 100 && session.hasOwnProperty('active_scan_id');
            
            if (isCompleted) {
                activeScanStatusElem.innerHTML = `Status: <span class="badge bg-success">Slutförd</span>`;
                // Mark as completed only if we explicitly started this scan
                if (!activeScanStatusElem.hasAttribute('data-completed')) {
                    activeScanStatusElem.setAttribute('data-completed', 'true');
                    console.log("Aktiv scanning är nu slutförd med " + (status.alerts || 0) + " alerts.");
                    
                    // Set flag for active scanning complete
                    window.activeScanComplete = true;
                    
                    // Mark button as completed
                    startActiveScanBtn.classList.remove('btn-primary');
                    startActiveScanBtn.classList.add('btn-success');
                    startActiveScanBtn.innerHTML = 'Aktiv Scanning Klar <i class="bi bi-check-circle"></i>';
                }
            } else {
                activeScanStatusElem.innerHTML = `Status: <span class="badge bg-info">Pågår (${scanPercent}%)</span>`;
            }
            
            // Update alerts count if available
            if (status.alerts !== undefined && zapAlertsCount) {
                zapAlertsCount.textContent = status.alerts || 0;
            }
        }
    }

    // Update Ajax Spider status
    function updateAjaxSpiderStatus(status) {
        if (!status) return;
        
        // Check if Ajax Spider is running or has results
        const isRunning = status.running === true;
        const hasResults = (status.urls_found > 0 || status.numberOfResults > 0);
        
        if (isRunning || hasResults || status.status === 'stopped') {
            ajaxSpiderProgressContainer.classList.remove('d-none');
            
            // If running, show animated progress bar
            if (isRunning) {
                ajaxSpiderProgressBar.style.width = '100%';
                ajaxSpiderProgressBar.classList.add('progress-bar-striped', 'progress-bar-animated');
                ajaxSpiderStatusElem.innerHTML = `Status: <span class="badge bg-info">Pågår</span>`;
                
                if (startAjaxSpiderBtn) {
                    startAjaxSpiderBtn.disabled = true;
                    startAjaxSpiderBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Kör...';
                }
            } 
            // If stopped or completed and we explicitly started this scan
            else if ((status.status === 'stopped' || status.status === '') && session.hasOwnProperty('ajax_spider_running')) {
                ajaxSpiderProgressBar.style.width = '100%';
                ajaxSpiderProgressBar.classList.remove('progress-bar-striped', 'progress-bar-animated');
                
                const resourcesFound = status.urls_found || status.numberOfResults || 0;
                ajaxSpiderStatusElem.innerHTML = `Status: <span class="badge bg-success">Slutförd</span> (${resourcesFound} URLs)`;
                
                if (startAjaxSpiderBtn) {
                    startAjaxSpiderBtn.disabled = false;
                    startAjaxSpiderBtn.classList.remove('btn-primary');
                    startAjaxSpiderBtn.classList.add('btn-success');
                    startAjaxSpiderBtn.innerHTML = 'Ajax Spider Klar <i class="bi bi-check-circle"></i>';
                }
                
                // Update number of URLs found in results section
                if (ajaxUrlsCount) {
                    ajaxUrlsCount.textContent = resourcesFound;
                }
                
                // Set flag for Ajax Spider completion
                window.ajaxSpiderComplete = true;
            } else {
                // If we have a status but didn't explicitly start this scan
                ajaxSpiderStatusElem.innerHTML = `Status: <span class="badge bg-secondary">${status.status || 'Inte startad'}</span>`;
            }
        }
    }    
    // Uppdatera total status
    function updateTotalStatus(data) {
        let isSpiderDone = false;
        let isActiveScanDone = false;
        let isSqlmapDone = false;
        
        if (data.spider && parseInt(data.spider.status) >= 100) {
            isSpiderDone = true;
        }
        
        if (data.active_scan && parseInt(data.active_scan.status) >= 100) {
            isActiveScanDone = true;
        }
        
        if (data.sqlmap && data.sqlmap.status && data.sqlmap.status.status === 'terminated') {
            isSqlmapDone = true;
        }
        
        if (isSpiderDone && isActiveScanDone && isSqlmapDone) {
            totalStatusBadge.className = 'badge bg-success';
            totalStatusBadge.textContent = 'Slutförd';
            viewReportBtn.disabled = false;
            
            if (totalStatusBadge.getAttribute('data-notified') !== 'true') {
                APP.showToast('Alla scanningar slutförda! Du kan nu se den fullständiga rapporten.', 'success');
                totalStatusBadge.setAttribute('data-notified', 'true');
            }
        } else if (isSpiderDone || isActiveScanDone || isSqlmapDone) {
            totalStatusBadge.className = 'badge bg-info';
            totalStatusBadge.textContent = 'Delvis slutförd';
        }
    }
    
    // Starta polling vid sidladdning
    statusPollInterval = setInterval(updateStatus, APP.STATUS_POLL_INTERVAL);
    
    // Initial uppdatering
    updateStatus();
    
    // Rensa intervall vid sidavslut
    window.addEventListener('beforeunload', function() {
        if (statusPollInterval) {
            clearInterval(statusPollInterval);
        }
    });
});