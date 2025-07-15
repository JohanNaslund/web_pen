/**
 * JavaScript för rapport-sidan
 */

// ====================================================
// GLOBALA VARIABLER
// ====================================================
let currentAlertData = null;

// ====================================================
// GLOBALA FUNKTIONER (måste vara tillgängliga för onclick)
// ====================================================

/**
 * Visa detaljerad information för en specifik sårbarhet
 */
function showAlertDetails(alertId) {
    console.log('showAlertDetails called with ID:', alertId);
    
    // Visa loading i modal
    showModalLoading();
    
    // Hämta detaljerad information från API
    fetch(`/api/alert-details/${alertId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Alert details response:', data);
            
            if (data.error) {
                showModalError(data.error);
                return;
            }
            
            // Extrahera alert-objektet från response
            const alertDetail = data.alert || data;
            populateAlertModal(alertDetail);
            
        })
        .catch(error => {
            console.error('Error fetching alert details:', error);
            showModalError('Kunde inte hämta sårbarhetsdetaljer: ' + error.message);
        });
}

/**
 * Visa modal i loading-läge
 */
function showModalLoading() {
    const modal = document.getElementById('alertDetailsModal');
    const modalTitle = document.getElementById('alertDetailsTitle');
    const modalBody = modal.querySelector('.modal-body');
    
    modalTitle.textContent = 'Laddar sårbarhetsdetaljer...';
    
    // Dölj allt innehåll och visa loading
    modalBody.style.position = 'relative';
    modalBody.style.minHeight = '300px';
    
    // Lägg till loading overlay
    const loadingOverlay = document.createElement('div');
    loadingOverlay.id = 'loading-overlay';
    loadingOverlay.style.cssText = `
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(255, 255, 255, 0.9);
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        z-index: 1000;
    `;
    loadingOverlay.innerHTML = `
        <div class="spinner-border text-primary" role="status">
            <span class="visually-hidden">Laddar...</span>
        </div>
        <p class="mt-2">Hämtar detaljerad information...</p>
    `;
    
    // Ta bort befintlig loading overlay om den finns
    const existingOverlay = modalBody.querySelector('#loading-overlay');
    if (existingOverlay) {
        existingOverlay.remove();
    }
    
    // Lägg till loading overlay
    modalBody.appendChild(loadingOverlay);
    
    // Visa modal
    const modalInstance = new bootstrap.Modal(modal);
    modalInstance.show();
}

/**
 * Visa error i modal
 */
function showModalError(errorMessage) {
    const modal = document.getElementById('alertDetailsModal');
    const modalTitle = document.getElementById('alertDetailsTitle');
    const modalBody = modal.querySelector('.modal-body');
    
    // Ta bort loading overlay
    const loadingOverlay = modalBody ? modalBody.querySelector('#loading-overlay') : null;
    if (loadingOverlay) {
        loadingOverlay.remove();
    }
    
    modalTitle.textContent = 'Fel vid hämtning av detaljer';
    
    // Lägg till error overlay
    const errorOverlay = document.createElement('div');
    errorOverlay.style.cssText = `
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(255, 255, 255, 0.95);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 1000;
    `;
    errorOverlay.innerHTML = `
        <div class="alert alert-danger">
            <i class="bi bi-exclamation-triangle-fill"></i>
            <strong>Fel:</strong> ${errorMessage}
        </div>
    `;
    
    modalBody.appendChild(errorOverlay);
    
    // Visa modal om den inte redan är synlig
    if (!modal.classList.contains('show')) {
        const modalInstance = new bootstrap.Modal(modal);
        modalInstance.show();
    }
}

/**
 * Fyll i modal med alert-data
 */
function populateAlertModal(alertData) {
    console.log('Populating modal with data:', alertData);
    
    // Ta bort loading overlay
    const modalBody = document.querySelector('#alertDetailsModal .modal-body');
    const loadingOverlay = modalBody ? modalBody.querySelector('#loading-overlay') : null;
    if (loadingOverlay) {
        loadingOverlay.remove();
    }
    
    // Spara current alert data för export
    currentAlertData = alertData;
    
    // Uppdatera modal titel
    const modalTitle = document.getElementById('alertDetailsTitle');
    if (modalTitle) {
        modalTitle.textContent = alertData.name || 'Sårbarhetsdetaljer';
    }
    
    // Uppdatera alla fält
    updateModalField('alert-description', alertData.description || 'Ingen beskrivning tillgänglig');
    updateModalField('alert-risk', alertData.risk || 'Okänd', getRiskBadgeClass(alertData.risk));
    updateModalField('alert-confidence', alertData.confidence || 'Okänd', getConfidenceBadgeClass(alertData.confidence));
    updateModalField('alert-url', alertData.url || 'Ingen URL tillgänglig', 'code-style');
    updateModalField('alert-parameter', alertData.param || alertData.parameter || 'Ingen parameter');
    updateModalField('alert-attack', alertData.attack || 'Ingen attack-information');
    updateModalField('alert-solution', alertData.solution || 'Inga åtgärdsförslag tillgängliga');
    
    // Hantera referenser
    const references = alertData.reference || alertData.references || '';
    updateModalField('alert-references', formatReferences(references));
    
    // Uppdatera CWE och WASC
    updateModalField('alert-cwe', formatCWE(alertData.cweid || alertData.cwe));
    updateModalField('alert-wasc', formatWASC(alertData.wascid || alertData.wasc));
    
    // Hantera taggar
    const tags = alertData.tags || {};
    updateModalField('alert-tags', formatTags(tags));
    
    // Teknisk information för accordion
    updateModalField('alert-id', alertData.id || 'Inte tillgänglig');
    updateModalField('alert-plugin-id', alertData.pluginId || alertData.plugin_id || 'Inte tillgänglig');
    updateModalField('alert-method', alertData.method || 'Inte tillgänglig');
    updateModalField('alert-input-vector', alertData.inputVector || 'Inte tillgänglig');
    
    // Evidence (om tillgängligt)
    if (alertData.evidence) {
        const evidenceSection = document.getElementById('evidence-section');
        if (evidenceSection) {
            evidenceSection.style.display = 'block';
            updateModalField('alert-evidence', alertData.evidence);
        }
    } else {
        const evidenceSection = document.getElementById('evidence-section');
        if (evidenceSection) {
            evidenceSection.style.display = 'none';
        }
    }
    
    // Request/Response information
    updateModalField('alert-request-response', formatRequestResponse(alertData));
    
    // Andra URLs som påverkas
    updateModalField('alert-other-urls', formatOtherUrls(alertData.otherInfo || alertData.other_urls));
    
    // Modal är redan synlig från loading, ingen showModal() behövs
}

/**
 * Visa modal
 */
function showModal() {
    const modal = document.getElementById('alertDetailsModal');
    if (modal) {
        const modalInstance = new bootstrap.Modal(modal);
        modalInstance.show();
    }
}

/**
 * Uppdatera ett fält i modal
 */
function updateModalField(fieldId, content, styleClass = '') {
    const element = document.getElementById(fieldId);
    if (element) {
        // Behåll befintliga klasser men rensa innehåll
        if (styleClass === 'code-style') {
            element.innerHTML = `<code class="text-break">${escapeHtml(content)}</code>`;
        } else if (styleClass.startsWith('bg-')) {
            element.innerHTML = `<span class="badge ${styleClass}">${escapeHtml(content)}</span>`;
        } else {
            element.innerHTML = formatContent(content);
        }
    } else {
        console.warn(`Element with ID '${fieldId}' not found`);
    }
}

/**
 * Kopiera alert-detaljer till clipboard
 */
function copyAlertDetails() {
    const alertData = currentAlertData;
    if (!alertData) {
        alert('Ingen alert-data tillgänglig för kopiering');
        return;
    }
    
    const textContent = `
SÅRBARHETSDETALJER
==================

Namn: ${alertData.name || 'N/A'}
Risk: ${alertData.risk || 'N/A'}
Konfidensgrad: ${alertData.confidence || 'N/A'}
URL: ${alertData.url || 'N/A'}
Parameter: ${alertData.param || alertData.parameter || 'N/A'}

BESKRIVNING:
${alertData.description || 'Ingen beskrivning tillgänglig'}

ÅTGÄRDSFÖRSLAG:
${alertData.solution || 'Inga åtgärdsförslag tillgängliga'}

ATTACK:
${alertData.attack || 'Ingen attack-information'}

TEKNISK INFORMATION:
- CWE: ${alertData.cweid || alertData.cwe || 'N/A'}
- WASC: ${alertData.wascid || alertData.wasc || 'N/A'}
- Alert ID: ${alertData.id || 'N/A'}
- Plugin ID: ${alertData.pluginId || alertData.plugin_id || 'N/A'}

REFERENSER:
${alertData.reference || alertData.references || 'Inga referenser tillgängliga'}

Genererad: ${new Date().toLocaleString('sv-SE')}
`;
    
    // Förbättrad clipboard-hantering
    if (navigator.clipboard && navigator.clipboard.writeText) {
        // Modern Clipboard API
        navigator.clipboard.writeText(textContent).then(() => {
            showTemporaryMessage('Sårbarhetsdetaljer kopierade till clipboard!', 'success');
        }).catch(err => {
            console.error('Kunde inte kopiera med Clipboard API: ', err);
            fallbackCopyText(textContent);
        });
    } else {
        // Fallback för äldre webbläsare
        fallbackCopyText(textContent);
    }
}

/**
 * Fallback-metod för att kopiera text
 */
function fallbackCopyText(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showTemporaryMessage('Sårbarhetsdetaljer kopierade till clipboard!', 'success');
        } else {
            showTemporaryMessage('Kunde inte kopiera till clipboard', 'error');
        }
    } catch (err) {
        console.error('Fallback copy failed: ', err);
        showTemporaryMessage('Kunde inte kopiera till clipboard', 'error');
    }
    
    document.body.removeChild(textArea);
}

/**
 * Exportera alert-detaljer som JSON
 */
function exportAlertDetails() {
    const alertData = currentAlertData;
    if (!alertData) {
        alert('Ingen alert-data tillgänglig för export');
        return;
    }
    
    const exportData = {
        ...alertData,
        exportedAt: new Date().toISOString(),
        exportedBy: 'Web PEN Testing Tool'
    };
    
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = `alert_${alertData.id || 'unknown'}_${new Date().toISOString().split('T')[0]}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
    
    showTemporaryMessage('Alert-detaljer exporterade!', 'success');
}

// ====================================================
// HJÄLPFUNKTIONER
// ====================================================

function formatContent(content) {
    // Om innehållet redan innehåller HTML-taggar, behåll dem
    if (content.includes('<a ') || content.includes('<span ') || content.includes('<em ')) {
        return content; // Returnera HTML som det är
    }
    // Annars, escape HTML och konvertera newlines
    const escaped = escapeHtml(content);
    return escaped.replace(/\n/g, '<br>');
}

function formatCWE(cweId) {
    if (!cweId || cweId === 'N/A') {
        return '<em class="text-muted">Inte tillgänglig</em>';
    }
    
    const cweNumber = cweId.toString().replace(/[^0-9]/g, '');
    if (cweNumber) {
        return `<a href="https://cwe.mitre.org/data/definitions/${cweNumber}.html" target="_blank" class="text-decoration-none">
            CWE-${cweNumber} <i class="bi bi-box-arrow-up-right"></i>
        </a>`;
    }
    
    return escapeHtml(cweId); // Endast escape om det inte är ett nummer
}

function formatWASC(wascId) {
    if (!wascId || wascId === 'N/A') {
        return '<em class="text-muted">Inte tillgänglig</em>';
    }
    
    const wascNumber = wascId.toString().replace(/[^0-9]/g, '');
    if (wascNumber) {
        return `<a href="http://projects.webappsec.org/w/page/13246978/Threat%20Classification%20Reference%20Grid" target="_blank" class="text-decoration-none">
            WASC-${wascNumber} <i class="bi bi-box-arrow-up-right"></i>
        </a>`;
    }
    
    return escapeHtml(wascId); // Endast escape om det inte är ett nummer
}

function formatReferences(references) {
    if (!references || references === 'N/A') {
        return '<em class="text-muted">Inga referenser tillgängliga</em>';
    }
    
    const lines = references.split('\n').filter(line => line.trim());
    const formattedLines = lines.map(line => {
        const trimmed = line.trim();
        if (trimmed.startsWith('http')) {
            // Skapa länk utan att escape:a HTML
            return `<a href="${trimmed}" target="_blank" class="text-decoration-none">${trimmed} <i class="bi bi-box-arrow-up-right"></i></a>`;
        } else {
            // Escape endast text som inte är länkar
            return escapeHtml(trimmed);
        }
    });
    
    return formattedLines.join('<br>');
}

function formatTags(tags) {
    if (!tags || Object.keys(tags).length === 0) {
        return '<em class="text-muted">Inga taggar tillgängliga</em>';
    }
    
    const tagBadges = Object.entries(tags)
        .map(([key, value]) => {
            // Kontrollera om värdet är en URL
            if (typeof value === 'string' && value.startsWith('http')) {
                return `<span class="badge bg-secondary me-1">${escapeHtml(key)}: <a href="${value}" target="_blank" class="text-white text-decoration-none">${value} <i class="bi bi-box-arrow-up-right"></i></a></span>`;
            } else {
                return `<span class="badge bg-secondary me-1">${escapeHtml(key)}: ${escapeHtml(value)}</span>`;
            }
        })
        .join(' ');
    
    return tagBadges;
}

function formatRequestResponse(alertData) {
    let html = '';
    
    if (alertData.messageId) {
        html += `<div class="mb-2"><strong>Message ID:</strong> ${alertData.messageId}</div>`;
    }
    
    if (alertData.requestMethod) {
        html += `<div class="mb-2"><strong>Request Method:</strong> <code>${alertData.requestMethod}</code></div>`;
    }
    
    if (alertData.requestUri) {
        html += `<div class="mb-2"><strong>Request URI:</strong> <code class="text-break">${escapeHtml(alertData.requestUri)}</code></div>`;
    }
    
    if (alertData.responseStatusCode) {
        html += `<div class="mb-2"><strong>Response Status:</strong> <code>${alertData.responseStatusCode}</code></div>`;
    }
    
    if (!html) {
        html = '<em class="text-muted">Ingen request/response information tillgänglig</em>';
    }
    
    return html;
}

function formatOtherUrls(otherUrls) {
    if (!otherUrls || otherUrls.length === 0) {
        return '<em class="text-muted">Inga andra URLs påverkade</em>';
    }
    
    if (typeof otherUrls === 'string') {
        otherUrls = otherUrls.split('\n').filter(url => url.trim());
    }
    
    if (Array.isArray(otherUrls)) {
        const urlList = otherUrls.map(url => `<div class="mb-1"><code class="text-break">${escapeHtml(url)}</code></div>`).join('');
        return urlList;
    }
    
    return '<em class="text-muted">Kunde inte formatera URL-information</em>';
}

function getRiskBadgeClass(risk) {
    switch (risk?.toLowerCase()) {
        case 'high':
            return 'bg-danger text-white';
        case 'medium':
            return 'bg-warning text-dark';
        case 'low':
            return 'bg-info text-white';
        case 'informational':
            return 'bg-secondary text-white';
        default:
            return 'bg-secondary text-white';
    }
}

function getConfidenceBadgeClass(confidence) {
    switch (confidence?.toLowerCase()) {
        case 'high':
            return 'bg-success text-white';
        case 'medium':
            return 'bg-warning text-dark';
        case 'low':
            return 'bg-light text-dark';
        default:
            return 'bg-secondary text-white';
    }
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    
    return String(text).replace(/[&<>"']/g, function(m) { return map[m]; });
}

function showTemporaryMessage(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type === 'success' ? 'success' : 'info'} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
    alertDiv.innerHTML = `
        <i class="bi bi-${type === 'error' ? 'exclamation-triangle' : type === 'success' ? 'check-circle' : 'info-circle'}-fill"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 3000);
}

// ====================================================
// DOMContentLoaded EVENT HANDLER
// ====================================================

document.addEventListener('DOMContentLoaded', function() {
    
    // ====================================================
    // LOKALA FUNKTIONER (för att hantera data hämtning)
    // ====================================================
    
    function fetchVulnerabilities() {
        console.log('Fetching vulnerabilities...');
        fetch('/api/zap-alerts-by-risk')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error('API error:', data.error);
                    updateCounts(0, 0, 0, 0);
                    showErrorInRecommendations('Error loading vulnerabilities: ' + data.error);
                    return;
                }
                
                console.log('Vulnerabilities fetched successfully');
                updateCounts(data);
                generateRecommendations(data);
                populateVulnerabilityAccordions(data);
                hideLoadingMessage();
            })
            .catch(error => {
                console.error('Error fetching vulnerabilities:', error);
                updateCounts(0, 0, 0, 0);
                showErrorInRecommendations('Error loading vulnerabilities. Please try again.');
                hideLoadingMessage();
            });
    }
    
    function updateCounts(data) {
        const alertsByRisk = data.alerts_by_risk || {};
        
        const highCount = alertsByRisk.highAlerts ? alertsByRisk.highAlerts.length : 0;
        const mediumCount = alertsByRisk.mediumAlerts ? alertsByRisk.mediumAlerts.length : 0;
        const lowCount = alertsByRisk.lowAlerts ? alertsByRisk.lowAlerts.length : 0;
        const infoCount = alertsByRisk.infoAlerts ? alertsByRisk.infoAlerts.length : 0;
        
        safeUpdateElement('high-risk-count', highCount);
        safeUpdateElement('medium-risk-count', mediumCount);
        safeUpdateElement('low-risk-count', lowCount);
        safeUpdateElement('info-risk-count', infoCount);
        
        safeUpdateElement('high-risk-badge', highCount);
        safeUpdateElement('medium-risk-badge', mediumCount);
        safeUpdateElement('low-risk-badge', lowCount);
        safeUpdateElement('info-risk-badge', infoCount);
    }
    
    function populateVulnerabilityAccordions(data) {
        const alertsByRisk = data.alerts_by_risk || {};
        
        populateRiskLevelAccordion('high', alertsByRisk.highAlerts || []);
        populateRiskLevelAccordion('medium', alertsByRisk.mediumAlerts || []);
        populateRiskLevelAccordion('low', alertsByRisk.lowAlerts || []);
        populateRiskLevelAccordion('info', alertsByRisk.infoAlerts || []);
    }
    
    function populateRiskLevelAccordion(riskLevel, alerts) {
        const container = document.getElementById(`${riskLevel}-risk-types-accordion`);
        const emptyMessage = document.getElementById(`${riskLevel}-risk-empty`);
        
        if (!container) return;
        
        container.innerHTML = '';
        
        if (alerts.length === 0) {
            if (emptyMessage) {
                emptyMessage.classList.remove('d-none');
            }
            return;
        }
        
        if (emptyMessage) {
            emptyMessage.classList.add('d-none');
        }
        
        const alertsByType = {};
        alerts.forEach(alert => {
            const alertName = alert.name || 'Okänd sårbarhet';
            if (!alertsByType[alertName]) {
                alertsByType[alertName] = [];
            }
            alertsByType[alertName].push(alert);
        });
        
        Object.keys(alertsByType).forEach((alertName, index) => {
            const alertList = alertsByType[alertName];
            const alertId = `${riskLevel}-${index}`;
            
            const accordionItem = `
                <div class="accordion-item">
                    <h2 class="accordion-header" id="heading-${alertId}">
                        <button class="accordion-button collapsed" type="button" 
                                data-bs-toggle="collapse" data-bs-target="#collapse-${alertId}" 
                                aria-expanded="false" aria-controls="collapse-${alertId}">
                            ${alertName} <span class="badge bg-secondary ms-2">${alertList.length}</span>
                        </button>
                    </h2>
                    <div id="collapse-${alertId}" class="accordion-collapse collapse" 
                        aria-labelledby="heading-${alertId}" data-bs-parent="#${riskLevel}-risk-types-accordion">
                        <div class="accordion-body">
                            ${generateAlertDetails(alertList)}
                        </div>
                    </div>
                </div>
            `;
            
            container.insertAdjacentHTML('beforeend', accordionItem);
        });
    }

    function generateAlertDetails(alerts) {
        let html = '<div class="alert-instances">';
        
        alerts.forEach((alert, index) => {
            
            html += `
                <div class="alert-instance mb-3 p-3 border rounded">
                    <div class="row">
                        <div class="col-md-8">
                            <strong>URL:</strong> <code class="text-break">${escapeHtml(alert.url || 'N/A')}</code>
                        </div>
                        <div class="col-md-4">
                            <span class="badge bg-${getRiskColorClass(alert.risk)} text-white">${alert.risk || 'Unknown'}</span>
                            <span class="badge bg-info ms-1">${alert.confidence || 'Unknown'}</span>
                        </div>
                    </div>
                    ${alert.param ? `<div class="mt-2"><strong>Parameter:</strong> <code>${escapeHtml(alert.param)}</code></div>` : ''}
                    ${alert.description ? `<div class="mt-2"><small>${escapeHtml(alert.description.substring(0, 200))}...</small></div>` : ''}
                    <button class="btn btn-sm btn-outline-primary mt-2" onclick="showAlertDetails('${alert.id}')">
                        <i class="bi bi-info-circle me-1"></i>Visa detaljer
                    </button>
                </div>
            `;
        });
        
        html += '</div>';
        return html;
    }

    function getRiskColorClass(risk) {
        switch (risk?.toLowerCase()) {
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            case 'informational': return 'secondary';
            default: return 'secondary';
        }
    }
    
    function safeUpdateElement(id, content) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = content;
        } else {
            console.warn(`Element with id '${id}' not found`);
        }
    }
    
    function hideLoadingMessage() {
        const loadingElement = document.getElementById('alerts-loading');
        if (loadingElement) {
            loadingElement.classList.add('d-none');
        }
    }
    
    function showErrorInRecommendations(message) {
        const recommendationsContainer = document.getElementById('recommendations-container');
        if (recommendationsContainer) {
            recommendationsContainer.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle"></i> ${message}
                </div>
            `;
        }
    }
    
    function showSuccessMessage(message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-success alert-dismissible fade show';
        alertDiv.innerHTML = `
            <i class="bi bi-check-circle-fill"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        const cardBody = document.querySelector('.card-body');
        if (cardBody) {
            cardBody.insertBefore(alertDiv, cardBody.firstChild);
        }
        
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
    
    function showErrorMessage(message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger alert-dismissible fade show';
        alertDiv.innerHTML = `
            <i class="bi bi-exclamation-triangle-fill"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        const cardBody = document.querySelector('.card-body');
        if (cardBody) {
            cardBody.insertBefore(alertDiv, cardBody.firstChild);
        }
        
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
    
    function generateRecommendations(data) {
        const recommendationsContainer = document.getElementById('recommendations-container');
        if (!recommendationsContainer) {
            console.warn('Recommendations container not found');
            return;
        }
        
        const alertsByRisk = data.alerts_by_risk || {};
        
        let prioritizedRecommendations = [];
        
        if (alertsByRisk.highAlerts && alertsByRisk.highAlerts.length > 0) {
            const sqlInjectionAlerts = alertsByRisk.highAlerts.filter(alert => 
                alert.name && alert.name.toLowerCase().includes('sql injection'));
            
            if (sqlInjectionAlerts.length > 0) {
                prioritizedRecommendations.push({
                    title: 'Åtgärda SQL Injection sårbarheter OMEDELBART',
                    description: 'SQL Injection är en kritisk sårbarhet som kan leda till databaskompromiss. Använd parameteriserade queries och validera all input.',
                    priority: 'danger',
                    icon: 'bi-shield-exclamation'
                });
            }
            
            prioritizedRecommendations.push({
                title: 'Åtgärda högrisksårbarheter',
                description: `${alertsByRisk.highAlerts.length} högrisksårbarheter hittades. Dessa kräver omedelbar uppmärksamhet.`,
                priority: 'danger',
                icon: 'bi-exclamation-triangle-fill'
            });
        }
        
        if (alertsByRisk.mediumAlerts && alertsByRisk.mediumAlerts.length > 0) {
            prioritizedRecommendations.push({
                title: 'Granska medelrisksårbarheter',
                description: `${alertsByRisk.mediumAlerts.length} medelrisksårbarheter hittades. Planera åtgärder inom kort.`,
                priority: 'warning',
                icon: 'bi-exclamation-circle'
            });
        }
        
        if (alertsByRisk.lowAlerts && alertsByRisk.lowAlerts.length > 0) {
            prioritizedRecommendations.push({
                title: 'Åtgärda lågriskssårbarheter',
                description: `${alertsByRisk.lowAlerts.length} lågriskssårbarheter hittades. Åtgärda vid nästa underhållsperiod.`,
                priority: 'info',
                icon: 'bi-info-circle'
            });
        }
        
        prioritizedRecommendations.push({
            title: 'Allmänna säkerhetsrekommendationer',
            description: 'Implementera säkerhetsheaders, använd HTTPS, uppdatera regelbundet, och utför penetrationstester kontinuerligt.',
            priority: 'success',
            icon: 'bi-shield-check'
        });
        
        let html = '<div class="recommendations-list">';
        prioritizedRecommendations.forEach((rec, index) => {
            html += `
                <div class="alert alert-${rec.priority} border-start border-${rec.priority === 'danger' ? 'danger' : rec.priority === 'warning' ? 'warning' : rec.priority === 'info' ? 'info' : 'success'} border-3 mb-3">
                    <div class="d-flex align-items-center">
                        <i class="bi ${rec.icon} me-2"></i>
                        <div>
                            <h6 class="mb-1">${rec.title}</h6>
                            <p class="mb-0">${rec.description}</p>
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        
        recommendationsContainer.innerHTML = html;
    }
    
    // ====================================================
    // INITIALIZATION
    // ====================================================
    
    // Starta hämtning av sårbarhetsdata
    fetchVulnerabilities();
    
    // Lägg till händelselyssnare för modal-stängning
    const alertModal = document.getElementById('alertDetailsModal');
    if (alertModal) {
        alertModal.addEventListener('hidden.bs.modal', function() {
            currentAlertData = null;
        });
    }
    
    // PDF-nedladdning hantering
    document.querySelectorAll('.pdf-download-btn').forEach(button => {
        button.addEventListener('click', function() {
            const reportType = this.dataset.reportType;
            const originalText = this.innerHTML;
            
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Genererar PDF...';
            this.disabled = true;
            
            fetch(`/api/download-pdf-report/${reportType}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.blob();
                })
                .then(blob => {
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    
                    const reportNames = {
                        'basic': 'basic_slutkund',
                        'medium': 'medium_detaljerad', 
                        'full': 'fullstandig'
                    };
                    
                    a.download = `sakerheterapport_${reportNames[reportType]}_${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    
                    showSuccessMessage(`${reportType.charAt(0).toUpperCase() + reportType.slice(1)} rapport har laddats ner!`);
                })
                .catch(error => {
                    console.error('Error downloading PDF:', error);
                    showErrorMessage('Kunde inte generera PDF-rapporten. Vänligen försök igen.');
                })
                .finally(() => {
                    this.innerHTML = originalText;
                    this.disabled = false;
                });
        });
    });
    
    // JSON-nedladdning hantering
    const downloadReportBtn = document.getElementById('download-report-btn');
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', function() {
            const reportId = window.REPORT_CONFIG ? window.REPORT_CONFIG.report_id : 'unknown';
            
            fetch(`/api/download-report/${reportId}`)
                .then(response => response.json())
                .then(data => {
                    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
                    const downloadAnchorNode = document.createElement('a');
                    downloadAnchorNode.setAttribute("href", dataStr);
                    downloadAnchorNode.setAttribute("download", `pentesting_report_${data.id || reportId}.json`);
                    document.body.appendChild(downloadAnchorNode);
                    downloadAnchorNode.click();
                    downloadAnchorNode.remove();
                })
                .catch(error => {
                    console.error('Error downloading report:', error);
                    alert('Kunde inte hämta rapporten. Vänligen försök igen.');
                });
        });
    }
    
    // Debug-funktioner
    if (window.REPORT_CONFIG && window.REPORT_CONFIG.debug_mode) {
        console.info('Debug mode enabled');
        console.info('Target URL:', window.REPORT_CONFIG.target_url);
        console.info('Report ID:', window.REPORT_CONFIG.report_id);
    }
});