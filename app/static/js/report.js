document.addEventListener('DOMContentLoaded', function() {
    
    // ====================================================
    // FUNKTIONER FÖR SÅRBARHETSDATA (BEFINTLIG KOD)
    // ====================================================
    
    function fetchVulnerabilities() {
        console.log('Fetching vulnerabilities...');
        fetch('/api/zap-alerts-by-risk')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error('API error:', data.error);
                    // Uppdatera bara räknarna vid fel
                    updateCounts(0, 0, 0, 0);
                    showErrorInRecommendations('Error loading vulnerabilities: ' + data.error);
                    return;
                }
                
                console.log('Vulnerabilities fetched successfully');
                updateCounts(data);
                generateRecommendations(data);
                
                // Dölj laddningsmeddelande och visa framgång
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
        // Säkert sätt att uppdatera räknare
        const alertsByRisk = data.alerts_by_risk || {};
        
        const highCount = alertsByRisk.highAlerts ? alertsByRisk.highAlerts.length : 0;
        const mediumCount = alertsByRisk.mediumAlerts ? alertsByRisk.mediumAlerts.length : 0;
        const lowCount = alertsByRisk.lowAlerts ? alertsByRisk.lowAlerts.length : 0;
        const infoCount = alertsByRisk.infoAlerts ? alertsByRisk.infoAlerts.length : 0;
        
        // FIXAT: Uppdatera räknare med korrekta ID:n
        safeUpdateElement('high-risk-badge', highCount);
        safeUpdateElement('medium-risk-badge', mediumCount);
        safeUpdateElement('low-risk-badge', lowCount);
        safeUpdateElement('info-risk-badge', infoCount);
        
        // Uppdatera även summary cards om de finns
        safeUpdateElement('high-risk-count', highCount);
        safeUpdateElement('medium-risk-count', mediumCount);
        safeUpdateElement('low-risk-count', lowCount);
        safeUpdateElement('info-risk-count', infoCount);
        
        // NYTT: Populera accordion-innehåll
        populateAccordionContent('high', alertsByRisk.highAlerts || []);
        populateAccordionContent('medium', alertsByRisk.mediumAlerts || []);
        populateAccordionContent('low', alertsByRisk.lowAlerts || []);
        populateAccordionContent('info', alertsByRisk.infoAlerts || []);
        
        // Uppdatera report date
        safeUpdateElement('report-date', new Date().toLocaleString('sv-SE'));
    }     


    function populateAccordionContent(riskLevel, alerts) {
        const containerId = `${riskLevel}-risk-types-accordion`;
        const emptyMessageId = `${riskLevel}-risk-empty`;
        
        const container = document.getElementById(containerId);
        const emptyMessage = document.getElementById(emptyMessageId);
        
        if (!container) {
            console.warn(`Container ${containerId} not found`);
            return;
        }
        
        // Rensa befintligt innehåll
        container.innerHTML = '';
        
        if (alerts.length === 0) {
            // Visa "inga sårbarheter" meddelande
            if (emptyMessage) {
                emptyMessage.classList.remove('d-none');
            }
            return;
        }
        
        // Dölj "inga sårbarheter" meddelande
        if (emptyMessage) {
            emptyMessage.classList.add('d-none');
        }
        
        // Gruppera alerts per typ
        const alertsByType = {};
        alerts.forEach(alert => {
            const alertName = alert.name || 'Okänd sårbarhet';
            if (!alertsByType[alertName]) {
                alertsByType[alertName] = [];
            }
            alertsByType[alertName].push(alert);
        });
        
        // Skapa accordion items för varje alert-typ
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
                        aria-labelledby="heading-${alertId}" data-bs-parent="#${containerId}">
                        <div class="accordion-body">
                            ${generateAlertDetails(alertList)}
                        </div>
                    </div>
                </div>
            `;
            
            container.insertAdjacentHTML('beforeend', accordionItem);
        });
    }

    // NYTT: Funktion för att generera alert-detaljer
    function generateAlertDetails(alerts) {
        let html = '<div class="alert-instances">';
        
        alerts.forEach((alert, index) => {
            if (index >= 5) { // Begränsa till 5 instanser
                html += `<p class="text-muted">...och ${alerts.length - 5} fler instanser</p>`;
                return;
            }
            
            // Skapa en säker JSON-string för onclick
            const alertJson = JSON.stringify(alert).replace(/"/g, '&quot;');
            
            html += `
                <div class="alert-instance mb-3 p-3 border rounded">
                    <div class="row">
                        <div class="col-md-8">
                            <strong>URL:</strong> <code class="text-break">${escapeHtml(alert.url || 'N/A')}</code>
                        </div>
                        <div class="col-md-4">
                            <button class="btn btn-sm btn-outline-primary mt-2 float-end" onclick='showAlertDetailsFromData(${alertJson})'>
                                <i class="bi bi-info-circle me-1"></i>Visa detaljer
                            </button>
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        return html;
}

    // NYTT: Hjälpfunktion för risk-färger
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
        // Dölj laddningsmeddelanden
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
    
    function generateRecommendations(data) {
        const recommendationsContainer = document.getElementById('recommendations-container');
        if (!recommendationsContainer) {
            console.warn('Recommendations container not found');
            return;
        }
        
        const alertsByRisk = data.alerts_by_risk || {};
        
        let prioritizedRecommendations = [];
        
        // Hög prioritet
        if (alertsByRisk.highAlerts && alertsByRisk.highAlerts.length > 0) {
            // Kolla för specifika sårbarheter
            const sqlInjectionAlerts = alertsByRisk.highAlerts.filter(alert => 
                alert.name && alert.name.toLowerCase().includes('sql injection'));
            
            if (sqlInjectionAlerts.length > 0) {
                prioritizedRecommendations.push({
                    title: 'Åtgärda SQL Injection sårbarheter OMEDELBART',
                    description: 'SQL Injection är en kritisk sårbarhet som kan leda till databaskompromiss. Använd parameteriserade queries och validera all input.',
                    priority: 'high',
                    count: sqlInjectionAlerts.length
                });
            }
            
            const xssAlerts = alertsByRisk.highAlerts.filter(alert => 
                alert.name && (alert.name.toLowerCase().includes('xss') || alert.name.toLowerCase().includes('cross site scripting')));
            
            if (xssAlerts.length > 0) {
                prioritizedRecommendations.push({
                    title: 'Implementera XSS-skydd',
                    description: 'Cross-Site Scripting sårbarheter hittades. Implementera Content Security Policy och validera/koda all output.',
                    priority: 'high',
                    count: xssAlerts.length
                });
            }
            
            // Generisk rekommendation för andra höga risker
            if (prioritizedRecommendations.length === 0) {
                prioritizedRecommendations.push({
                    title: 'Åtgärda högrisk sårbarheter omedelbart',
                    description: 'Kritiska säkerhetsproblem har identifierats som kräver omedelbar uppmärksamhet.',
                    priority: 'high',
                    count: alertsByRisk.highAlerts.length
                });
            }
        }
        
        // Medelhög prioritet
        if (alertsByRisk.mediumAlerts && alertsByRisk.mediumAlerts.length > 0) {
            prioritizedRecommendations.push({
                title: 'Granska säkerhetsheaders',
                description: 'Implementera säkerhetsheaders som CSRF-tokens, X-Frame-Options och Content Security Policy.',
                priority: 'medium',
                count: alertsByRisk.mediumAlerts.length
            });
        }
        
        // Låg prioritet
        if (alertsByRisk.lowAlerts && alertsByRisk.lowAlerts.length > 0) {
            prioritizedRecommendations.push({
                title: 'Förbättra informationssäkerhet',
                description: 'Dölj versionsinfo och implementera proper cache-control headers.',
                priority: 'low',
                count: alertsByRisk.lowAlerts.length
            });
        }
        
        // Allmän rekommendation
        prioritizedRecommendations.push({
            title: 'Implementera säker utvecklingsprocess',
            description: 'Utbilda utvecklare i säker kodning och implementera säkerhetsgranskningar i utvecklingsprocessen.',
            priority: 'low'
        });
        
        // Om inga sårbarheter finns
        if (prioritizedRecommendations.length === 1) { // Bara den allmänna rekommendationen
            prioritizedRecommendations.unshift({
                title: 'Bra jobbat!',
                description: 'Inga allvarliga säkerhetsproblem hittades. Fortsätt med regelbundna säkerhetskontroller.',
                priority: 'success'
            });
        }
        
        // Visa rekommendationer
        let recommendationsHTML = `<ul class="list-group">`;
        
        prioritizedRecommendations.forEach(rec => {
            let priorityClass;
            switch (rec.priority) {
                case 'high':
                    priorityClass = 'list-group-item-danger';
                    break;
                case 'medium':
                    priorityClass = 'list-group-item-warning';
                    break;
                case 'success':
                    priorityClass = 'list-group-item-success';
                    break;
                default:
                    priorityClass = 'list-group-item-info';
            }
            
            const countBadge = rec.count ? `<span class="badge bg-secondary">${rec.count}</span>` : '';
            
            recommendationsHTML += `
                <li class="list-group-item ${priorityClass}">
                    <div class="d-flex w-100 justify-content-between">
                        <h5 class="mb-1">${rec.title} ${countBadge}</h5>
                        <small>${rec.priority.charAt(0).toUpperCase() + rec.priority.slice(1)} prioritet</small>
                    </div>
                    <p class="mb-1">${rec.description}</p>
                </li>
            `;
        });
        
        recommendationsHTML += `</ul>`;
        recommendationsContainer.innerHTML = recommendationsHTML;
    }
    
    // ====================================================
    // NYA PDF-NEDLADDNINGSFUNKTIONER (TRE RAPPORTTYPER)
    // ====================================================
    
    // Hantera PDF-nedladdning för alla rapporttyper
    document.querySelectorAll('.pdf-download-btn').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const reportType = this.getAttribute('data-report-type');
            const originalText = this.innerHTML;
            
            // Visa laddningsindikator
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Genererar...';
            
            // Inaktivera alla dropdown-items
            document.querySelectorAll('.pdf-download-btn').forEach(btn => {
                btn.style.pointerEvents = 'none';
            });
            
            // Gör fetch-anrop för att hämta PDF
            fetch(`/api/download-pdf-report/${reportType}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.blob();
                })
                .then(blob => {
                    // Skapa en URL för blob och ladda ner filen
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    
                    // Generera filnamn baserat på rapporttyp
                    const reportNames = {
                        'basic': 'basic_slutkund',
                        'medium': 'medium_detaljerad', 
                        'full': 'fullstandig'
                    };
                    
                    a.download = `sakerheterapport_${reportNames[reportType]}_${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    
                    // Visa framgångsmeddelande
                    showSuccessMessage(`${reportType.charAt(0).toUpperCase() + reportType.slice(1)} rapport har laddats ner!`);
                })
                .catch(error => {
                    console.error('Error downloading PDF:', error);
                    showErrorMessage('Kunde inte generera PDF-rapporten. Vänligen försök igen.');
                })
                .finally(() => {
                    // Återställ alla knappar
                    document.querySelectorAll('.pdf-download-btn').forEach(btn => {
                        btn.style.pointerEvents = 'auto';
                    });
                    this.innerHTML = originalText;
                });
        });
    });
    
    // ====================================================
    // JSON-NEDLADDNING (BEFINTLIG KOD)
    // ====================================================
    
    // Hantera nedladdning av rapport som JSON
    const downloadReportBtn = document.getElementById('download-report-btn');
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', function() {
            fetch('/api/download-report/{{ report_id }}')
                .then(response => response.json())
                .then(data => {
                    // Skapa en JSON-fil för nedladdning
                    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
                    const downloadAnchorNode = document.createElement('a');
                    downloadAnchorNode.setAttribute("href", dataStr);
                    downloadAnchorNode.setAttribute("download", `pentesting_report_${data.id || '{{ report_id }}'}.json`);
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
    
    // ====================================================
    // HJÄLPFUNKTIONER FÖR MEDDELANDEN
    // ====================================================
    
    function showSuccessMessage(message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-success alert-dismissible fade show';
        alertDiv.innerHTML = `
            <i class="bi bi-check-circle-fill"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Lägg till i början av första card-body vi hittar
        const cardBody = document.querySelector('.card-body');
        if (cardBody) {
            cardBody.insertBefore(alertDiv, cardBody.firstChild);
        }
        
        // Ta bort efter 5 sekunder
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
        
        // Lägg till i början av första card-body vi hittar
        const cardBody = document.querySelector('.card-body');
        if (cardBody) {
            cardBody.insertBefore(alertDiv, cardBody.firstChild);
        }
        
        // Ta bort efter 5 sekunder
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
    
    // ====================================================
    // INITIALISERING
    // ====================================================
    
    // Initiera hämtning av sårbarheter när sidan laddas
    fetchVulnerabilities();

});

    function showAlertDetails(alertId, alertData = null) {
        console.log('showAlertDetails called with ID:', alertId);
        
        // Om alert data redan finns, visa det direkt
        if (alertData) {
            populateAlertModal(alertData);
            showModal();
            return;
        }
        
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
        modalBody.innerHTML = `
            <div class="text-center p-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Laddar...</span>
                </div>
                <p class="mt-2">Hämtar detaljerad information...</p>
            </div>
        `;
        
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
        
        modalTitle.textContent = 'Fel vid hämtning av detaljer';
        modalBody.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <strong>Fel:</strong> ${errorMessage}
            </div>
        `;
        
        // Visa modal om den inte redan är synlig
        if (!modal.classList.contains('show')) {
            const modalInstance = new bootstrap.Modal(modal);
            modalInstance.show();
        }
    }

    /**
    * Visa modal med populerad data
    */
    function showModal() {
        const modal = document.getElementById('alertDetailsModal');
        const modalInstance = new bootstrap.Modal(modal);
        modalInstance.show();
    }

    /**
    * Fyll i modal med alert-data
    */
    function populateAlertModal(alertData) {
        console.log('Populating modal with data:', alertData);
        
        // Uppdatera modal titel
        const modalTitle = document.getElementById('alertDetailsTitle');
        modalTitle.textContent = alertData.name || 'Sårbarhetsdetaljer';
        
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
        updateModalField('alert-cwe', alertData.cweid || alertData.cwe || 'Inte tillgänglig');
        updateModalField('alert-wasc', alertData.wascid || alertData.wasc || 'Inte tillgänglig');
        
        // Hantera taggar
        const tags = alertData.tags || {};
        updateModalField('alert-tags', formatTags(tags));
        
        // Visa modal
        showModal();
    }

    /**
    * Uppdatera ett fält i modal
    */
    function updateModalField(fieldId, content, styleClass = '') {
        const element = document.getElementById(fieldId);
        if (element) {
            // Rensa tidigare klasser
            element.className = 'p-2 bg-light';
            
            // Lägg till style-klass om specificerad
            if (styleClass === 'code-style') {
                element.innerHTML = `<code class="text-break">${escapeHtml(content)}</code>`;
            } else if (styleClass.startsWith('badge-')) {
                element.innerHTML = `<span class="badge ${styleClass}">${escapeHtml(content)}</span>`;
            } else {
                element.innerHTML = formatContent(content);
            }
        } else {
            console.warn(`Element with ID '${fieldId}' not found`);
        }
    }

    /**
    * Formatera innehåll för visning
    */
    function formatContent(content) {
        if (!content || content === 'N/A') {
            return '<em class="text-muted">Inte tillgänglig</em>';
        }
        
        // Konvertera newlines till br-taggar och escape HTML
        const escaped = escapeHtml(content);
        return escaped.replace(/\n/g, '<br>');
    }

    /**
    * Formatera referenser
    */
    function formatReferences(references) {
        if (!references || references === 'N/A') {
            return '<em class="text-muted">Inga referenser tillgängliga</em>';
        }
        
        // Splitta på newlines och skapa länkar
        const lines = references.split('\n').filter(line => line.trim());
        const formattedLines = lines.map(line => {
            const trimmed = line.trim();
            if (trimmed.startsWith('http')) {
                return `<a href="${trimmed}" target="_blank" class="text-decoration-none">${escapeHtml(trimmed)} <i class="bi bi-box-arrow-up-right"></i></a>`;
            } else {
                return escapeHtml(trimmed);
            }
        });
        
        return formattedLines.join('<br>');
    }

    /**
    * Formatera taggar
    */
    function formatTags(tags) {
        if (!tags || Object.keys(tags).length === 0) {
            return '<em class="text-muted">Inga taggar tillgängliga</em>';
        }
        
        const tagBadges = Object.entries(tags)
            .map(([key, value]) => `<span class="badge bg-secondary me-1">${escapeHtml(key)}: ${escapeHtml(value)}</span>`)
            .join(' ');
        
        return tagBadges;
    }

    /**
    * Få CSS-klass för risk-badge
    */
    function getRiskBadgeClass(risk) {
        switch (risk?.toLowerCase()) {
            case 'high':
                return 'badge-bg-danger text-white';
            case 'medium':
                return 'badge-bg-warning text-dark';
            case 'low':
                return 'badge-bg-info text-white';
            case 'informational':
                return 'badge-bg-secondary text-white';
            default:
                return 'badge-bg-secondary text-white';
        }
    }

    /**
    * Få CSS-klass för confidence-badge
    */
    function getConfidenceBadgeClass(confidence) {
        switch (confidence?.toLowerCase()) {
            case 'high':
                return 'badge-bg-success text-white';
            case 'medium':
                return 'badge-bg-warning text-dark';
            case 'low':
                return 'badge-bg-light text-dark';
            default:
                return 'badge-bg-secondary text-white';
        }
    }

    /**
    * Escape HTML för säkerhet
    */
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

    // Förbättra befintlig generateAlertDetails-funktion för att skicka alert-objektet
    // Denna funktion bör uppdateras i din befintliga kod:
    function generateAlertDetailsImproved(alerts) {
        let html = '<div class="alert-instances">';
        
        alerts.forEach((alert, index) => {
            if (index >= 5) { // Begränsa till 5 instanser
                html += `<p class="text-muted">...och ${alerts.length - 5} fler instanser</p>`;
                return;
            }
            
            html += `
                <div class="alert-instance mb-3 p-3 border rounded">
                    <div class="row">
                        <div class="col-md-8">
                            <strong>URL:</strong> <code class="text-break">${alert.url || 'N/A'}</code>
                        </div>
                        <div class="col-md-4">
                            <span class="badge bg-${getRiskColorClass(alert.risk)} text-white">${alert.risk || 'Unknown'}</span>
                            <span class="badge bg-info ms-1">${alert.confidence || 'Unknown'}</span>
                        </div>
                    </div>
                    ${alert.param ? `<div class="mt-2"><strong>Parameter:</strong> <code>${alert.param}</code></div>` : ''}
                    ${alert.description ? `<div class="mt-2"><small>${alert.description.substring(0, 200)}...</small></div>` : ''}
                    <button class="btn btn-sm btn-outline-primary mt-2" onclick="showAlertDetails('${alert.id}', ${JSON.stringify(alert).replace(/'/g, '\\\'')})">
                        Visa detaljer
                    </button>
                </div>
            `;
        });
        
        html += '</div>';
        return html;
    }



/**
 * Utökad populateAlertModal för att hantera all teknisk information
 */
function populateAlertModalExtended(alertData) {
    console.log('Populating extended modal with data:', alertData);
    
    // Uppdatera modal titel
    const modalTitle = document.getElementById('alertDetailsTitle');
    modalTitle.textContent = alertData.name || 'Sårbarhetsdetaljer';
    
    // Grundläggande fält
    updateModalField('alert-description', alertData.description || 'Ingen beskrivning tillgänglig');
    updateModalField('alert-risk', alertData.risk || 'Okänd', getRiskBadgeClass(alertData.risk));
    updateModalField('alert-confidence', alertData.confidence || 'Okänd', getConfidenceBadgeClass(alertData.confidence));
    updateModalField('alert-url', alertData.url || 'Ingen URL tillgänglig', 'code-style');
    updateModalField('alert-parameter', alertData.param || alertData.parameter || 'Ingen parameter');
    updateModalField('alert-attack', alertData.attack || 'Ingen attack-information');
    updateModalField('alert-solution', alertData.solution || 'Inga åtgärdsförslag tillgängliga');
    
    // Referenser
    const references = alertData.reference || alertData.references || '';
    updateModalField('alert-references', formatReferences(references));
    
    // Teknisk information
    updateModalField('alert-cwe', formatCWE(alertData.cweid || alertData.cwe));
    updateModalField('alert-wasc', formatWASC(alertData.wascid || alertData.wasc));
    
    // Taggar
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
        evidenceSection.style.display = 'block';
        updateModalField('alert-evidence', alertData.evidence);
    } else {
        const evidenceSection = document.getElementById('evidence-section');
        evidenceSection.style.display = 'none';
    }
    
    // Request/Response information
    updateModalField('alert-request-response', formatRequestResponse(alertData));
    
    // Andra URLs som påverkas
    updateModalField('alert-other-urls', formatOtherUrls(alertData.otherInfo || alertData.other_urls));
    
    // Spara current alert data för export
    window.currentAlertData = alertData;
    
    // Visa modal
    showModal();
}

/**
 * Formatera CWE-information med länkar
 */
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
    
    return escapeHtml(cweId);
}

/**
 * Formatera WASC-information med länkar
 */
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
    
    return escapeHtml(wascId);
}

/**
 * Formatera request/response information
 */
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

/**
 * Formatera andra URLs
 */
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

/**
 * Kopiera alert-detaljer till clipboard
 */
function copyAlertDetails() {
    const alertData = window.currentAlertData;
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
    
    navigator.clipboard.writeText(textContent).then(() => {
        // Visa success-meddelande
        showTemporaryMessage('Sårbarhetsdetaljer kopierade till clipboard!', 'success');
    }).catch(err => {
        console.error('Kunde inte kopiera text: ', err);
        showTemporaryMessage('Fel vid kopiering till clipboard', 'error');
    });
}

/**
 * Exportera alert-detaljer som JSON
 */
function exportAlertDetails() {
    const alertData = window.currentAlertData;
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

/**
 * Visa tillfälligt meddelande
 */
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
    
    // Ta bort efter 3 sekunder
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 3000);
}

/**
 * Uppdaterad generateAlertDetails som använder den nya funktionen
 */
function generateAlertDetailsWithModal(alerts) {
    let html = '<div class="alert-instances">';
    
    alerts.forEach((alert, index) => {
        if (index >= 5) { // Begränsa till 5 instanser
            html += `<p class="text-muted">...och ${alerts.length - 5} fler instanser</p>`;
            return;
        }
        
        // Skapa en säker JSON-string för onclick
        const alertJson = JSON.stringify(alert).replace(/"/g, '&quot;');
        
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
                <button class="btn btn-sm btn-outline-primary mt-2" onclick='showAlertDetailsFromData(${alertJson})'>
                    <i class="bi bi-info-circle me-1"></i>Visa detaljer
                </button>
            </div>
        `;
    });
    
    html += '</div>';
    return html;
}

/**
 * Hjälpfunktion för att visa alert-detaljer från JSON-data
 */
function showAlertDetailsFromData(alertData) {
    if (alertData.id) {
        // Om vi har ett ID, hämta full data från API
        showAlertDetails(alertData.id, alertData);
    } else {
        // Annars, använd den data vi har
        populateAlertModalExtended(alertData);
    }
}

// Överskugga den ursprungliga populateAlertModal med den utökade versionen
window.populateAlertModal = populateAlertModalExtended;

// Lägg till händelselyssnare för att hantera modal-stängning
document.addEventListener('DOMContentLoaded', function() {
    const alertModal = document.getElementById('alertDetailsModal');
    if (alertModal) {
        alertModal.addEventListener('hidden.bs.modal', function() {
            // Rensa saved alert data när modal stängs
            window.currentAlertData = null;
        });
    }
});