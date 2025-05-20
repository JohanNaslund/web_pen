/**
 * Gemensamma JavaScript-funktioner för Web PEN Testing-applikationen
 */

// Globala variabler och inställningar
const APP = {
    // API-endpoints
    API: {
        SCAN_STATUS: '/api/scan-status',
        EXTRACT_COOKIES: '/api/extract-cookies',
        SAVE_SESSION: '/api/save-session'
    },
    
    // Polling-intervall för statusuppdateringar (ms)
    STATUS_POLL_INTERVAL: 5000
};

/**
 * Hjälpfunktion för att göra fetch-requests
 * @param {string} url - API-endpoint
 * @param {Object} options - Fetch-options
 * @returns {Promise} - Fetch-promise
 */
APP.fetch = function(url, options = {}) {
    return fetch(url, options)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .catch(error => {
            console.error('Fetch error:', error);
            throw error;
        });
};

/**
 * Visa popup-meddelande
 * @param {string} message - Meddelande att visa
 * @param {string} type - Meddelandetyp (success, danger, warning, info)
 * @param {number} duration - Visningstid i millisekunder
 */
APP.showToast = function(message, type = 'info', duration = 5000) {
    // Skapa toast-element om det inte redan finns
    let toastContainer = document.querySelector('.toast-container');
    
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    // Skapa ett unikt ID för toast
    const toastId = 'toast-' + Date.now();
    
    // Skapa toast HTML
    const toastHtml = `
        <div id="${toastId}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header">
                <strong class="me-auto">${type.charAt(0).toUpperCase() + type.slice(1)}</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Stäng"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    // Lägg till toast i container
    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    
    // Initiera toast med Bootstrap
    const toastElement = document.getElementById(toastId);
    const bsToast = new bootstrap.Toast(toastElement, { 
        autohide: true,
        delay: duration
    });
    
    // Visa toast
    bsToast.show();
    
    // Ta bort toast efter att den stängts
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
};

/**
 * Formatterar datum till lokalt format
 * @param {string|number|Date} date - Datum att formatera
 * @returns {string} - Formaterat datum
 */
APP.formatDate = function(date) {
    if (!date) return '';
    
    const d = new Date(date);
    return d.toLocaleString();
};

// DOM-redo händelser
document.addEventListener('DOMContentLoaded', function() {
    // Initialisera Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Hantera API-fel globalt
    window.addEventListener('unhandledrejection', function(event) {
        console.error('Unhandled promise rejection:', event.reason);
        APP.showToast('Ett fel uppstod: ' + event.reason.message, 'danger');
    });
});