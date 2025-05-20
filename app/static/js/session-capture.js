/**
 * JavaScript för sessionskapturingssidan
 */
document.addEventListener('DOMContentLoaded', function() {
    const extractCookiesBtn = document.getElementById('extract_cookies_btn');
    const saveSessionBtn = document.getElementById('save_session_btn');
    const sessionNameInput = document.getElementById('session_name');
    const cookiesDataTextarea = document.getElementById('cookies_data');
    
    if (!extractCookiesBtn || !saveSessionBtn) return;
    
    // När användaren klickar på "Hämta cookies"
    extractCookiesBtn.addEventListener('click', function() {
        extractCookiesBtn.disabled = true;
        extractCookiesBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Hämtar...';
        
        // Använd ZAP API för att hämta cookies från senaste sessionen
        fetch('/api/extract-cookies')
            .then(response => response.json())
            .then(data => {
                if (data.cookies) {
                    cookiesDataTextarea.value = data.cookies;
                    saveSessioBtn.disabled = false;
                    
                    // Enable editing of the textarea in case user needs to modify
                    cookiesDataTextarea.readOnly = false;
                } else {
                    cookiesDataTextarea.value = "";
                    cookiesDataTextarea.placeholder = "Kunde inte hämta cookies automatiskt. Klistra in cookies manuellt här.";
                    cookiesDataTextarea.readOnly = false;
                    saveSessioBtn.disabled = false;
                    alert('Kunde inte hämta cookies. Du kan pröva att manuellt kopiera cookie-raden från ZAP UI eller direkt från webbläsaren.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                cookiesDataTextarea.readOnly = false;
                saveSessioBtn.disabled = false;
                alert('Ett fel uppstod vid hämtning av cookies. Försök att klistra in manuellt.');
            })
            .finally(() => {
                extractCookiesBtn.disabled = false;
                extractCookiesBtn.textContent = 'Hämta cookies';
            });
    });
    
    // När användaren klickar på "Spara session"
    saveSessionBtn.addEventListener('click', function() {
        const sessionName = sessionNameInput.value.trim();
        
        if (!sessionName) {
            APP.showToast('Vänligen ange ett sessionsnamn.', 'warning');
            return;
        }
        
        const cookiesData = cookiesDataTextarea.value.trim();
        
        if (!cookiesData) {
            APP.showToast('Ingen cookie-data att spara.', 'warning');
            return;
        }
        
        saveSessionBtn.disabled = true;
        saveSessionBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sparar...';
        
        // Skicka data till servern
        APP.fetch(APP.API.SAVE_SESSION, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                session_name: sessionName,
                cookies: cookiesData
            }),
        })
        .then(data => {
            if (data.success) {
                APP.showToast('Session sparad framgångsrikt!', 'success');
                // Omdirigera till scanning-sidan efter en kort fördröjning
                setTimeout(() => {
                    window.location.href = '/scan';
                }, 1500);
            } else {
                APP.showToast('Kunde inte spara sessionen.', 'danger');
                saveSessionBtn.disabled = false;
            }
        })
        .catch(error => {
            APP.showToast('Ett fel uppstod vid sparande av session: ' + error.message, 'danger');
            saveSessionBtn.disabled = false;
            saveSessionBtn.textContent = 'Spara session';
        });
    });
});