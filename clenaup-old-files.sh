#!/bin/bash

# Rensa gamla filer som inte längre behövs

echo "🧹 Rensar gamla IP-discovery filer..."

# Ta bort gamla filer
rm -f test-ip.sh
rm -f docker-compose-host-network.yml
rm -f app_integration_example.py
rm -f logging_fix.py

echo "✅ Gamla filer borttagna"
echo ""
echo "📋 Kvar finns:"
echo "   - docker-compose.yml (förenklad)"
echo "   - start.sh (förenklad)"
echo "   - ip_config.py (ny filbaserad IP-hantering)"
echo "   - ip_config_routes.py (Flask routes)"
echo "   - ip_config_setup.html (setup-sida)"
echo "   - ip_config.html (konfigurationssida)"
echo "   - ip_discovery.py (förenklad för bakåtkompatibilitet)"
echo "   - INTEGRERING.md (instruktioner)"
echo ""
echo "🎯 Nästa steg:"
echo "   1. Läs INTEGRERING.md"
echo "   2. Kopiera filer till ditt projekt"
echo "   3. Uppdatera app.py enligt instruktionerna"
echo "   4. Testa med ./start.sh"