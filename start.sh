#!/bin/bash

# Säkerhetsapplikation - Startup Script

set -e

echo "🚀 Startar säkerhetsapplikationen..."

# Kontrollera att Docker och Docker Compose finns
if ! command -v docker &> /dev/null; then
    echo "❌ Docker är inte installerat. Installera Docker först."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose är inte installerat. Installera Docker Compose först."
    exit 1
fi

# Använd rätt kommando för Docker Compose
COMPOSE_CMD="docker-compose"
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
fi

# Auto-upptäck host IP om det behövs
echo "🔍 Upptäcker host IP-adress..."

# Försök hitta host IP på olika sätt
HOST_IP=""

# Metod 1: Primär nätverksgränssnitt
if [ -z "$HOST_IP" ]; then
    HOST_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "")
fi

# Metod 2: ip route kommando
if [ -z "$HOST_IP" ]; then
    HOST_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || echo "")
fi

# Metod 3: ifconfig fallback
if [ -z "$HOST_IP" ] && command -v ifconfig &> /dev/null; then
    HOST_IP=$(ifconfig | grep -E "inet ([0-9]{1,3}\.){3}[0-9]{1,3}" | grep -v "127.0.0.1" | awk '{print $2}' | head -1 | sed 's/addr://')
fi

# Metod 4: Extern IP som fallback
if [ -z "$HOST_IP" ]; then
    echo "⚠️  Kan inte hitta lokal IP, försöker hämta extern IP..."
    HOST_IP=$(curl -s --max-time 5 https://api.ipify.org || echo "")
fi

if [ -n "$HOST_IP" ]; then
    echo "✅ Hittade host IP: $HOST_IP"
    export HOST_IP
else
    echo "⚠️  Kunde inte auto-upptäcka IP. Använder localhost som fallback."
    export HOST_IP="localhost"
fi

# Skapa nödvändiga mappar
echo "📁 Skapar nödvändiga mappar..."
mkdir -p results logs zap-config

# Kopiera miljövariabler om .env inte finns
if [ ! -f .env ]; then
    echo "📋 Kopierar .env template..."
    cp .env.template .env
    echo "⚠️  VIKTIGT: Redigera .env-filen och ändra API-nycklar och lösenord!"
fi

# Uppdatera .env med upptäckt IP om HOST_IP=auto
if grep -q "HOST_IP=auto" .env; then
    echo "🔄 Uppdaterar .env med upptäckt IP..."
    sed -i "s/HOST_IP=auto/HOST_IP=$HOST_IP/" .env
fi

# Visa IP-information
echo ""
echo "🌐 IP-konfiguration:"
echo "   Host IP:    $HOST_IP"
echo "   App URL:    http://$HOST_IP:5001"
echo "   ZAP UI:     http://$HOST_IP:8080"
echo "   ZAP Proxy:  http://$HOST_IP:8090"
echo ""

# Bygg och starta alla services
echo "🔨 Bygger Docker images..."
$COMPOSE_CMD build

echo "🆙 Startar alla services..."
$COMPOSE_CMD up -d

# Vänta på att services ska bli redo
echo "⏳ Väntar på att services ska starta..."
sleep 30

# Kontrollera hälsostatus
echo "🏥 Kontrollerar service-hälsa..."

# Kontrollera huvudapplikationen
if curl -f http://localhost:5001/api/health &> /dev/null; then
    echo "✅ Huvudapplikation: Körande på http://$HOST_IP:5001"
else
    echo "❌ Huvudapplikation: Inte tillgänglig"
fi

# Kontrollera ZAP
if curl -f http://localhost:8080/JSON/core/view/version/ &> /dev/null; then
    echo "✅ ZAP: Körande på http://$HOST_IP:8080"
else
    echo "❌ ZAP: Inte tillgänglig"
fi

echo ""
echo "🎉 Applikationen är startad!"
echo ""
echo "📖 Användning:"
echo "   Web UI:     http://$HOST_IP:5001"
echo "   ZAP UI:     http://$HOST_IP:8080"
echo "   ZAP Proxy:  http://$HOST_IP:8090"
echo ""
echo "🔧 Proxy-inställningar för webbläsare:"
echo "   HTTP Proxy: $HOST_IP:8090"
echo "   HTTPS Proxy: $HOST_IP:8090"
echo ""
echo "📝 Kommandon:"
echo "   Se loggar:  $COMPOSE_CMD logs -f"
echo "   Stoppa:     $COMPOSE_CMD down"
echo "   Starta om:  $COMPOSE_CMD restart"
echo ""
echo "📁 Data sparas i:"
echo "   Resultat:   ./results/"
echo "   Loggar:     ./logs/"
echo ""

# Visa loggar från alla services
echo "📊 Visar live loggar (Ctrl+C för att avsluta)..."
$COMPOSE_CMD logs -f