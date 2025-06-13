#!/bin/bash

# ANSI färgkoder
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

heading() {
    echo -e "${BLUE}=== $1 ===${NC}"
}
success() {
    echo -e "${GREEN}✓ $1${NC}"
}
warning() {
    echo -e "${YELLOW}! $1${NC}"
}
error() {
    echo -e "${RED}✗ $1${NC}"
}

# Starta Attack proxy (ta alltid bort och skapa ny)
start_zap() {
    heading "Startar Attack proxy"
    
    # Stoppa och ta bort eventuell gammal container
    if docker ps -a --format '{{.Names}}' | grep -q '^zap$'; then
        docker stop zap &>/dev/null
        docker rm zap &>/dev/null
        success "Tidigare Attack proxy-container borttagen"
    fi
    # Vänta tills Docker inte längre listar containern
    while docker ps -a --format '{{.Names}}' | grep -q '^zap$'; do
        sleep 0.2
    done
    docker pull ghcr.io/zaproxy/zaproxy:stable >/dev/null && success "Senaste Attack proxy-image nedladdad"
    # Starta en ny container
    if docker run -d -p 8080:8080 --name zap ghcr.io/zaproxy/zaproxy:stable \
        zap.sh -daemon -host 0.0.0.0 -port 8080 \
        -config api.key=wsaYdB64K4 \
        -config api.addrs.addr.name=.* \
        -config api.addrs.addr.regex=true \
        -config proxy.ip=0.0.0.0; then
        success "Attack proxy-container startad"
    else
        error "Misslyckades med att starta Attack proxy-container"
        exit 1
    fi

    echo "Väntar på att Attack proxy ska starta..."
    sleep 5

    if curl -s "http://localhost:8080/JSON/core/view/version/?apikey=wsaYdB64K4" > /dev/null; then
        success "Attack proxy API är tillgängligt"
    else
        warning "Attack proxy API svarar inte – det kan ta längre tid eller något är fel"
    fi
}

# Stoppa Attack proxy
stop_zap() {
    heading "Stoppar Attack proxy"

    if docker ps --format '{{.Names}}' | grep -q '^zap$'; then
        docker stop zap && success "Attack proxy stoppad" || error "Kunde inte stoppa Attack proxy"
    else
        warning "Attack proxy-container kör inte"
    fi
}

# Visa status
show_status() {
    heading "Status för Attack proxy"
    if docker ps --format '{{.Names}}' | grep -q '^zap$'; then
        success "Attack proxy kör"
        echo "  API: http://localhost:8080/"
        echo "  API-nyckel: wsaYdB64K4"
        echo "  Proxy: localhost:8090"
    else
        warning "Attack proxy är inte igång"
    fi
}

# Visa loggar
show_logs() {
    docker logs zap 2>/dev/null || echo "Containern 'zap' verkar inte vara igång."
}

# Rensa
clean() {
    heading "Rensar Attack proxy-container"
    if docker ps -a --format '{{.Names}}' | grep -q '^zap$'; then
        docker stop zap &>/dev/null
        docker rm zap && success "Attack proxy-container borttagen" || error "Kunde inte ta bort Attack proxy"
    else
        warning "Attack proxy-container finns inte"
    fi
}

# Hjälp
show_help() {
    echo "Användning: $0 [kommando]"
    echo ""
    echo "Kommandon:"
    echo "  start        Startar en ny Attack proxy-container"
    echo "  stop         Stoppar Attack proxy-container"
    echo "  restart      Startar om Attack proxy-container"
    echo "  status       Visar Attack proxy-status"
    echo "  logs         Visar loggar från Attack proxy"
    echo "  clean        Tar bort Attack proxy-container"
    echo "  help         Visar denna hjälp"
}

# Huvudfunktion
main() {
    case "$1" in
        start)
            start_zap
            show_status
            ;;
        stop)
            stop_zap
            ;;
        restart)
            stop_zap
            sleep 2
            start_zap
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            show_help
            ;;
    esac
}

main "$1"
