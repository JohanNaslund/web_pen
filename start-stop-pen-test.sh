#!/bin/bash

# ANSI färgkoder för bättre läsbarhet
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Rubriker
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

# Funktion för att kontrollera om en Docker-container finns och är igång
check_container() {
    local container_name=$1
    
    # Kontrollera om containern finns
    if [[ $(docker ps -a -q -f name=$container_name) ]]; then
        # Kontrollera om containern är igång
        if [[ $(docker ps -q -f name=$container_name) ]]; then
            return 0 # Container exists and is running
        else
            return 1 # Container exists but is not running
        fi
    else
        return 2 # Container does not exist
    fi
}

# Funktion för att starta ZAP
start_zap() {
    heading "Starta OWASP ZAP"
    
    check_container "zap"
    local zap_status=$?
    
    if [[ $zap_status -eq 0 ]]; then
        success "ZAP-containern är redan igång"
    elif [[ $zap_status -eq 1 ]]; then
        echo "ZAP-containern finns men är stoppad. Startar..."
        if docker start zap; then
            success "ZAP-containern startad"
        else
            error "Kunde inte starta ZAP-containern"
        fi
    else
        echo "ZAP-containern existerar inte. Skapar ny..."
        if docker run -d -p 8080:8080 --name zap ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=changeme123 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config proxy.ip=0.0.0.0; then
            success "ZAP-containern skapad och startad"
        else
            error "Kunde inte skapa ZAP-containern"
        fi
    fi
    
    echo "Väntar på att ZAP ska starta fullständigt..."
    sleep 5
    
    # Kontrollera om ZAP API är tillgängligt
    if curl -s "http://localhost:8080/JSON/core/view/version/?apikey=changeme123" > /dev/null; then
        success "ZAP API är tillgängligt"
    else
        warning "ZAP API svarar inte. Det kan ta längre tid att starta, eller så kan något vara fel"
    fi
}

# Funktion för att starta SQLMap - Uppdaterad med bättre image
start_sqlmap() {
    heading "Starta SQLMap"
    
    check_container "sqlmap"
    local sqlmap_status=$?
    
    if [[ $sqlmap_status -eq 0 ]]; then
        success "SQLMap-containern är redan igång"
    elif [[ $sqlmap_status -eq 1 ]]; then
        echo "SQLMap-containern finns men är stoppad. Startar..."
        if docker start sqlmap; then
            success "SQLMap-containern startad"
        else
            error "Kunde inte starta SQLMap-containern"
        fi
    else
        echo "SQLMap-containern existerar inte. Skapar ny..."
        
        # Skapa en Dockerfile för SQLMap om den inte finns
        if [ ! -f "sqlmap-dockerfile/Dockerfile" ]; then
            mkdir -p sqlmap-dockerfile
            cat > sqlmap-dockerfile/Dockerfile <<EOF
FROM python:3.9-slim

RUN apt-get update && \
    apt-get install -y git && \
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /sqlmap && \
    apt-get remove -y git && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /sqlmap

EXPOSE 8775

CMD ["python3", "-m", "sqlmapapi", "-s", "-H", "0.0.0.0"]
EOF
            success "Dockerfile för SQLMap skapad"
        fi
        
        # Bygg SQLMap image
        echo "Bygger SQLMap image..."
        if docker build -t local-sqlmap sqlmap-dockerfile/; then
            success "SQLMap image byggd"
            
            # Skapa och starta containern
            echo "Skapar och startar SQLMap-containern..."
            if docker run -d -p 8775:8775 --name sqlmap local-sqlmap; then
                success "SQLMap-containern skapad och startad"
            else
                error "Kunde inte skapa SQLMap-containern"
            fi
        else
            error "Kunde inte bygga SQLMap-imagen"
            
            # Fallback till direct volume mapping
            echo "Försöker alternativ metod med officiell Python-image..."
            if docker run -d -p 8775:8775 --name sqlmap python:3.9-slim bash -c "apt-get update && apt-get install -y git && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /sqlmap && cd /sqlmap && python -m sqlmap.sqlmapapi -s -H 0.0.0.0"; then
                success "SQLMap-containern skapad och startad med alternativ metod"
            else
                error "Båda försöken att skapa SQLMap-containern misslyckades"
                return 1
            fi
        fi
    fi
    
    echo "Väntar på att SQLMap ska starta fullständigt..."
    sleep 3
    
    # Kontrollera om SQLMap API är tillgängligt
    if curl -s "http://localhost:8775" > /dev/null; then
        success "SQLMap API är tillgängligt"
    else
        warning "SQLMap API svarar inte. Det kan ta längre tid att starta, eller så kan något vara fel"
        
        # Visa loggarna för felsökning
        echo "Visar SQLMap-containerns loggar för felsökning:"
        docker logs sqlmap
    fi
}

# Funktion för att stoppa ZAP
stop_zap() {
    heading "Stoppa OWASP ZAP"
    
    check_container "zap"
    local zap_status=$?
    
    if [[ $zap_status -eq 0 ]]; then
        echo "Stoppar ZAP-containern..."
        if docker stop zap; then
            success "ZAP-containern stoppad"
        else
            error "Kunde inte stoppa ZAP-containern"
        fi
    elif [[ $zap_status -eq 1 ]]; then
        success "ZAP-containern är redan stoppad"
    else
        warning "ZAP-containern existerar inte"
    fi
}

# Funktion för att stoppa SQLMap
stop_sqlmap() {
    heading "Stoppa SQLMap"
    
    check_container "sqlmap"
    local sqlmap_status=$?
    
    if [[ $sqlmap_status -eq 0 ]]; then
        echo "Stoppar SQLMap-containern..."
        if docker stop sqlmap; then
            success "SQLMap-containern stoppad"
        else
            error "Kunde inte stoppa SQLMap-containern"
        fi
    elif [[ $sqlmap_status -eq 1 ]]; then
        success "SQLMap-containern är redan stoppad"
    else
        warning "SQLMap-containern existerar inte"
    fi
}

# Funktion för att visa status
show_status() {
    heading "Status för PEN-testtjänster"
    
    # Kontrollera ZAP-status
    check_container "zap"
    local zap_status=$?
    
    echo -n "OWASP ZAP: "
    if [[ $zap_status -eq 0 ]]; then
        success "Igång"
        echo "  API URL: http://localhost:8080/"
        echo "  API-nyckel: changeme123"
        echo "  Proxy: localhost:8090"
    elif [[ $zap_status -eq 1 ]]; then
        warning "Stoppad"
    else
        error "Existerar inte"
    fi
    
    # Kontrollera SQLMap-status
    check_container "sqlmap"
    local sqlmap_status=$?
    
    echo -n "SQLMap: "
    if [[ $sqlmap_status -eq 0 ]]; then
        success "Igång"
        echo "  API URL: http://localhost:8775/"
    elif [[ $sqlmap_status -eq 1 ]]; then
        warning "Stoppad"
    else
        error "Existerar inte"
    fi
    
    # Visa hur man kör Flask-appen
    echo ""
    heading "Hur man kör Flask-appen"
    echo "1. Aktivera din Python-miljö (om du använder venv)"
    echo "   source venv/bin/activate"
    echo ""
    echo "2. Kör Flask-appen"
    echo "   python app.py"
    echo "   eller"
    echo "   flask run"
    echo ""
    echo "3. Besök webb-appen på http://localhost:5000"
}

# Funktion för att visa loggarna
show_logs() {
    local service=$1
    if [ "$service" == "zap" ]; then
        heading "OWASP ZAP loggar"
        check_container "zap"
        if [[ $? -eq 0 ]]; then
            docker logs zap
        else
            error "ZAP-containern är inte igång"
        fi
    elif [ "$service" == "sqlmap" ]; then
        heading "SQLMap loggar"
        check_container "sqlmap"
        if [[ $? -eq 0 ]]; then
            docker logs sqlmap
        else
            error "SQLMap-containern är inte igång"
        fi
    else
        error "Ogiltig tjänst. Använd 'zap' eller 'sqlmap'"
    fi
}

# Funktion för att ta bort containrarna
clean() {
    heading "Ta bort Docker-containrar"
    
    # Stoppa och ta bort ZAP
    check_container "zap"
    if [[ $? -ne 2 ]]; then
        echo "Tar bort ZAP-containern..."
        docker stop zap 2>/dev/null
        if docker rm zap; then
            success "ZAP-containern borttagen"
        else
            error "Kunde inte ta bort ZAP-containern"
        fi
    else
        warning "ZAP-containern existerar inte"
    fi
    
    # Stoppa och ta bort SQLMap
    check_container "sqlmap"
    if [[ $? -ne 2 ]]; then
        echo "Tar bort SQLMap-containern..."
        docker stop sqlmap 2>/dev/null
        if docker rm sqlmap; then
            success "SQLMap-containern borttagen"
        else
            error "Kunde inte ta bort SQLMap-containern"
        fi
    else
        warning "SQLMap-containern existerar inte"
    fi
    
    # Ta bort SQLMap-imagen om den finns
    if docker images | grep -q local-sqlmap; then
        echo "Tar bort lokal SQLMap-image..."
        if docker rmi local-sqlmap; then
            success "Lokal SQLMap-image borttagen"
        else
            error "Kunde inte ta bort lokal SQLMap-image"
        fi
    fi
}

# Funktion för att skapa docker-compose.yml
create_compose() {
    heading "Skapar docker-compose.yml"
    
    if [ -f "docker-compose.yml" ]; then
        warning "docker-compose.yml existerar redan. Vill du skriva över den? (y/n)"
        read -r answer
        if [[ ! "$answer" =~ ^[Yy]$ ]]; then
            warning "Avbryter"
            return
        fi
    fi
    
    cat > docker-compose.yml <<EOF
version: '3'

services:
  zap:
    image: ghcr.io/zaproxy/zaproxy:stable
    container_name: zap
    ports:
      - "8080:8080"
      - "8090:8090"
    volumes:
      - ./data/zap:/zap/wrk
    command: >
      zap.sh -daemon -host 0.0.0.0 -port 8080 
      -config api.key=changeme123 
      -config api.addrs.addr.name=.* 
      -config api.addrs.addr.regex=true 
      -config proxy.ip=0.0.0.0 
      -config proxy.port=8090
      -config connection.timeoutInSecs=60
    restart: unless-stopped

  sqlmap:
    build:
      context: ./sqlmap-dockerfile
    container_name: sqlmap
    ports:
      - "8775:8775"
    restart: unless-stopped

  # Avkommenteras om du vill köra Flask-appen i Docker
  # flask-app:
  #   build: 
  #     context: ./app
  #   container_name: flask-app
  #   ports:
  #     - "5000:5000"
  #   environment:
  #     - FLASK_APP=app.py
  #     - FLASK_ENV=development
  #     - ZAP_HOST=zap
  #     - ZAP_PORT=8080
  #     - SQLMAP_HOST=sqlmap
  #     - SQLMAP_PORT=8775
  #   volumes:
  #     - ./app:/app
  #     - ./data:/data
  #   depends_on:
  #     - zap
  #     - sqlmap
EOF
    
    # Skapa SQLMap Dockerfile
    mkdir -p sqlmap-dockerfile
    cat > sqlmap-dockerfile/Dockerfile <<EOF
FROM python:3.9-slim

RUN apt-get update && \
    apt-get install -y git && \
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /sqlmap && \
    apt-get remove -y git && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /sqlmap

EXPOSE 8775

CMD ["python3", "-m", "sqlmap.sqlmapapi", "-s", "-H", "0.0.0.0"]
EOF
    
    success "docker-compose.yml och Dockerfile för SQLMap har skapats"
    echo "Du kan nu köra 'docker-compose up -d' för att starta tjänsterna"
}

# Visa hjälp
show_help() {
    echo "Användning: $0 [kommando]"
    echo ""
    echo "Kommandon:"
    echo "  start       Starta ZAP och SQLMap"
    echo "  stop        Stoppa ZAP och SQLMap"
    echo "  restart     Starta om ZAP och SQLMap"
    echo "  status      Visa status för tjänsterna"
    echo "  logs [service]  Visa loggar för en tjänst (zap eller sqlmap)"
    echo "  clean       Ta bort Docker-containrarna"
    echo "  compose     Skapa docker-compose.yml fil"
    echo "  zap-start   Starta endast ZAP"
    echo "  zap-stop    Stoppa endast ZAP"
    echo "  sqlmap-start  Starta endast SQLMap"
    echo "  sqlmap-stop   Stoppa endast SQLMap"
    echo "  help        Visa denna hjälptext"
    echo ""
}

# Huvudfunktion
main() {
    case "$1" in
        start)
            start_zap
            start_sqlmap
            show_status
            ;;
        stop)
            stop_zap
            stop_sqlmap
            show_status
            ;;
        restart)
            stop_zap
            stop_sqlmap
            sleep 2
            start_zap
            start_sqlmap
            show_status
            ;;
        status)
            show_status
            ;;
        logs)
            if [ -z "$2" ]; then
                error "Ange vilken tjänst du vill se loggar för (zap eller sqlmap)"
                echo "Exempel: $0 logs zap"
            else
                show_logs "$2"
            fi
            ;;
        clean)
            clean
            ;;
        compose)
            create_compose
            ;;
        zap-start)
            start_zap
            show_status
            ;;
        zap-stop)
            stop_zap
            show_status
            ;;
        sqlmap-start)
            start_sqlmap
            show_status
            ;;
        sqlmap-stop)
            stop_sqlmap
            show_status
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            show_help
            ;;
    esac
}

# Kör huvudfunktionen med argumentet
main "$1" "$2"
