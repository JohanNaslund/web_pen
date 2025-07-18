#!/bin/bash

# Test script för IP-discovery

echo "🔍 Testar IP-upptäckt på Ubuntu host..."

echo ""
echo "📋 Metod 1: ip route get 8.8.8.8"
ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || echo "Misslyckades"

echo ""
echo "📋 Metod 2: hostname -I (filtrerad)"
hostname -I | awk '{for(i=1;i<=NF;i++) if($i!="127.0.0.1" && $i!~/^172\./ && $i!~/^169\.254\./) {print $i; exit}}'

echo ""
echo "📋 Metod 3: ip addr show (filtrerad)"
ip addr show | grep 'inet ' | grep -v '127.0.0.1' | grep -v '172.1[7-9].' | grep -v '172.2[0-9].' | head -1 | awk '{print $2}' | cut -d'/' -f1

echo ""
echo "📋 Alla nätverksgränssnitt:"
ip addr show | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1

echo ""
echo "🌐 Förväntat resultat: 192.168.2.110"

echo ""
echo "🔧 Om IP-upptäckt inte fungerar, sätt manuellt:"
echo "   export HOST_IP=192.168.2.110"
echo "   export EXTERNAL_IP=192.168.2.110"
echo "   ./start.sh"