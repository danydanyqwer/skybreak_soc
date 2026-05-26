#!/bin/bash

# Security Toolkit - Environment Setup Script
# Automatizează instalarea dependențelor de Linux și Python

echo "[*] Inițializare setup Security Toolkit..."

# 1. Update și instalare pachete native de Linux (necesită parolă de sudo)
echo "[*] Verificare și instalare utilitare Linux (nmap, python3-venv)..."
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nmap

# 2. Creare Virtual Environment (izolare mediu Python)
echo "[*] Configurare mediu virtual Python (venv)..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "[+] Virtual environment creat cu succes."
else
    echo "[!] Virtual environment deja existent. Trecem mai departe."
fi

# 3. Activare venv
source venv/bin/activate

# 4. Instalare pachete Python
echo "[*] Instalare dependențe Python (Flask, requests)..."
pip install --upgrade pip
pip install flask requests

# 5. Configurare structură directoare pentru FIM
echo "[*] Configurare structură directoare..."
mkdir -p reports

# 6. Pornire aplicație
echo "[*] Setup complet! Pornire server Flask pe portul 5000..."
python3 app.py