"""
Security Toolkit - Flask Web Application
Combines: FIM, Email/URL Checker (VirusTotal), Port Scanner
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import sys

__author__ = "Dan Grigorescu"
__version__ = "1.0.0"
__project__ = "Greuceanu_SOC"

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from fim import FIMScanner
from email_checker import EmailChecker
from port_scanner import PortScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'security-toolkit-2025'

# ─── MAIN ROUTES ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/fim')
def fim_page():
    return render_template('fim.html')

@app.route('/email-checker')
def email_checker_page():
    return render_template('email_checker.html')

@app.route('/port-scanner')
def port_scanner_page():
    return render_template('port_scanner.html')

# ─── FIM API ──────────────────────────────────────────────────────────────────

@app.route('/api/fim/scan', methods=['POST'])
def fim_scan():
    data = request.json
    directory = data.get('directory', '')
    if not directory or not os.path.isdir(directory):
        return jsonify({'error': 'Director invalid sau inexistent'}), 400
    scanner = FIMScanner(directory)
    result = scanner.create_baseline()
    return jsonify(result)

@app.route('/api/fim/check', methods=['POST'])
def fim_check():
    data = request.json
    directory = data.get('directory', '')
    if not directory or not os.path.isdir(directory):
        return jsonify({'error': 'Director invalid sau inexistent'}), 400
    scanner = FIMScanner(directory)
    result = scanner.check_integrity()
    return jsonify(result)

@app.route('/api/fim/report', methods=['POST'])
def fim_report():
    data = request.json
    directory = data.get('directory', '')
    scanner = FIMScanner(directory)
    report_path = scanner.export_report()
    return jsonify({'report_path': report_path})

# ─── EMAIL CHECKER API ────────────────────────────────────────────────────────

@app.route('/api/email/analyze', methods=['POST'])
def email_analyze():
    data = request.json
    text = data.get('text', '')
    api_key = data.get('api_key', '')
    if not text:
        return jsonify({'error': 'Nu ai introdus niciun text'}), 400
    checker = EmailChecker(api_key=api_key)
    result = checker.analyze(text)
    return jsonify(result)

# ─── PORT SCANNER API ─────────────────────────────────────────────────────────

@app.route('/api/portscan/scan', methods=['POST'])
def port_scan():
    data = request.json
    host = data.get('host', '')
    mode = data.get('mode', 'common')       # 'common' | 'range' | 'both'
    port_range = data.get('range', '1-1024')
    timeout = float(data.get('timeout', 0.5))

    if not host:
        return jsonify({'error': 'Host invalid'}), 400

    scanner = PortScanner(host, timeout=timeout)

    if mode == 'common':
        result = scanner.scan_common()
    elif mode == 'range':
        result = scanner.scan_range(port_range)
    else:
        result = scanner.scan_both(port_range)

    return jsonify(result)

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
