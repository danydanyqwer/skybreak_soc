"""
Port Scanner Module
Scaneaza porturile unui host folosind socket Python + subprocess (nmap daca e disponibil)
Include modul de lookup CVE via NIST NVD API.
"""

import socket
import subprocess
import concurrent.futures
import datetime
import time
import requests

COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 514, 515,
    587, 631, 636, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2082,
    2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 3000, 3306, 3389,
    3690, 4000, 4444, 4848, 5000, 5432, 5900, 5985, 6000, 6379, 6443,
    7000, 7080, 7443, 8000, 8008, 8080, 8088, 8443, 8888, 9000, 9090,
    9200, 9300, 9418, 9443, 10000, 11211, 27017, 27018, 27019, 28017,
    50000, 50070, 50075, 61616
]

SERVICE_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    67: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
    119: 'NNTP', 123: 'NTP', 135: 'MS-RPC', 137: 'NetBIOS', 139: 'SMB',
    143: 'IMAP', 161: 'SNMP', 179: 'BGP', 389: 'LDAP', 443: 'HTTPS',
    445: 'SMB/CIFS', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP-TLS',
    636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS',
    1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS',
    2375: 'Docker', 2376: 'Docker-TLS', 3000: 'Dev-Server',
    3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit', 5000: 'Flask/UPnP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 6443: 'K8s-API',
    8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
    8888: 'Jupyter', 9000: 'SonarQube', 9200: 'Elasticsearch',
    9300: 'Elasticsearch-Cluster', 27017: 'MongoDB', 50000: 'DB2'
}

HIGH_RISK_PORTS = {21, 23, 135, 137, 138, 139, 445, 1433, 1521, 3389, 4444, 5900, 27017, 6379}
MEDIUM_RISK_PORTS = {22, 25, 53, 80, 110, 143, 2375, 2376, 3306, 5432, 8080, 9200}

class PortScanner:
    def __init__(self, host: str, timeout: float = 0.5):
        self.host = host
        self.timeout = timeout
        self.ip = None

    def _resolve_host(self) -> str:
        try:
            ip = socket.gethostbyname(self.host)
            self.ip = ip
            return ip
        except socket.gaierror:
            return None

    def _lookup_cve(self, service: str) -> list:
        """Interoghează baza de date NIST NVD pentru vulnerabilități cunoscute"""
        if service in ['Unknown', 'HTTP-Alt', 'HTTPS-Alt']:
            return []
            
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}&resultsPerPage=2"
            r = requests.get(url, timeout=3)
            
            if r.status_code == 200:
                data = r.json()
                vulnerabilities = data.get('vulnerabilities', [])
                cves = []
                
                for v in vulnerabilities:
                    cve_item = v.get('cve', {})
                    cve_id = cve_item.get('id', 'N/A')
                    
                    metrics = cve_item.get('metrics', {})
                    score = "N/A"
                    if 'cvssMetricV31' in metrics:
                        score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 'N/A')
                        
                    cves.append({"id": cve_id, "score": score})
                    
                return cves
        except Exception:
            pass
            
        return []

    def _scan_port(self, port: int) -> dict | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.host, port))
            s.close()
            if result == 0:
                service = SERVICE_NAMES.get(port, 'Unknown')
                risk = 'HIGH' if port in HIGH_RISK_PORTS else ('MEDIUM' if port in MEDIUM_RISK_PORTS else 'LOW')
                
                # Fetch CVEs dynamically
                cves = self._lookup_cve(service)
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'risk': risk,
                    'protocol': 'tcp',
                    'cves': cves
                }
        except (socket.error, OSError):
            pass
        return None

    def _nmap_scan(self, ports: list) -> list:
        port_str = ','.join(map(str, ports[:100]))
        try:
            cmd = ['nmap', '-sV', '--open', '-p', port_str, '-T4', self.host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return self._parse_nmap_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return []

    def _parse_nmap_output(self, output: str) -> list:
        open_ports = []
        for line in output.splitlines():
            line = line.strip()
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = int(parts[0].split('/')[0])
                    service = parts[2] if len(parts) > 2 else SERVICE_NAMES.get(port, 'Unknown')
                    risk = 'HIGH' if port in HIGH_RISK_PORTS else ('MEDIUM' if port in MEDIUM_RISK_PORTS else 'LOW')
                    
                    cves = self._lookup_cve(service)
                    
                    open_ports.append({
                        'port': port, 'state': 'open',
                        'service': service, 'risk': risk,
                        'protocol': 'tcp', 'source': 'nmap',
                        'cves': cves
                    })
        return open_ports

    def _scan_ports_parallel(self, ports: list) -> list:
        open_ports = []
        max_workers = min(100, len(ports))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._scan_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        return sorted(open_ports, key=lambda x: x['port'])

    def _build_result(self, open_ports: list, scanned_count: int, mode: str, duration: float) -> dict:
        high = [p for p in open_ports if p['risk'] == 'HIGH']
        medium = [p for p in open_ports if p['risk'] == 'MEDIUM']
        low = [p for p in open_ports if p['risk'] == 'LOW']

        overall_risk = 'LOW'
        if medium:
            overall_risk = 'MEDIUM'
        if high:
            overall_risk = 'HIGH'

        return {
            'host': self.host,
            'ip': self.ip or self.host,
            'scan_mode': mode,
            'scanned_at': datetime.datetime.now().isoformat(),
            'duration_seconds': round(duration, 2),
            'ports_scanned': scanned_count,
            'open_ports_count': len(open_ports),
            'overall_risk': overall_risk,
            'summary': {
                'high_risk': len(high),
                'medium_risk': len(medium),
                'low_risk': len(low)
            },
            'open_ports': open_ports
        }

    def scan_common(self) -> dict:
        ip = self._resolve_host()
        if not ip: return {'error': f'Nu pot rezolva host-ul: {self.host}'}
        start = time.time()
        open_ports = self._scan_ports_parallel(COMMON_PORTS)
        duration = time.time() - start
        return self._build_result(open_ports, len(COMMON_PORTS), 'common_ports', duration)

    def scan_range(self, port_range: str) -> dict:
        ip = self._resolve_host()
        if not ip: return {'error': f'Nu pot rezolva host-ul: {self.host}'}
        ports = []
        try:
            if '-' in port_range and ',' not in port_range:
                start_p, end_p = map(int, port_range.split('-'))
                ports = list(range(start_p, min(end_p + 1, 65536)))
            else:
                ports = [int(p.strip()) for p in port_range.split(',') if p.strip().isdigit()]
        except ValueError:
            return {'error': f'Range invalid: {port_range}. Foloseste formatul 1-1024 sau 80,443,8080'}

        if not ports: return {'error': 'Nu s-au putut extrage porturi din range-ul specificat'}
        if len(ports) > 10000: return {'error': 'Range prea mare (max 10000 porturi)'}

        start = time.time()
        open_ports = self._scan_ports_parallel(ports)
        duration = time.time() - start
        return self._build_result(open_ports, len(ports), f'range:{port_range}', duration)

    def scan_both(self, port_range: str) -> dict:
        ip = self._resolve_host()
        if not ip: return {'error': f'Nu pot rezolva host-ul: {self.host}'}
        range_ports = []
        try:
            if '-' in port_range and ',' not in port_range:
                start_p, end_p = map(int, port_range.split('-'))
                range_ports = list(range(start_p, min(end_p + 1, 65536)))
            else:
                range_ports = [int(p.strip()) for p in port_range.split(',') if p.strip().isdigit()]
        except ValueError:
            range_ports = []

        all_ports = sorted(set(COMMON_PORTS + range_ports))
        if len(all_ports) > 15000: all_ports = all_ports[:15000]

        start = time.time()
        open_ports = self._scan_ports_parallel(all_ports)
        duration = time.time() - start
        return self._build_result(open_ports, len(all_ports), f'common+range:{port_range}', duration)