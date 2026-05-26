"""
Email / Text Checker Module
Extrage IP-uri, domenii si URL-uri din text folosind regex
Le trimite la VirusTotal API v3 si returneaza rezultatele
"""

import re
import time
import requests
from urllib.parse import urlparse
import base64


# ── Regex patterns ────────────────────────────────────────────────────────────

# IP v4
RE_IP = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# URL completa (http/https/ftp)
RE_URL = re.compile(
    r'https?://[^\s<>"\']+|ftp://[^\s<>"\']+',
    re.IGNORECASE
)

# Domeniu simplu (fara protocol) - ex: evil.com, sub.domain.co.uk
RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|ro|eu|gov|edu|co|uk|de|fr|ru|cn|info|biz|xyz|top|site|online|tk|ml|ga|cf|gq)\b',
    re.IGNORECASE
)

VIRUSTOTAL_BASE = 'https://www.virustotal.com/api/v3'


class EmailChecker:
    def __init__(self, api_key: str = ''):
        self.api_key = api_key.strip()
        self.headers = {'X-Developed-By': 'Dan Grigorescu - ETTI'}
        if self.api_key:
            self.headers['x-apikey'] = self.api_key

    # ── Extrage indicatori din text ───────────────────────────────────────────
    def extract_indicators(self, text: str) -> dict:
        """Extrage IP-uri, URL-uri si domenii din text folosind regex"""
        ips = list(set(RE_IP.findall(text)))
        urls = list(set(RE_URL.findall(text)))
        
        # Extrage domeniile din URL-uri
        domains_from_urls = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    domains_from_urls.add(parsed.hostname.lower())
            except Exception:
                pass

        # Domenii gasite direct in text (exclude cele din URL-uri deja capturate)
        raw_domains = set(d.lower() for d in RE_DOMAIN.findall(text))
        standalone_domains = raw_domains - domains_from_urls

        # Filtrare IP-uri private (nu le trimitem la VT)
        public_ips = [ip for ip in ips if not self._is_private_ip(ip)]
        private_ips = [ip for ip in ips if self._is_private_ip(ip)]

        return {
            'ips': {'public': public_ips, 'private': private_ips},
            'urls': urls,
            'domains': list(standalone_domains),
            'domains_from_urls': list(domains_from_urls)
        }

    def _is_private_ip(self, ip: str) -> bool:
        """Verifica daca un IP este privat/rezervat"""
        parts = list(map(int, ip.split('.')))
        return (
            parts[0] == 10 or
            (parts[0] == 172 and 16 <= parts[1] <= 31) or
            (parts[0] == 192 and parts[1] == 168) or
            parts[0] == 127 or
            parts[0] == 0
        )

    # ── VirusTotal API calls ──────────────────────────────────────────────────
    def _vt_ip(self, ip: str) -> dict:
        """Interogheaza VirusTotal pentru un IP"""
        if not self.api_key:
            return {'resource': ip, 'type': 'ip', 'error': 'No API key'}
        try:
            r = requests.get(f'{VIRUSTOTAL_BASE}/ip_addresses/{ip}', headers=self.headers, timeout=10)
            if r.status_code == 200:
                data = r.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'resource': ip, 'type': 'ip',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'country': data.get('country', 'N/A'),
                    'owner': data.get('as_owner', 'N/A'),
                    'reputation': data.get('reputation', 0),
                    'vt_link': f'https://www.virustotal.com/gui/ip-address/{ip}'
                }
            elif r.status_code == 401:
                return {'resource': ip, 'type': 'ip', 'error': 'API key invalid'}
            elif r.status_code == 429:
                return {'resource': ip, 'type': 'ip', 'error': 'Rate limit atins (4 req/min free tier)'}
            else:
                return {'resource': ip, 'type': 'ip', 'error': f'HTTP {r.status_code}'}
        except requests.RequestException as e:
            return {'resource': ip, 'type': 'ip', 'error': str(e)}

    def _vt_domain(self, domain: str) -> dict:
        """Interogheaza VirusTotal pentru un domeniu"""
        if not self.api_key:
            return {'resource': domain, 'type': 'domain', 'error': 'No API key'}
        try:
            r = requests.get(f'{VIRUSTOTAL_BASE}/domains/{domain}', headers=self.headers, timeout=10)
            if r.status_code == 200:
                data = r.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'resource': domain, 'type': 'domain',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'reputation': data.get('reputation', 0),
                    'categories': list(data.get('categories', {}).values())[:3],
                    'vt_link': f'https://www.virustotal.com/gui/domain/{domain}'
                }
            elif r.status_code == 401:
                return {'resource': domain, 'type': 'domain', 'error': 'API key invalid'}
            elif r.status_code == 429:
                return {'resource': domain, 'type': 'domain', 'error': 'Rate limit atins'}
            else:
                return {'resource': domain, 'type': 'domain', 'error': f'HTTP {r.status_code}'}
        except requests.RequestException as e:
            return {'resource': domain, 'type': 'domain', 'error': str(e)}

    def _vt_url(self, url: str) -> dict:
        """Interogheaza VirusTotal pentru o URL (necesita encoding base64)"""
        if not self.api_key:
            return {'resource': url, 'type': 'url', 'error': 'No API key'}
        try:
            # VT API v3 cere URL-ul encodat base64 fara padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
            r = requests.get(f'{VIRUSTOTAL_BASE}/urls/{url_id}', headers=self.headers, timeout=10)
            if r.status_code == 200:
                data = r.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'resource': url, 'type': 'url',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'reputation': data.get('reputation', 0),
                    'vt_link': f'https://www.virustotal.com/gui/url/{url_id}'
                }
            elif r.status_code == 404:
                # URL nu e in baza VT, il submittem
                return self._submit_url(url)
            elif r.status_code == 401:
                return {'resource': url, 'type': 'url', 'error': 'API key invalid'}
            elif r.status_code == 429:
                return {'resource': url, 'type': 'url', 'error': 'Rate limit atins'}
            else:
                return {'resource': url, 'type': 'url', 'error': f'HTTP {r.status_code}'}
        except requests.RequestException as e:
            return {'resource': url, 'type': 'url', 'error': str(e)}

    def _submit_url(self, url: str) -> dict:
        """Submite un URL nou la VirusTotal pentru analiza"""
        try:
            r = requests.post(
                f'{VIRUSTOTAL_BASE}/urls',
                headers=self.headers,
                data={'url': url},
                timeout=10
            )
            if r.status_code == 200:
                return {'resource': url, 'type': 'url', 'status': 'submitted', 'message': 'URL trimis la VirusTotal pentru analiza. Incearca din nou in cateva minute.'}
            return {'resource': url, 'type': 'url', 'error': f'Submit failed: HTTP {r.status_code}'}
        except requests.RequestException as e:
            return {'resource': url, 'type': 'url', 'error': str(e)}

    # ── Analiza completa ──────────────────────────────────────────────────────
    def analyze(self, text: str) -> dict:
        """Extrage indicatorii din text si ii verifica pe VirusTotal"""
        indicators = self.extract_indicators(text)
        results = []
        
        has_key = bool(self.api_key)
        delay = 16  # 4 req/min pe free tier = 15s intre requesturi

        all_to_check = []
        for ip in indicators['ips']['public'][:5]:   # max 5 IP-uri
            all_to_check.append(('ip', ip))
        for domain in (indicators['domains'] + indicators['domains_from_urls'])[:5]:
            all_to_check.append(('domain', domain))
        for url in indicators['urls'][:3]:            # max 3 URL-uri
            all_to_check.append(('url', url))

        for i, (kind, resource) in enumerate(all_to_check):
            if kind == 'ip':
                res = self._vt_ip(resource)
            elif kind == 'domain':
                res = self._vt_domain(resource)
            else:
                res = self._vt_url(resource)

            results.append(res)

            # Rate limiting pentru free tier
            if has_key and i < len(all_to_check) - 1:
                time.sleep(delay)

        # Calculeaza scor de risc global
        total_malicious = sum(r.get('malicious', 0) for r in results)
        risk_level = 'LOW'
        if total_malicious > 0:
            risk_level = 'MEDIUM'
        if total_malicious >= 3:
            risk_level = 'HIGH'
        if total_malicious >= 10:
            risk_level = 'CRITICAL'

        return {
            'indicators_found': {
                'public_ips': indicators['ips']['public'],
                'private_ips': indicators['ips']['private'],
                'domains': indicators['domains'] + indicators['domains_from_urls'],
                'urls': indicators['urls']
            },
            'vt_results': results,
            'risk_level': risk_level,
            'total_malicious_detections': total_malicious,
            'api_key_provided': has_key
        }
