"""
File Integrity Monitor (FIM) Module
Foloseste sha256sum (Linux CLI) + hashlib Python pentru redundanta
Stocheaza baseline in JSON, detecteaza modificari.
Include alerte automate via Telegram.
"""

import os
import json
import hashlib
import subprocess
import datetime
import csv
import requests
from pathlib import Path

BASELINE_FILE = os.path.join(os.path.dirname(__file__), '..', 'reports', 'fim_baseline.json')
REPORT_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports')

class FIMScanner:
    def __init__(self, directory: str):
        self.directory = os.path.abspath(directory)
        self.baseline_path = BASELINE_FILE
        
        # --- CONFIGURARE TELEGRAM ---
        self.telegram_token = "x"
        self.telegram_chat_id = "x"

    def _send_telegram_alert(self, added: int, deleted: int, modified: int):
        """Trimite o alertă pe Telegram dacă găsește modificări"""
        if not self.telegram_token or self.telegram_token == "LIPEȘTE_AICI_TOKEN_UL_BOTULUI":
            return
            
        message = "🚨 *ALARMĂ DE SECURITATE (F.I.M)* 🚨\n\n"
        message += f"S-au detectat modificări neautorizate în directorul:\n`{self.directory}`\n\n"
        message += "*Sumar:*\n"
        message += f"🟢 Adăugate: {added}\n"
        message += f"🔴 Șterse: {deleted}\n"
        message += f"🟡 Modificate: {modified}\n\n"
        message += "_Recomandare: Verificați imediat integritatea sistemului!_"

        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception:
            pass # Trecem silențios peste eroare ca să nu blocăm aplicația

    def _hash_python(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, PermissionError):
            return 'ACCESS_DENIED'

    def _hash_linux(self, filepath: str) -> str:
        try:
            result = subprocess.run(
                ['sha256sum', filepath],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.split()[0]
            return 'ERROR'
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return self._hash_python(filepath)

    def _get_file_info(self, filepath: str) -> dict:
        try:
            stat = os.stat(filepath)
            return {
                'size_bytes': stat.st_size,
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:]
            }
        except OSError:
            return {'size_bytes': 0, 'modified': 'N/A', 'permissions': 'N/A'}

    def _list_files_linux(self) -> list:
        try:
            result = subprocess.run(
                ['find', self.directory, '-type', 'f'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
                return files
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        files = []
        for root, _, filenames in os.walk(self.directory):
            for fname in filenames:
                files.append(os.path.join(root, fname))
        return files

    def create_baseline(self) -> dict:
        files = self._list_files_linux()
        baseline = {
            'directory': self.directory,
            'created_at': datetime.datetime.now().isoformat(),
            'files': {}
        }

        for filepath in files:
            hash_val = self._hash_linux(filepath)
            info = self._get_file_info(filepath)
            baseline['files'][filepath] = {
                'sha256': hash_val,
                **info
            }

        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
        with open(self.baseline_path, 'w') as f:
            json.dump(baseline, f, indent=2)

        return {
            'status': 'baseline_created',
            'directory': self.directory,
            'files_scanned': len(baseline['files']),
            'timestamp': baseline['created_at'],
            'files': baseline['files']
        }

    def check_integrity(self) -> dict:
        if not os.path.exists(self.baseline_path):
            return {'status': 'no_baseline', 'message': 'Nu exista baseline. Creeaza-l mai intai.'}

        with open(self.baseline_path, 'r') as f:
            baseline = json.load(f)

        if baseline.get('directory') != self.directory:
            return {'status': 'error', 'message': 'Baseline-ul e pentru un alt director.'}

        current_files = self._list_files_linux()
        baseline_files = set(baseline['files'].keys())
        current_set = set(current_files)

        added = list(current_set - baseline_files)
        deleted = list(baseline_files - current_set)
        modified = []
        unchanged = []

        for filepath in current_set & baseline_files:
            current_hash = self._hash_linux(filepath)
            saved_hash = baseline['files'][filepath]['sha256']
            info = self._get_file_info(filepath)
            if current_hash != saved_hash:
                modified.append({
                    'path': filepath,
                    'old_hash': saved_hash,
                    'new_hash': current_hash,
                    **info
                })
            else:
                unchanged.append(filepath)

        total_issues = len(added) + len(deleted) + len(modified)
        
        # Declanșare alertă Telegram
        if total_issues > 0:
            self._send_telegram_alert(len(added), len(deleted), len(modified))

        return {
            'status': 'alert' if total_issues > 0 else 'clean',
            'checked_at': datetime.datetime.now().isoformat(),
            'baseline_created': baseline['created_at'],
            'summary': {
                'added': len(added),
                'deleted': len(deleted),
                'modified': len(modified),
                'unchanged': len(unchanged),
                'total_issues': total_issues
            },
            'added': added,
            'deleted': deleted,
            'modified': modified
        }

    def export_report(self) -> str:
        result = self.check_integrity()
        os.makedirs(REPORT_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(REPORT_DIR, f'fim_report_{ts}.csv')

        with open(report_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Status', 'Filepath', 'Detail', 'Timestamp'])
            for f in result.get('added', []):
                writer.writerow(['ADDED', f, '', result['checked_at']])
            for f in result.get('deleted', []):
                writer.writerow(['DELETED', f, '', result['checked_at']])
            for f in result.get('modified', []):
                writer.writerow(['MODIFIED', f['path'], f'Hash: {f["old_hash"][:16]}...->{f["new_hash"][:16]}...', result['checked_at']])

        return report_path