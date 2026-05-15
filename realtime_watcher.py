"""
Real-time File Watcher - Uses inotify to detect file changes instantly.
Supports: auto-quarantine, upload hook scanning, instant alerts.
"""
import os, json, time, threading, hashlib, shutil, re

try:
    import inotify.adapters
    HAS_INOTIFY = True
except ImportError:
    HAS_INOTIFY = False

class RealtimeWatcher:
    __config_path = '/www/server/panel/plugin/malwarescan/watcher_config.json'
    __log_path = '/www/server/panel/plugin/malwarescan/logs/watcher.log'
    __quarantine_path = '/www/server/panel/plugin/malwarescan/quarantine'
    __pid_file = '/www/server/panel/plugin/malwarescan/watcher.pid'

    __dangerous_extensions = {'.php', '.phtml', '.php5', '.php7', '.phar', '.pht'}
    __quick_signatures = [
        (r'eval\s*\(\s*(\$_(GET|POST|REQUEST)|base64_decode)', 'eval with input/decode'),
        (r'(system|exec|passthru|shell_exec)\s*\(\s*\$_(GET|POST|REQUEST)', 'command execution'),
        (r'(c99|r57|b374k|wso|alfa)\s*shell', 'known webshell'),
        (r'move_uploaded_file\s*\(.+\$_(GET|POST|REQUEST)', 'upload backdoor'),
        (r'file_put_contents\s*\(\s*\$_(GET|POST|REQUEST)', 'arbitrary file write'),
    ]

    def __init__(self):
        self.config = self._load_config()
        self._running = False
        self._thread = None

    def _load_config(self):
        if os.path.exists(self.__config_path):
            try:
                return json.loads(open(self.__config_path).read())
            except Exception:
                pass
        return {
            'enabled': False,
            'watch_paths': [],
            'auto_quarantine': False,
            'scan_uploads': True,
            'alert_webhook': '',
            'alert_email': '',
            'events': []
        }

    def _save_config(self):
        with open(self.__config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def _log(self, msg, level='info'):
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        line = f"[{ts}] [{level.upper()}] {msg}\n"
        try:
            with open(self.__log_path, 'a') as f:
                f.write(line)
        except Exception:
            pass

    def _quick_scan(self, filepath):
        """Fast regex scan for critical threats only"""
        try:
            if os.path.getsize(filepath) > 2 * 1024 * 1024:
                return None
            content = open(filepath, 'r', errors='ignore').read()
            for pattern, desc in self.__quick_signatures:
                if re.search(pattern, content, re.IGNORECASE):
                    return desc
        except Exception:
            pass
        return None

    def _quarantine_file(self, filepath, reason):
        """Auto-quarantine a detected threat"""
        try:
            filename = os.path.basename(filepath)
            dest = os.path.join(self.__quarantine_path, f"{int(time.time())}_{filename}.quarantined")
            meta = {
                'original_path': filepath,
                'quarantined_at': int(time.time()),
                'reason': reason,
                'auto': True,
                'size': os.path.getsize(filepath),
                'md5': hashlib.md5(open(filepath, 'rb').read()).hexdigest()
            }
            shutil.move(filepath, dest)
            with open(dest + '.meta', 'w') as f:
                json.dump(meta, f)
            self._log(f"AUTO-QUARANTINED: {filepath} ({reason})", 'critical')
            return True
        except Exception as e:
            self._log(f"Quarantine failed: {filepath} - {e}", 'error')
            return False

    def _send_alert(self, message):
        """Send alert via configured webhook"""
        if not self.config.get('alert_webhook'):
            return
        try:
            import requests
            requests.post(self.config['alert_webhook'], json={
                'text': f"🚨 Malware Scanner Alert\n{message}",
                'content': f"🚨 Malware Scanner Alert\n{message}"
            }, timeout=5)
        except Exception:
            pass

    def _handle_event(self, filepath, event_type):
        """Process a file system event"""
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in self.__dangerous_extensions:
            return

        if not os.path.isfile(filepath):
            return

        self._log(f"File {event_type}: {filepath}")

        # Quick scan
        threat = self._quick_scan(filepath)
        if threat:
            event = {
                'time': int(time.time()),
                'file': filepath,
                'event': event_type,
                'threat': threat,
                'action': 'none'
            }

            # Auto-quarantine if enabled
            if self.config.get('auto_quarantine'):
                if self._quarantine_file(filepath, threat):
                    event['action'] = 'quarantined'

            # Alert
            self._send_alert(f"Threat detected: {threat}\nFile: {filepath}\nAction: {event['action']}")

            # Store event
            self.config['events'] = self.config.get('events', [])[-99:]  # keep last 100
            self.config['events'].append(event)
            self._save_config()

            self._log(f"THREAT: {filepath} - {threat}", 'critical')

    def _watch_loop(self):
        """Main inotify watch loop"""
        if not HAS_INOTIFY:
            self._log("inotify not available", 'error')
            return

        i = inotify.adapters.InotifyTrees(
            self.config['watch_paths'],
            mask=inotify.constants.IN_CREATE | inotify.constants.IN_MODIFY |
                 inotify.constants.IN_MOVED_TO | inotify.constants.IN_CLOSE_WRITE
        )

        self._log(f"Watcher started on: {self.config['watch_paths']}")

        for event in i.event_gen(yield_nones=False):
            if not self._running:
                break
            (_, type_names, path, filename) = event
            if not filename:
                continue
            filepath = os.path.join(path, filename)
            event_type = 'modified' if 'IN_MODIFY' in type_names or 'IN_CLOSE_WRITE' in type_names else 'created'
            try:
                self._handle_event(filepath, event_type)
            except Exception as e:
                self._log(f"Error handling {filepath}: {e}", 'error')

    # === PUBLIC API ===

    def start(self):
        if not HAS_INOTIFY:
            return {'status': False, 'msg': 'inotify not installed (pip install inotify)'}
        if not self.config.get('watch_paths'):
            return {'status': False, 'msg': 'No watch paths configured'}
        if self._running:
            return {'status': False, 'msg': 'Already running'}

        self._running = True
        self.config['enabled'] = True
        self._save_config()

        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

        # Write PID
        with open(self.__pid_file, 'w') as f:
            f.write(str(os.getpid()))

        return {'status': True, 'msg': 'Watcher started'}

    def stop(self):
        self._running = False
        self.config['enabled'] = False
        self._save_config()
        if os.path.exists(self.__pid_file):
            os.remove(self.__pid_file)
        return {'status': True, 'msg': 'Watcher stopped'}

    def get_status(self):
        running = self._running or (os.path.exists(self.__pid_file))
        return {
            'status': True,
            'running': running,
            'watch_paths': self.config.get('watch_paths', []),
            'auto_quarantine': self.config.get('auto_quarantine', False),
            'events_count': len(self.config.get('events', [])),
            'has_inotify': HAS_INOTIFY
        }

    def get_events(self):
        return {'status': True, 'events': list(reversed(self.config.get('events', [])))}

    def set_config(self, watch_paths=None, auto_quarantine=None, alert_webhook=None):
        if watch_paths is not None:
            self.config['watch_paths'] = [p for p in watch_paths if os.path.isdir(p)]
        if auto_quarantine is not None:
            self.config['auto_quarantine'] = auto_quarantine
        if alert_webhook is not None:
            self.config['alert_webhook'] = alert_webhook
        self._save_config()
        return {'status': True, 'msg': 'Config updated'}

    def clear_events(self):
        self.config['events'] = []
        self._save_config()
        return {'status': True, 'msg': 'Events cleared'}
