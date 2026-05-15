"""
WordPress Advanced Scanner - Core checksum verification, plugin CVE lookup,
auto-update, and database malware scan.
"""
import os, json, re, hashlib, time, sqlite3

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class WPAdvancedScanner:
    __cache_path = '/www/server/panel/plugin/malwarescan/wp_cache'

    def __init__(self):
        os.makedirs(self.__cache_path, exist_ok=True)

    # === CORE CHECKSUM VERIFICATION ===

    def verify_core_checksums(self, wp_path):
        """Compare WP core files against official WordPress.org checksums API"""
        version = self._get_version(wp_path)
        if not version or version == 'unknown':
            return {'status': False, 'msg': 'Cannot determine WP version'}

        checksums = self._fetch_checksums(version)
        if not checksums:
            return {'status': False, 'msg': f'Cannot fetch checksums for WP {version}'}

        results = {'modified': [], 'missing': [], 'extra': [], 'verified': 0}
        core_files = set()

        for rel_path, expected_md5 in checksums.items():
            core_files.add(rel_path)
            full_path = os.path.join(wp_path, rel_path)

            if not os.path.exists(full_path):
                results['missing'].append(rel_path)
                continue

            actual_md5 = self._md5(full_path)
            if actual_md5 == expected_md5:
                results['verified'] += 1
            else:
                results['modified'].append({
                    'file': rel_path,
                    'expected': expected_md5,
                    'actual': actual_md5,
                    'size': os.path.getsize(full_path)
                })

        # Check for extra PHP files in wp-admin and wp-includes
        for check_dir in ['wp-admin', 'wp-includes']:
            dir_path = os.path.join(wp_path, check_dir)
            if not os.path.isdir(dir_path):
                continue
            for root, _, files in os.walk(dir_path):
                for f in files:
                    if not f.endswith('.php'):
                        continue
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, wp_path)
                    if rel not in core_files:
                        results['extra'].append(rel)

        results['version'] = version
        results['total_core_files'] = len(checksums)
        return {'status': True, 'results': results}

    def _fetch_checksums(self, version):
        """Fetch checksums from WordPress.org API with caching"""
        cache_file = os.path.join(self.__cache_path, f'checksums_{version}.json')

        # Use cache if less than 24h old
        if os.path.exists(cache_file) and time.time() - os.path.getmtime(cache_file) < 86400:
            return json.loads(open(cache_file).read())

        if not HAS_REQUESTS:
            return None

        try:
            url = f'https://api.wordpress.org/core/checksums/1.0/?version={version}&locale=en_US'
            resp = requests.get(url, timeout=15)
            data = resp.json()
            if data.get('checksums'):
                checksums = data['checksums']
                with open(cache_file, 'w') as f:
                    json.dump(checksums, f)
                return checksums
        except Exception:
            pass
        return None

    # === PLUGIN CVE DATABASE ===

    def check_plugin_vulnerabilities(self, wp_path):
        """Check installed plugins against known vulnerabilities"""
        plugins = self._get_installed_plugins(wp_path)
        results = []

        for plugin in plugins:
            vulns = self._lookup_vulns(plugin['slug'], plugin['version'])
            if vulns:
                results.append({
                    'plugin': plugin['name'],
                    'slug': plugin['slug'],
                    'installed_version': plugin['version'],
                    'vulnerabilities': vulns
                })

        return {'status': True, 'plugins_checked': len(plugins),
                'vulnerable': len(results), 'results': results}

    def _lookup_vulns(self, slug, version):
        """Check WPScan/Patchstack-style vulnerability database"""
        # Check local CVE cache first
        vuln_db_file = os.path.join(self.__cache_path, 'vuln_db.json')
        vuln_db = {}
        if os.path.exists(vuln_db_file):
            try:
                vuln_db = json.loads(open(vuln_db_file).read())
            except Exception:
                pass

        # Try WordPress.org plugin API for version info
        vulns = []
        if slug in vuln_db:
            for vuln in vuln_db[slug]:
                if self._version_affected(version, vuln.get('affected_versions', '')):
                    vulns.append(vuln)

        # Also check via WordPress.org API for outdated plugins
        if HAS_REQUESTS:
            try:
                resp = requests.get(f'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug={slug}', timeout=10)
                data = resp.json()
                if data.get('version') and version:
                    if self._version_compare(version, data['version']) < 0:
                        vulns.append({
                            'title': f'Outdated plugin (latest: {data["version"]})',
                            'severity': 'medium',
                            'fixed_in': data['version'],
                            'type': 'outdated'
                        })
            except Exception:
                pass

        return vulns

    def update_vuln_database(self):
        """Download/update the vulnerability database"""
        if not HAS_REQUESTS:
            return {'status': False, 'msg': 'requests module not available'}

        vuln_db_file = os.path.join(self.__cache_path, 'vuln_db.json')

        # Fetch from a public vulnerability feed
        try:
            # Using WPVulnDB-style format
            url = 'https://raw.githubusercontent.com/developer-developer/wp-vuln-db/main/db.json'
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                with open(vuln_db_file, 'w') as f:
                    f.write(resp.text)
                return {'status': True, 'msg': 'Database updated'}
        except Exception:
            pass

        # If fetch fails, create empty DB
        if not os.path.exists(vuln_db_file):
            with open(vuln_db_file, 'w') as f:
                json.dump({}, f)
        return {'status': True, 'msg': 'Using cached database'}

    # === AUTO-UPDATE VULNERABLE PLUGINS ===

    def auto_update_plugins(self, wp_path, slugs=None):
        """Update plugins via WP-CLI or direct download"""
        results = []
        wp_cli = self._find_wp_cli()

        if wp_cli:
            plugins_to_update = slugs or self._get_outdated_plugins(wp_path)
            for slug in plugins_to_update:
                try:
                    import subprocess
                    cmd = [wp_cli, 'plugin', 'update', slug, f'--path={wp_path}', '--allow-root']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    success = result.returncode == 0
                    results.append({'slug': slug, 'success': success, 'output': result.stdout[:200]})
                except Exception as e:
                    results.append({'slug': slug, 'success': False, 'output': str(e)})
        else:
            return {'status': False, 'msg': 'WP-CLI not found. Install: curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar'}

        return {'status': True, 'results': results, 'updated': sum(1 for r in results if r['success'])}

    def _find_wp_cli(self):
        for path in ['/usr/local/bin/wp', '/usr/bin/wp', '/www/server/panel/plugin/malwarescan/wp-cli.phar']:
            if os.path.exists(path):
                return path
        return None

    def _get_outdated_plugins(self, wp_path):
        wp_cli = self._find_wp_cli()
        if not wp_cli:
            return []
        try:
            import subprocess
            result = subprocess.run(
                [wp_cli, 'plugin', 'list', '--update=available', '--field=name', f'--path={wp_path}', '--allow-root'],
                capture_output=True, text=True, timeout=30
            )
            return [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
        except Exception:
            return []

    # === DATABASE MALWARE SCAN ===

    def scan_database(self, wp_path):
        """Scan WordPress database for injected malware in posts, options, and widgets"""
        wp_config = os.path.join(wp_path, 'wp-config.php')
        if not os.path.exists(wp_config):
            return {'status': False, 'msg': 'wp-config.php not found'}

        db_creds = self._parse_wp_config(wp_config)
        if not db_creds:
            return {'status': False, 'msg': 'Cannot parse database credentials'}

        threats = []
        try:
            import pymysql
            conn = pymysql.connect(
                host=db_creds['host'], user=db_creds['user'],
                password=db_creds['password'], database=db_creds['name'],
                charset='utf8mb4', connect_timeout=10
            )
            cursor = conn.cursor()
            prefix = db_creds.get('prefix', 'wp_')

            # Scan wp_options for suspicious values
            cursor.execute(f"SELECT option_name, option_value FROM {prefix}options WHERE option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode%' OR option_value LIKE '%<script%' OR option_value LIKE '%<iframe%'")
            for row in cursor.fetchall():
                threats.append({
                    'table': f'{prefix}options',
                    'field': 'option_value',
                    'key': row[0],
                    'snippet': row[1][:200],
                    'type': 'injected_code'
                })

            # Scan wp_posts for injected scripts
            cursor.execute(f"SELECT ID, post_title, post_content FROM {prefix}posts WHERE post_content LIKE '%<script%eval(%' OR post_content LIKE '%<iframe%display:none%' OR post_content LIKE '%base64_decode%' OR post_content LIKE '%document.write(unescape%' LIMIT 100")
            for row in cursor.fetchall():
                threats.append({
                    'table': f'{prefix}posts',
                    'field': 'post_content',
                    'key': f'Post #{row[0]}: {row[1][:50]}',
                    'snippet': row[2][:200],
                    'type': 'injected_script'
                })

            # Scan wp_usermeta for suspicious capabilities
            cursor.execute(f"SELECT user_id, meta_value FROM {prefix}usermeta WHERE meta_key='{prefix}capabilities' AND meta_value LIKE '%administrator%'")
            admins = cursor.fetchall()

            # Check for recently created admins (potential backdoor accounts)
            cursor.execute(f"SELECT u.ID, u.user_login, u.user_registered FROM {prefix}users u INNER JOIN {prefix}usermeta m ON u.ID=m.user_id WHERE m.meta_key='{prefix}capabilities' AND m.meta_value LIKE '%administrator%' ORDER BY u.user_registered DESC LIMIT 10")
            recent_admins = []
            for row in cursor.fetchall():
                recent_admins.append({'id': row[0], 'login': row[1], 'registered': str(row[2])})

            conn.close()

            return {
                'status': True,
                'threats': threats,
                'total_threats': len(threats),
                'admin_users': recent_admins,
                'total_admins': len(admins)
            }

        except ImportError:
            return {'status': False, 'msg': 'pymysql not installed'}
        except Exception as e:
            return {'status': False, 'msg': f'Database error: {str(e)}'}

    def _parse_wp_config(self, config_path):
        """Extract DB credentials from wp-config.php"""
        try:
            content = open(config_path, 'r', errors='ignore').read()
            creds = {}
            patterns = {
                'name': r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)",
                'user': r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)",
                'password': r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)",
                'host': r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)",
            }
            for key, pattern in patterns.items():
                m = re.search(pattern, content)
                if m:
                    creds[key] = m.group(1)

            # Table prefix
            m = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)", content)
            creds['prefix'] = m.group(1) if m else 'wp_'

            if all(k in creds for k in ['name', 'user', 'password', 'host']):
                return creds
        except Exception:
            pass
        return None

    # === HELPERS ===

    def _get_version(self, wp_path):
        ver_file = os.path.join(wp_path, 'wp-includes/version.php')
        if os.path.exists(ver_file):
            content = open(ver_file, 'r', errors='ignore').read()
            m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)", content)
            if m:
                return m.group(1)
        return 'unknown'

    def _md5(self, filepath):
        h = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    def _get_installed_plugins(self, wp_path):
        plugins = []
        plugins_dir = os.path.join(wp_path, 'wp-content/plugins')
        if not os.path.isdir(plugins_dir):
            return plugins
        for plugin in os.listdir(plugins_dir):
            plugin_path = os.path.join(plugins_dir, plugin)
            if not os.path.isdir(plugin_path):
                continue
            for f in os.listdir(plugin_path):
                if f.endswith('.php'):
                    fpath = os.path.join(plugin_path, f)
                    content = open(fpath, 'r', errors='ignore').read(3000)
                    if 'Plugin Name:' in content:
                        name_m = re.search(r'Plugin Name:\s*(.+)', content)
                        ver_m = re.search(r'Version:\s*([^\s]+)', content)
                        plugins.append({
                            'slug': plugin,
                            'name': name_m.group(1).strip() if name_m else plugin,
                            'version': ver_m.group(1).strip() if ver_m else ''
                        })
                        break
        return plugins

    def _version_compare(self, v1, v2):
        """Compare version strings. Returns -1, 0, or 1"""
        def normalize(v):
            return [int(x) for x in re.sub(r'[^0-9.]', '', v).split('.') if x]
        a, b = normalize(v1), normalize(v2)
        for i in range(max(len(a), len(b))):
            x = a[i] if i < len(a) else 0
            y = b[i] if i < len(b) else 0
            if x < y: return -1
            if x > y: return 1
        return 0

    def _version_affected(self, installed, affected_range):
        """Check if installed version falls within affected range"""
        if not affected_range:
            return False
        # Simple check: if affected_range is "< X.Y.Z"
        m = re.match(r'<\s*([\d.]+)', affected_range)
        if m:
            return self._version_compare(installed, m.group(1)) < 0
        return False
