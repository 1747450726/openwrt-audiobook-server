#!/usr/bin/env python3
# audiobook_server.py

import os
import json
import time
import socket
import mimetypes
import logging
import threading
import secrets
from logging.handlers import RotatingFileHandler
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime
import re

CONFIG = {
    'host': '::',
    'port': 8080,
    'data_dir': '/root/audiobook/data',
    'audio_dir': '/你的音频库文件位置',
    'log_dir': '/root/audiobook/log',    #日志路径
    'log_file': '/root/audiobook/log/server.log',    #懒得写自己看吧
    'token_file': '/root/audiobook/data/tokens.json',
    'progress_file': '/root/audiobook/data/progress.json',
    'settings_file': '/root/audiobook/data/settings.json',
    'users_file': '/root/audiobook/data/users.json',
    'behavior_file': '/root/audiobook/data/behavior.json',
    'token_expire': 7 * 24 * 3600,
    'max_log_size': 10 * 1024 * 1024,
    'log_backup_count': 5,
}

os.makedirs(CONFIG['data_dir'], exist_ok=True)
os.makedirs(CONFIG['log_dir'], exist_ok=True)

logger = logging.getLogger("audiobook")
logger.setLevel(logging.DEBUG)
logger.handlers.clear()

handler = RotatingFileHandler(
    CONFIG['log_file'],
    maxBytes=CONFIG['max_log_size'],
    backupCount=CONFIG['log_backup_count']
)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s [%(process)d:%(thread)d] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
logger.addHandler(handler)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s %(message)s'))
logger.addHandler(console)

class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True

def natural_sort_key(text):
    
    def atoi(text):
        return int(text) if text.isdigit() else text.lower()
    return [atoi(c) for c in re.split(r'(\d+)', text)]

def load_json(path, default=None):
    if default is None: 
        default = {}
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error("Load %s error: %s", path, e)
    return default

def save_json(path, data):
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.error("Save %s error: %s", path, e)
        return False

TOKENS = load_json(CONFIG['token_file'])
PROGRESS = load_json(CONFIG['progress_file'])
SETTINGS = load_json(CONFIG['settings_file'])
BEHAVIOR = load_json(CONFIG['behavior_file'])
ONLINE_USERS = {}

def init_users():
    old_users = load_json(CONFIG['users_file'], {})
    users = {}
    for k, v in old_users.items():
        if isinstance(v, dict) and 'password' in v:
            users[k] = v
        else:
            users[k] = {'password': v, 'paths': []}
    if 'admin' not in users:
        users['admin'] = {'password': 'admin123', 'paths': []}
        save_json(CONFIG['users_file'], users)
    return users

USERS = init_users()
lock = threading.RLock()

def create_token(username):
    token = secrets.token_hex(32)
    expire = time.time() + CONFIG['token_expire']
    with lock:
        TOKENS[token] = {'username': username, 'expire_time': expire}
        save_json(CONFIG['token_file'], TOKENS)
    return token

def validate_token(token):
    with lock:
        if token not in TOKENS:
            return None
        data = TOKENS[token]
        if time.time() > data.get('expire_time', 0):
            del TOKENS[token]
            save_json(CONFIG['token_file'], TOKENS)
            return None
        return data.get('username')

def cleanup_tokens():
    while True:
        time.sleep(60)
        with lock:
            now = time.time()
            expired = [t for t, d in TOKENS.items() if now > d.get('expire_time', 0)]
            for t in expired:
                del TOKENS[t]
            if expired:
                save_json(CONFIG['token_file'], TOKENS)

cleanup_thread = threading.Thread(target=cleanup_tokens, daemon=True)
cleanup_thread.start()

def record_behavior(username, ip, action, details=None):
    try:
        with lock:
            if username not in BEHAVIOR:
                BEHAVIOR[username] = []
            BEHAVIOR[username].append({
                'time': datetime.now().isoformat(),
                'ip': ip,
                'action': action,
                'details': details or {}
            })
            if len(BEHAVIOR[username]) > 1000:
                BEHAVIOR[username] = BEHAVIOR[username][-1000:]
            save_json(CONFIG['behavior_file'], BEHAVIOR)
    except Exception as e:
        logger.error("Record behavior error: %s", e)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.info("%s - %s", self.client_address[0], fmt % args)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def _auth(self):
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return None
        token = auth.split(' ', 1)[1] if ' ' in auth else None
        if not token:
            return None
        username = validate_token(token)
        if username:
            with lock:
                ONLINE_USERS[token] = {
                    'username': username,
                    'ip': self.client_address[0],
                    'device': self.headers.get('User-Agent', 'Unknown')[:100],
                    'login_time': ONLINE_USERS.get(token, {}).get('login_time', datetime.now().isoformat()),
                    'last_activity': datetime.now().isoformat()
                }
        return username

    def _is_admin(self, username):
        return username == 'admin'

    def _json(self, obj, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(json.dumps(obj, ensure_ascii=False).encode('utf-8'))

    def _html(self, content):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def _error(self, code, msg):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': msg}, ensure_ascii=False).encode('utf-8'))

    def _read_json(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > 1024 * 1024:
                self._error(413, '请求过大')
                return None
            return json.loads(self.rfile.read(length)) if length else {}
        except:
            self._error(400, '无效JSON')
            return None

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == '/':
                self._html(HTML)
            elif path == '/admin':
                username = self._auth()
                if not username or not self._is_admin(username):
                    self._error(403, '禁止访问')
                else:
                    self._html(ADMIN_HTML)
            elif path == '/api/audio-files':
                self._audio_list()
            elif path == '/api/audio-chapters':
                self._audio_chapters()
            elif path == '/api/get-progress':
                self._get_progress()
            elif path == '/api/get-settings':
                self._get_settings()
            elif path == '/api/admin/logs':
                self._get_logs()
            elif path == '/api/admin/online-users':
                self._get_online_users()
            elif path == '/api/admin/user-behavior':
                self._get_user_behavior()
            elif path == '/api/admin/users':
                self._get_users()
            elif path == '/api/admin/user-paths':
                self._get_user_paths()
            elif path.startswith('/audio/'):
                self._audio_file(path)
            else:
                self.send_error(404)
        except Exception as e:
            logger.error("GET error: %s", e, exc_info=True)
            self._error(500, '服务器错误')

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == '/api/login':
                self._login()
            elif path == '/api/save-progress':
                self._save_progress()
            elif path == '/api/save-settings':
                self._save_settings()
            elif path == '/api/admin/add-user':
                self._add_user()
            elif path == '/api/admin/delete-user':
                self._delete_user()
            elif path == '/api/admin/set-user-path':
                self._set_user_path()
            else:
                self.send_error(404)
        except Exception as e:
            logger.error("POST error: %s", e, exc_info=True)
            self._error(500, '服务器错误')

    def _login(self):
        data = self._read_json()
        if not data:
            return
        u, p = data.get('username', '').strip(), data.get('password', '').strip()
        if not u or not p:
            self._error(400, '用户名密码不能为空')
            return
        with lock:
            if u not in USERS:
                self._error(401, '用户不存在')
                return
            user_data = USERS[u]
            if user_data.get('password') != p:
                self._error(401, '密码错误')
                return
            token = create_token(u)
            if u not in SETTINGS:
                SETTINGS[u] = {'skip_begin': 15, 'skip_end': 15, 'sleep_timer': 0}
                save_json(CONFIG['settings_file'], SETTINGS)
            if u not in PROGRESS:
                PROGRESS[u] = {}
                save_json(CONFIG['progress_file'], PROGRESS)
        record_behavior(u, self.client_address[0], 'login', {})
        logger.info("User '%s' login from %s", u, self.client_address[0])
        self._json({'token': token, 'username': u, 'is_admin': self._is_admin(u)})

    def _audio_list(self):
        username = self._auth()
        if not username:
            self._error(401, '未授权')
            return
        paths = [CONFIG['audio_dir']]
        with lock:
            user_data = USERS.get(username, {})
            if user_data.get('paths'):
                paths.extend(user_data['paths'])
        
        files = []
        dirs = {}
        
        for base in paths:
            if not os.path.exists(base):
                logger.warning("Path does not exist: %s", base)
                continue
            try:
                for root, _, fs in os.walk(base):
                    rel_dir = os.path.relpath(root, base)
                    if rel_dir == '.':
                        rel_dir = ''
                    
                    for f in fs:
                        if f.lower().endswith(('.mp3', '.m4a', '.m4b', '.aac', '.flac', '.wav', '.ogg')):
                            try:
                                full = os.path.join(root, f)
                                if not os.path.realpath(full).startswith(os.path.realpath(base)):
                                    continue
                                size = os.path.getsize(full)
                                rel = os.path.relpath(full, base)
                                info = {
                                    'name': f,
                                    'path': rel,
                                    'base': base,
                                    'size_mb': round(size / 1024 / 1024, 2)
                                }
                                
                                if rel_dir not in dirs:
                                    dirs[rel_dir] = []
                                dirs[rel_dir].append(info)
                                files.append(info)
                            except Exception as e:
                                logger.error("Error processing file %s: %s", f, e)
                                continue
            except Exception as e:
                logger.error("Scan %s error: %s", base, e)
        
        for d in dirs.values():
            d.sort(key=lambda x: natural_sort_key(x['name']))
        files.sort(key=lambda x: natural_sort_key(x['name']))
        
        logger.info("Found %d audio files for user %s", len(files), username)
        record_behavior(username, self.client_address[0], 'list_audio', {'total': len(files)})
        self._json({'files': files, 'dirs': dirs, 'total': len(files)})

    def _audio_chapters(self):
        username = self._auth()
        if not username:
            self._error(401, '未授权')
            return
        query = urlparse(self.path).query
        params = parse_qs(query)
        audio_path = params.get('path', [''])[0]
        if not audio_path:
            self._error(400, '缺少路径')
            return
        
        paths = [CONFIG['audio_dir']]
        with lock:
            user_data = USERS.get(username, {})
            if user_data.get('paths'):
                paths.extend(user_data['paths'])
        
        chapters = []
        for base in paths:
            dir_path = os.path.dirname(audio_path)
            full_dir = os.path.join(base, dir_path)
            if not os.path.isdir(full_dir):
                continue
            try:
                files = []
                for f in os.listdir(full_dir):
                    if f.lower().endswith(('.mp3', '.m4a', '.m4b', '.aac', '.flac', '.wav', '.ogg')):
                        try:
                            full = os.path.join(full_dir, f)
                            if not os.path.realpath(full).startswith(os.path.realpath(base)):
                                continue
                            size = os.path.getsize(full)
                            files.append({
                                'name': f,
                                'path': os.path.join(dir_path, f) if dir_path else f,
                                'size_mb': round(size / 1024 / 1024, 2)
                            })
                        except:
                            continue
                            
                files.sort(key=lambda x: natural_sort_key(x['name']))
                chapters.extend(files)
            except:
                continue
        
        self._json({'chapters': chapters})

    def _get_progress(self):
        username = self._auth()
        if not username:
            self._error(401, '未授权')
            return
        query = urlparse(self.path).query
        params = parse_qs(query)
        audio_path = params.get('path', [''])[0]
        with lock:
            progress = PROGRESS.get(username, {}).get(audio_path, {'position': 0, 'last_played': 0})
        self._json(progress)

    def _save_progress(self):
        username = self._auth()
        if not username:
            self._error(401, '未授权')
            return
        data = self._read_json()
        if not data:
            return
        path = data.get('path', '').strip()
        if not path:
            self._error(400, '缺少路径')
            return
        try:
            position = float(data.get('position', 0))
            if position < 0:
                position = 0
        except:
            self._error(400, '无效进度')
            return
        with lock:
            if username not in PROGRESS:
                PROGRESS[username] = {}
            PROGRESS[username][path] = {'position': position, 'last_played': int(time.time())}
            save_json(CONFIG['progress_file'], PROGRESS)
        record_behavior(username, self.client_address[0], 'save_progress', {'path': path[:50]})
        self._json({'success': True})

    def _get_settings(self):
        username = self._auth()
        if not username:
            self._error(401, '未授权')
            return
        with lock:
            settings = SETTINGS.get(username, {'skip_begin': 15, 'skip_end': 15, 'sleep_timer': 0})
        self._json(settings)

    def _save_settings(self):
        username = self._auth()
        if not username:
            self._error(401, '未授权')
            return
        data = self._read_json()
        if not data:
            return
        with lock:
            SETTINGS[username] = {
                'skip_begin': min(30, max(10, int(data.get('skip_begin', 15)))),
                'skip_end': min(30, max(10, int(data.get('skip_end', 15)))),
                'sleep_timer': max(0, int(data.get('sleep_timer', 0)))
            }
            save_json(CONFIG['settings_file'], SETTINGS)
        self._json({'success': True})

    def _audio_file(self, path):
        username = self._auth()
        if not username:
            self._error(401, '未授权')
            return
        
        rel = unquote(path[len('/audio/'):])
        paths = [CONFIG['audio_dir']]
        with lock:
            user_data = USERS.get(username, {})
            if user_data.get('paths'):
                paths.extend(user_data['paths'])
        
        for base in paths:
            real = os.path.realpath(os.path.join(base, rel))
            root = os.path.realpath(base)
            
            if not real.startswith(root) or not os.path.isfile(real):
                continue
            
            try:
                mime = mimetypes.guess_type(real)[0] or 'audio/mpeg'
                size = os.path.getsize(real)

                range_header = self.headers.get('Range', '')
                
                if range_header:
                    try:
                        range_str = range_header.replace('bytes=', '')
                        start, end = range_str.split('-')
                        start = int(start) if start else 0
                        end = int(end) if end else size - 1
                        
                        if start < 0 or end >= size or start > end:
                            self.send_error(416, 'Range Not Satisfiable')
                            return
                        
                        # 返回 206 Partial Content
                        self.send_response(206)
                        self.send_header('Content-Type', mime)
                        self.send_header('Content-Length', str(end - start + 1))
                        self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
                        self.send_header('Accept-Ranges', 'bytes')
                        self.end_headers()
                        
                        with open(real, 'rb') as f:
                            f.seek(start)
                            remaining = end - start + 1
                            while remaining > 0:
                                chunk_size = min(1024 * 1024, remaining)
                                chunk = f.read(chunk_size)
                                if not chunk:
                                    break
                                self.wfile.write(chunk)
                                remaining -= len(chunk)
                        
                        logger.info("Served audio range %d-%d for %s (user: %s)", start, end, rel, username)
                        record_behavior(username, self.client_address[0], 'play_audio', {'path': rel[:50], 'range': f'{start}-{end}'})
                        return
                    except Exception as e:
                        logger.error("Range request error: %s", e)
                        self.send_error(400, 'Invalid Range')
                        return
                else:
                    self.send_response(200)
                    self.send_header('Content-Type', mime)
                    self.send_header('Content-Length', str(size))
                    self.send_header('Accept-Ranges', 'bytes')
                    self.end_headers()
                    
                    with open(real, 'rb') as f:
                        while True:
                            chunk = f.read(1024 * 1024)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    
                    logger.info("Served full audio file %s (user: %s)", rel, username)
                    record_behavior(username, self.client_address[0], 'play_audio', {'path': rel[:50]})
                    return
            
            except Exception as e:
                logger.error("Serve audio error: %s", e, exc_info=True)
                self._error(500, '文件错误')
                return
        
        self._error(404, '文件不存在')

    def _get_logs(self):
        username = self._auth()
        if not username or not self._is_admin(username):
            self._error(403, '禁止')
            return
        try:
            lines = []
            if os.path.exists(CONFIG['log_file']):
                with open(CONFIG['log_file'], 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[-1000:]
            self._json({'logs': lines, 'total': len(lines)})
        except Exception as e:
            logger.error("Get logs error: %s", e)
            self._error(500, '获取日志失败')

    def _get_online_users(self):
        username = self._auth()
        if not username or not self._is_admin(username):
            self._error(403, '禁止')
            return
        with lock:
            users = list(ONLINE_USERS.values())
        self._json({'users': users, 'count': len(users)})

    def _get_user_behavior(self):
        username = self._auth()
        if not username or not self._is_admin(username):
            self._error(403, '禁止')
            return
        query = urlparse(self.path).query
        params = parse_qs(query)
        target = params.get('user', [''])[0]
        if not target:
            self._error(400, '缺少用户')
            return
        with lock:
            behavior = BEHAVIOR.get(target, [])
        self._json({'user': target, 'behavior': behavior[-500:], 'total': len(behavior)})

    def _get_users(self):
        username = self._auth()
        if not username or not self._is_admin(username):
            self._error(403, '禁止')
            return
        with lock:
            users = [{'username': u} for u in USERS.keys()]
        self._json({'users': users, 'total': len(users)})

    def _get_user_paths(self):
        username = self._auth()
        if not username or not self._is_admin(username):
            self._error(403, '禁止')
            return
        with lock:
            paths = {u: USERS[u].get('paths', []) for u in USERS.keys()}
        self._json({'paths': paths})

    def _add_user(self):
        username = self._auth()
        if not username or not self._is_admin(username):
            self._error(403, '禁止')
            return
        data = self._read_json()
        if not data:
            return
        new_u = data.get('username', '').strip()
        new_p = data.get('password', '').strip()
        if not new_u or len(new_u) < 3:
            self._error(400, '用户名至少3字符')
            return
        if not new_p or len(new_p) < 8:
            self._error(400, '密码至少8字符')
            return
        with lock:
            if new_u in USERS:
                self._error(400, '用户已存在')
                return
            USERS[new_u] = {'password': new_p, 'paths': []}
            save_json(CONFIG['users_file'], USERS)
        record_behavior(username, self.client_address[0], 'add_user', {'new_user': new_u})
        logger.info("Admin added user: %s", new_u)
        self._json({'success': True})

    def _delete_user(self):
        username = self._auth()
        if not username or not self._is_admin(username):
            self._error(403, '禁止')
            return
        data = self._read_json()
        if not data:
            return
        del_u = data.get('username', '').strip()
        if not del_u or del_u == 'admin':
            self._error(400, '不能删除该用户')
            return
        with lock:
            if del_u not in USERS:
                self._error(400, '用户不存在')
                return
            del USERS[del_u]
            save_json(CONFIG['users_file'], USERS)
            if del_u in PROGRESS:
                del PROGRESS[del_u]
                save_json(CONFIG['progress_file'], PROGRESS)
            if del_u in SETTINGS:
                del SETTINGS[del_u]
                save_json(CONFIG['settings_file'], SETTINGS)
            if del_u in BEHAVIOR:
                del BEHAVIOR[del_u]
                save_json(CONFIG['behavior_file'], BEHAVIOR)
        record_behavior(username, self.client_address[0], 'delete_user', {'user': del_u})
        logger.info("Admin deleted user: %s", del_u)
        self._json({'success': True})

    def _set_user_path(self):
        username = self._auth()
        if not username or not self._is_admin(username):
            self._error(403, '禁止')
            return
        data = self._read_json()
        if not data:
            return
        target = data.get('username', '').strip()
        paths = data.get('paths', [])
        if not target:
            self._error(400, '缺少用户')
            return
        with lock:
            if target not in USERS:
                self._error(400, '用户不存在')
                return
            valid_paths = [p for p in paths if os.path.isdir(p)]
            USERS[target]['paths'] = valid_paths
            save_json(CONFIG['users_file'], USERS)
        record_behavior(username, self.client_address[0], 'set_user_path', {'target': target})
        logger.info("Admin set paths for user: %s", target)
        self._json({'success': True})
HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>有声书播放器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; color: #333; }
        .header { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 30px 20px; text-align: center; }
        .header h1 { font-size: 32px; margin-bottom: 10px; }
        .login { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .login input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }
        .login button { width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; border-radius: 4px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 10px; }
        .login button:hover { opacity: 0.9; }
        .error { color: #d32f2f; text-align: center; margin: 10px 0; font-weight: 500; }
        
        .main { display: none; max-width: 1400px; margin: 20px auto; padding: 0 20px; }
        .main.show { display: block; }
        .top-bar { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .top-bar span { font-weight: bold; }
        .top-bar a { margin-left: 15px; color: #2196f3; text-decoration: none; cursor: pointer; }
        .top-bar a:hover { text-decoration: underline; }
        
        .layout { display: grid; grid-template-columns: 280px 1fr; gap: 20px; }
        .sidebar { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); height: fit-content; max-height: 70vh; overflow-y: auto; }
        .sidebar h3 { margin-bottom: 15px; color: #667eea; font-size: 16px; }
        .file-list { }
        .dir-title { margin: 15px 0 10px 0; font-weight: bold; color: #667eea; font-size: 13px; padding: 5px; background: #f0f0f0; border-radius: 3px; }
        .file-item { padding: 10px; margin: 5px 0; background: #f9f9f9; border-radius: 4px; cursor: pointer; border-left: 3px solid transparent; transition: all 0.2s; font-size: 13px; }
        .file-item:hover { background: #f0f0f0; }
        .file-item.active { background: #e3f2fd; border-left-color: #2196f3; font-weight: 500; }
        .file-name { font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .file-size { font-size: 11px; color: #999; margin-top: 3px; }
        
        .content { display: flex; flex-direction: column; gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .card h2 { color: #667eea; margin-bottom: 15px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        
        .player { display: flex; gap: 15px; align-items: center; margin: 20px 0; flex-wrap: wrap; }
        .btn-play { width: 50px; height: 50px; border-radius: 50%; background: #2196f3; color: white; border: none; cursor: pointer; font-size: 18px; display: flex; align-items: center; justify-content: center; transition: all 0.2s; }
        .btn-play:hover { background: #1976d2; transform: scale(1.05); }
        .btn-play:active { transform: scale(0.95); }
        .btn-skip { width: 45px; height: 45px; border-radius: 50%; background: #4caf50; color: white; border: none; cursor: pointer; font-size: 14px; display: flex; align-items: center; justify-content: center; transition: all 0.2s; }
        .btn-skip:hover { background: #45a049; }
        .progress { flex: 1; min-width: 300px; }
        .progress-bar { width: 100%; height: 6px; background: #e0e0e0; border-radius: 3px; cursor: pointer; margin: 10px 0; }
        .progress-fill { height: 100%; background: #667eea; border-radius: 3px; width: 0%; }
        .time { display: flex; justify-content: space-between; font-size: 12px; color: #999; }
        
        .setting { margin: 15px 0; }
        .setting label { display: block; margin-bottom: 5px; font-weight: 500; }
        .setting select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        
        .btn-group { display: flex; gap: 10px; margin-top: 15px; flex-wrap: wrap; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; transition: all 0.2s; }
        .btn-primary { background: #2196f3; color: white; }
        .btn-primary:hover { background: #1976d2; }
        .btn-success { background: #4caf50; color: white; }
        .btn-success:hover { background: #45a049; }
        
        .chapters { max-height: 300px; overflow-y: auto; }
        .chapter { padding: 10px; margin: 5px 0; background: #f9f9f9; border-radius: 4px; cursor: pointer; transition: all 0.2s; font-size: 13px; }
        .chapter:hover { background: #f0f0f0; }
        .chapter.active { background: #e3f2fd; color: #2196f3; font-weight: 500; }
        
        .status { position: fixed; bottom: 0; left: 0; right: 0; background: #333; color: white; padding: 12px; text-align: center; z-index: 1000; font-size: 14px; }
        
        @media (max-width: 768px) {
            .layout { grid-template-columns: 1fr; }
            .sidebar { max-height: 300px; }
            .player { justify-content: space-around; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📖 有声书播放器</h1>
        <p>自动记忆位置 • 章节管理 • 定时停止</p>
    </div>
    
    <div class="login" id="login">
        <input type="text" id="user" placeholder="用户名" autocomplete="username">
        <input type="password" id="pass" placeholder="密码" autocomplete="current-password">
        <button onclick="login()">登 录</button>
        <div id="err" class="error"></div>
    </div>
    
    <div class="main" id="main">
        <div class="top-bar">
            <span>👤 <strong id="uname"></strong></span>
            <div>
                <a id="admin-link" style="display: none;" onclick="goAdmin()">⚙️ 后台管理</a>
                <a onclick="logout()">🚪 退出登录</a>
            </div>
        </div>
        
        <div class="layout">
            <div class="sidebar">
                <h3>📚 音频库</h3>
                <div class="file-list" id="files"></div>
            </div>
            
            <div class="content">
                <div class="card">
                    <h2>🎵 播放器</h2>
                    <h3 id="now-playing" style="color: #666; font-size: 16px;">未选择音频</h3>
                    <div class="player">
                        <button class="btn-play" id="play-btn" onclick="togglePlay()" title="播放/暂停">▶</button>
                        <button class="btn-skip" onclick="back()" title="后退15秒">◀ 15s</button>
                        <button class="btn-skip" onclick="next()" title="前进15秒">15s ▶</button>
                        <div class="progress">
                            <div class="progress-bar" id="progress-bar" onclick="seek(event)">
                                <div class="progress-fill" id="fill"></div>
                            </div>
                            <div class="time">
                                <span id="cur">00:00</span>
                                <span id="dur">00:00</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <h2>⚙️ 设置</h2>
                    <div class="setting">
                        <label>跳过开头(秒)</label>
                        <select id="skip-b">
                            <option value="10">10</option>
                            <option value="15" selected>15</option>
                            <option value="20">20</option>
                            <option value="25">25</option>
                            <option value="30">30</option>
                        </select>
                    </div>
                    <div class="setting">
                        <label>跳过结尾(秒)</label>
                        <select id="skip-e">
                            <option value="10">10</option>
                            <option value="15" selected>15</option>
                            <option value="20">20</option>
                            <option value="25">25</option>
                            <option value="30">30</option>
                        </select>
                    </div>
                    <div class="setting">
                        <label>定时停止(分钟)</label>
                        <select id="sleep">
                            <option value="0" selected>不启用</option>
                            <option value="15">15</option>
                            <option value="30">30</option>
                            <option value="45">45</option>
                            <option value="60">60</option>
                            <option value="90">90</option>
                            <option value="120">120</option>
                        </select>
                    </div>
                    <div class="btn-group">
                        <button class="btn btn-primary" onclick="saveSetting()">💾 保存设置</button>
                        <button class="btn btn-success" onclick="saveProg()">📍 保存进度</button>
                    </div>
                </div>
                
                <div class="card">
                    <h2>📑 章节列表</h2>
                    <div class="chapters" id="chapters"></div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="status" id="status">✓ 准备就绪</div>
    
    <script>
        let token, user, isAdmin, audio, files = [], dirs = {}, chapters = [], currentPath = null;
        
        function login() {
            const u = document.getElementById('user').value.trim();
            const p = document.getElementById('pass').value.trim();
            if (!u || !p) { 
                showError('请输入用户名和密码');
                return; 
            }
            
            fetch('/api/login', { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' }, 
                body: JSON.stringify({username: u, password: p}) 
            })
            .then(r => r.json())
            .then(d => {
                if (d.error) {
                    showError(d.error);
                    return;
                }
                token = d.token;
                user = d.username;
                isAdmin = d.is_admin;
                document.getElementById('user').value = '';
                document.getElementById('pass').value = '';
                document.getElementById('uname').textContent = user;
                if (isAdmin) document.getElementById('admin-link').style.display = 'inline';
                document.getElementById('login').style.display = 'none';
                document.getElementById('main').classList.add('show');
                loadFiles();
                loadSetting();
                show('登录成功！', 'ok');
            })
            .catch(e => showError('登录失败: ' + e.message));
        }
        
        function showError(msg) {
            document.getElementById('err').textContent = msg;
            setTimeout(() => { document.getElementById('err').textContent = ''; }, 5000);
        }
        
        function logout() {
            if (audio) audio.pause();
            token = user = null;
            document.getElementById('login').style.display = 'block';
            document.getElementById('main').classList.remove('show');
        }
        
        function goAdmin() { 
            window.open('/admin', '_blank'); 
        }
        
        function loadFiles() {
            show('加载音频库...', 'info');
            fetch('/api/audio-files', { headers: { 'Authorization': 'Bearer ' + token } })
                .then(r => r.json())
                .then(d => {
                    if (d.error) {
                        show('加载失败: ' + d.error, 'err');
                        return;
                    }
                    files = d.files || [];
                    dirs = d.dirs || {};
                    let html = '';
                    
                    for (const [k, v] of Object.entries(dirs).sort()) {
                        if (k) html += `<div class="dir-title">📁 ${k}</div>`;
                        v.forEach(f => {
                            html += `<div class="file-item" onclick="playFile('${f.path.replace(/'/g, "\\'")}', this)" title="${f.name}">
                                <div class="file-name">${f.name}</div>
                                <div class="file-size">${f.size_mb} MB</div>
                            </div>`;
                        });
                    }
                    
                    document.getElementById('files').innerHTML = html || '<p style="color: #999; text-align: center;">📭 暂无音频文件</p>';
                    show('已加载 ' + files.length + ' 个音频文件', 'ok');
                })
                .catch(e => show('加载失败: ' + e.message, 'err'));
        }
        
        async function playFile(p, elem) {
            if (elem) {
                document.querySelectorAll('.file-item.active').forEach(e => e.classList.remove('active'));
                elem.classList.add('active');
            }
            
            currentPath = p;
            if (audio) { 
                audio.pause(); 
                audio.remove(); 
                saveProg(); 
            }
            
            try {
                show('加载音频中...', 'info');
                const response = await fetch('/audio/' + encodeURIComponent(p), {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                
                if (!response.ok) {
                    if (response.status === 401) {
                        show('❌ 认证失败，请重新登录', 'err');
                        logout();
                    } else {
                        show('❌ 加载失败: ' + response.statusText, 'err');
                    }
                    return;
                }
                
                const blob = await response.blob();
                const blobUrl = URL.createObjectURL(blob);
                
                audio = document.createElement('audio');
                audio.src = blobUrl;
                
                audio.addEventListener('loadedmetadata', async () => {
                    const prog = await getProgress(p);
                    const skipB = parseInt(document.getElementById('skip-b').value) || 15;
                    let start = prog.position - skipB;
                    if (start > 0 && start < audio.duration) {
                        audio.currentTime = start;
                    }
                    
                    document.getElementById('now-playing').textContent = '🎵 ' + p.split('/').pop();
                    updateBar();
                    audio.play();
                    await loadChapters(p);
                    setupSleep();
                    show('▶️  播放中: ' + p.split('/').pop(), 'ok');
                });
                
                audio.addEventListener('timeupdate', () => {
                    updateBar();
                    const skip = parseInt(document.getElementById('skip-e').value) || 15;
                    if (skip > 0 && audio.duration - audio.currentTime <= skip && !audio.paused) {
                        skipToNext(p);
                    }
                });
                
                audio.addEventListener('ended', async () => {
                    URL.revokeObjectURL(blobUrl);
                    if (!skipToNext(p)) {
                        show('✓ 播放完成', 'ok');
                        await saveProg();
                    }
                });
                
                audio.addEventListener('error', (e) => {
                    show('❌ 播放错误: ' + (e.target.error?.message || '未知错误'), 'err');
                    console.error('Audio error:', e);
                });
                
                document.body.appendChild(audio);
            } catch (e) {
                show('❌ 加载失败: ' + e.message, 'err');
                console.error('Load audio error:', e);
            }
        }
        
        function skipToNext(currentPath) {
            const dir = currentPath.includes('/') ? currentPath.substring(0, currentPath.lastIndexOf('/')) : '';
            const list = (dir && dirs[dir]) || dirs[''] || [];
            const idx = list.findIndex(x => x.path === currentPath);
            if (idx >= 0 && idx < list.length - 1) {
                playFile(list[idx + 1].path);
                return true;
            }
            return false;
        }
        
        async function loadChapters(p) {
            const dir = p.includes('/') ? p.substring(0, p.lastIndexOf('/')) : '';
            const r = await fetch(`/api/audio-chapters?path=${encodeURIComponent(dir || p)}`, { 
                headers: { 'Authorization': 'Bearer ' + token } 
            });
            if (r.ok) { 
                chapters = (await r.json()).chapters || []; 
                renderChapters(p); 
            }
        }
        
        function renderChapters(p) {
            let html = chapters.length === 0 ? '<div style="padding: 20px; color: #999; text-align: center;">📭 无其他章节</div>' : '';
            chapters.forEach((c, i) => {
                const isActive = audio && audio.src.includes(encodeURIComponent(c.path)) ? 'active' : '';
                html += `<div class="chapter ${isActive}" onclick="playFile('${c.path.replace(/'/g, "\\'")}')">
                    <strong>Ch${(i+1).toString().padStart(2, '0')}</strong> ${c.name} (${c.size_mb}MB)
                </div>`;
            });
            document.getElementById('chapters').innerHTML = html;
        }
        
        function updateBar() {
            if (!audio) return;
            const p = audio.duration ? (audio.currentTime / audio.duration) * 100 : 0;
            document.getElementById('fill').style.width = p + '%';
            document.getElementById('cur').textContent = fmt(audio.currentTime);
            document.getElementById('dur').textContent = fmt(audio.duration);
        }
        
        function togglePlay() {
            if (!audio) {
                show('请先选择音频', 'info');
                return;
            }
            if (audio.paused) {
                audio.play();
                document.getElementById('play-btn').textContent = '⏸';
            } else {
                audio.pause();
                document.getElementById('play-btn').textContent = '▶';
            }
        }
        
        function back() { 
            if (audio) {
                audio.currentTime = Math.max(0, audio.currentTime - 15); 
                show('⏮️  后退 15 秒', 'info');
            }
        }
        
        function next() { 
            if (audio) {
                audio.currentTime = Math.min(audio.duration, audio.currentTime + 15); 
                show('⏭️  前进 15 秒', 'info');
            }
        }
        
        function seek(e) { 
            if (audio && audio.duration) { 
                const r = e.currentTarget.getBoundingClientRect(); 
                audio.currentTime = ((e.clientX - r.left) / r.width) * audio.duration; 
            } 
        }
        
        async function getProgress(p) {
            const r = await fetch(`/api/get-progress?path=${encodeURIComponent(p)}`, { 
                headers: { 'Authorization': 'Bearer ' + token } 
            });
            return r.ok ? await r.json() : { position: 0 };
        }
        
        async function saveProg() {
            if (!audio || !currentPath) return;
            await fetch('/api/save-progress', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                body: JSON.stringify({ path: currentPath, position: Math.floor(audio.currentTime) })
            }).catch(e => console.error('Save progress error:', e));
        }
        
        async function loadSetting() {
            const r = await fetch('/api/get-settings', { headers: { 'Authorization': 'Bearer ' + token } });
            if (r.ok) {
                const d = await r.json();
                document.getElementById('skip-b').value = d.skip_begin || 15;
                document.getElementById('skip-e').value = d.skip_end || 15;
                document.getElementById('sleep').value = d.sleep_timer || 0;
            }
        }
        
        async function saveSetting() {
            await fetch('/api/save-settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                body: JSON.stringify({
                    skip_begin: parseInt(document.getElementById('skip-b').value),
                    skip_end: parseInt(document.getElementById('skip-e').value),
                    sleep_timer: parseInt(document.getElementById('sleep').value)
                })
            });
            show('⚙️ 设置已保存', 'ok');
            setupSleep();
        }
        
        let sleepTimer;
        function setupSleep() {
            if (sleepTimer) clearTimeout(sleepTimer);
            const m = parseInt(document.getElementById('sleep').value);
            if (m > 0 && audio) {
                sleepTimer = setTimeout(() => {
                    if (audio) audio.pause();
                    show('⏰ 定时停止激活', 'ok');
                }, m * 60 * 1000);
            }
        }
        
        function fmt(s) {
            if (!s || s === Infinity) return '00:00';
            const m = Math.floor(s / 60);
            return `${m.toString().padStart(2, '0')}:${Math.floor(s % 60).toString().padStart(2, '0')}`;
        }
        
        function show(msg, type) {
            const bar = document.getElementById('status');
            bar.textContent = (type === 'ok' ? '✓ ' : type === 'err' ? '✗ ' : 'ℹ ') + msg;
            bar.style.background = type === 'ok' ? '#4caf50' : type === 'err' ? '#f44336' : '#2196f3';
            setTimeout(() => { 
                bar.textContent = '✓ 准备就绪'; 
                bar.style.background = '#333'; 
            }, 4000);
        }
        
        setInterval(() => {
            if (audio) {
                document.getElementById('play-btn').textContent = audio.paused ? '▶' : '⏸';
            }
        }, 500);
        
        window.addEventListener('beforeunload', saveProg);
        setInterval(() => { if (audio && !audio.paused) saveProg(); }, 30000);
    </script>
</body>
</html>
"""

ADMIN_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>管理后台</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, sans-serif; background: #f5f5f5; color: #333; }
        .header { background: linear-gradient(135deg, #d32f2f, #b71c1c); color: white; padding: 20px; text-align: center; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .tab { padding: 10px 20px; background: white; border: 2px solid #ddd; border-radius: 4px; cursor: pointer; font-weight: 500; }
        .tab.active { background: #d32f2f; color: white; border-color: #d32f2f; }
        .content { display: none; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .content.active { display: block; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f5f5f5; font-weight: 600; }
        .logs { background: #f9f9f9; padding: 15px; border-radius: 4px; max-height: 400px; overflow-y: auto; font-family: monospace; font-size: 12px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
        .btn { padding: 8px 16px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; }
        .btn-del { background: #f44336; color: white; }
        .btn-add { background: #2196f3; color: white; }
        .input { padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; width: 100%; max-width: 300px; }
        .select { padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; width: 100%; max-width: 300px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚙️ 管理后台</h1>
        <p>系统管理与监控</p>
    </div>
    
    <div class="container">
        <div class="tabs">
            <div class="tab active" onclick="switchTab('logs')">📋 日志</div>
            <div class="tab" onclick="switchTab('users')">👥 用户</div>
            <div class="tab" onclick="switchTab('online')">🌐 在线</div>
            <div class="tab" onclick="switchTab('behavior')">📊 行为</div>
            <div class="tab" onclick="switchTab('paths')">📁 路径</div>
        </div>
        
        <div id="logs" class="content active">
            <h2>服务器日志</h2>
            <button class="btn btn-add" onclick="refreshLogs()">🔄 刷新</button>
            <div class="logs" id="log-content"></div>
        </div>
        
        <div id="users" class="content">
            <h2>用户管理</h2>
            <div>
                <input class="input" type="text" id="new-user" placeholder="新用户名" />
                <input class="input" type="password" id="new-pass" placeholder="密码(8字符以上)" />
                <button class="btn btn-add" onclick="addUser()">➕ 添加用户</button>
            </div>
            <table>
                <thead><tr><th>用户名</th><th>操作</th></tr></thead>
                <tbody id="user-list"></tbody>
            </table>
        </div>
        
        <div id="online" class="content">
            <h2>在线用户</h2>
            <button class="btn btn-add" onclick="loadOnline()">🔄 刷新</button>
            <table>
                <thead><tr><th>用户</th><th>IP</th><th>设备</th><th>登录时间</th><th>最后活动</th></tr></thead>
                <tbody id="online-list"></tbody>
            </table>
        </div>
        
        <div id="behavior" class="content">
            <h2>用户行为</h2>
            <select class="select" id="behavior-user" onchange="showBehavior()">
                <option>选择用户...</option>
            </select>
            <div id="behavior-content"></div>
        </div>
        
        <div id="paths" class="content">
            <h2>用户路径</h2>
            <div>
                <select class="select" id="path-user" onchange="loadUserPaths()">
                    <option>选择用户...</option>
                </select>
                <input class="input" type="text" id="path-input" placeholder="新路径(如: /mnt/xxx)" />
                <button class="btn btn-add" onclick="addPath()">➕ 添加路径</button>
            </div>
            <div id="path-content"></div>
        </div>
    </div>
    
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        let token = urlParams.get('token') || localStorage.getItem('token');
        
        function switchTab(name) {
            document.querySelectorAll('.content').forEach(e => e.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(e => e.classList.remove('active'));
            document.getElementById(name).classList.add('active');
            event.target.classList.add('active');
            if (name === 'logs') refreshLogs();
            else if (name === 'users') loadUsers();
            else if (name === 'online') loadOnline();
            else if (name === 'behavior') loadBehaviorUsers();
            else if (name === 'paths') loadUsersList();
        }
        
        function refreshLogs() {
            fetch('/api/admin/logs', { headers: { 'Authorization': 'Bearer ' + token } })
                .then(r => r.json()).then(d => {
                    const logText = d.logs.map(l => l.replace(/</g, '&lt;').replace(/>/g, '&gt;')).join('');
                    document.getElementById('log-content').innerHTML = logText || '(无日志)';
                }).catch(e => alert('加载日志失败: ' + e.message));
        }
        
        function loadUsers() {
            fetch('/api/admin/users', { headers: { 'Authorization': 'Bearer ' + token } })
                .then(r => r.json()).then(d => {
                    document.getElementById('user-list').innerHTML = d.users.map(u => 
                        `<tr><td>${u.username}</td><td>${u.username !== 'admin' ? '<button class="btn btn-del" onclick="delUser(\\''+u.username+'\\')">🗑️ 删除</button>' : '👑 管理员'}</td></tr>`
                    ).join('');
                }).catch(e => alert('加载用户失败: ' + e.message));
        }
        
        function addUser() {
            const u = document.getElementById('new-user').value.trim();
            const p = document.getElementById('new-pass').value.trim();
            if (!u || !p) return alert('请输入用户名和密码');
            if (u.length < 3) return alert('用户名至少3个字符');
            if (p.length < 8) return alert('密码至少8个字符');
            
            fetch('/api/admin/add-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                body: JSON.stringify({username: u, password: p})
            }).then(r => r.json()).then(d => {
                if (d.success) {
                    alert('✓ 添加成功');
                    document.getElementById('new-user').value = '';
                    document.getElementById('new-pass').value = '';
                    loadUsers();
                } else alert('✗ ' + (d.error || '添加失败'));
            }).catch(e => alert('错误: ' + e.message));
        }
        
        function delUser(u) {
            if (!confirm('⚠️  确定删除用户 ' + u + '？')) return;
            fetch('/api/admin/delete-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                body: JSON.stringify({username: u})
            }).then(r => r.json()).then(d => {
                if (d.success) { alert('✓ 删除成功'); loadUsers(); }
                else alert('✗ ' + (d.error || '删除失败'));
            }).catch(e => alert('错误: ' + e.message));
        }
        
        function loadOnline() {
            fetch('/api/admin/online-users', { headers: { 'Authorization': 'Bearer ' + token } })
                .then(r => r.json()).then(d => {
                    document.getElementById('online-list').innerHTML = d.users.length === 0 
                        ? '<tr><td colspan="5" style="text-align:center; color:#999;">暂无在线用户</td></tr>'
                        : d.users.map(u => 
                        `<tr><td>${u.username}</td><td>${u.ip}</td><td>${u.device}</td><td>${u.login_time}</td><td>${u.last_activity}</td></tr>`
                    ).join('');
                }).catch(e => alert('加载失败: ' + e.message));
        }
        
        function loadBehaviorUsers() {
            fetch('/api/admin/users', { headers: { 'Authorization': 'Bearer ' + token } })
                .then(r => r.json()).then(d => {
                    document.getElementById('behavior-user').innerHTML = '<option>选择用户...</option>' + 
                        d.users.map(u => `<option>${u.username}</option>`).join('');
                }).catch(e => alert('加载用户失败: ' + e.message));
        }
        
        function showBehavior() {
            const u = document.getElementById('behavior-user').value;
            if (!u || u === '选择用户...') return;
            fetch(`/api/admin/user-behavior?user=${encodeURIComponent(u)}`, { 
                headers: { 'Authorization': 'Bearer ' + token } 
            })
                .then(r => r.json()).then(d => {
                    if (d.behavior.length === 0) {
                        document.getElementById('behavior-content').innerHTML = '<p style="color:#999;text-align:center;">📭 无行为记录</p>';
                        return;
                    }
                    let html = '<table><tr><th>时间</th><th>IP</th><th>动作</th><th>详情</th></tr>';
                    d.behavior.forEach(b => {
                        html += `<tr><td>${b.time}</td><td>${b.ip}</td><td><strong>${b.action}</strong></td><td>${JSON.stringify(b.details)}</td></tr>`;
                    });
                    html += '</table>';
                    document.getElementById('behavior-content').innerHTML = html;
                }).catch(e => alert('加载失败: ' + e.message));
        }
        
        function loadUsersList() {
            fetch('/api/admin/users', { headers: { 'Authorization': 'Bearer ' + token } })
                .then(r => r.json()).then(d => {
                    document.getElementById('path-user').innerHTML = '<option>选择用户...</option>' + 
                        d.users.map(u => `<option>${u.username}</option>`).join('');
                }).catch(e => alert('加载用户失败: ' + e.message));
        }
        
        function loadUserPaths() {
            const u = document.getElementById('path-user').value;
            if (!u || u === '选择用户...') return;
            fetch('/api/admin/user-paths', { headers: { 'Authorization': 'Bearer ' + token } })
                .then(r => r.json()).then(d => {
                    const paths = d.paths[u] || [];
                    document.getElementById('path-content').innerHTML = paths.length === 0 
                        ? '<p style="color:#999;">📭 该用户暂无额外路径</p>'
                        : '<ul style="margin-left:20px;">' + paths.map(p => `<li>${p}</li>`).join('') + '</ul>';
                }).catch(e => alert('加载失败: ' + e.message));
        }
        
        function addPath() {
            const u = document.getElementById('path-user').value;
            const p = document.getElementById('path-input').value.trim();
            if (!u || !p || u === '选择用户...') return alert('请选择用户并输入路径');
            
            fetch('/api/admin/set-user-path', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                body: JSON.stringify({username: u, paths: [p]})
            }).then(r => r.json()).then(d => {
                if (d.success) { 
                    alert('✓ 添加成功');
                    document.getElementById('path-input').value = '';
                    loadUserPaths(); 
                }
                else alert('✗ ' + (d.error || '添加失败'));
            }).catch(e => alert('错误: ' + e.message));
        }
    </script>
</body>
</html>
"""




def main():
    logger.info("Starting Audiobook Server...")
    logger.info("Listening on [%s]:%d", CONFIG['host'], CONFIG['port'])
    logger.info("Audio directory: %s", CONFIG['audio_dir'])
    server = HTTPServerV6((CONFIG['host'], CONFIG['port']), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()

if __name__ == '__main__':
    main()
            
