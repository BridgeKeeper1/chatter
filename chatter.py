#!/usr/bin/env python3
"""
Chatter - Optimized Flask + Socket.IO Chat Application
Real-time messaging with immediate message delivery and no refresh required
"""

import os
import re
import io
import json
import time
import random
import string
import sqlite3
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash
from functools import wraps
from collections import defaultdict
import secrets
import threading

from flask import (
    Flask,
    request,
    jsonify,
    session,
    send_from_directory, 
    render_template_string, 
    abort, 
    redirect, 
    url_for,
    g,
    Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room
import html as _html
import hmac
import hashlib
import base64 as _b64
import shutil 

import sqlite3
import csv
import io
import json
import markdown
import bleach
import secrets
import string
import requests
import difflib
import zlib

# ============================================================================
# EMERGENCY SHUTDOWN SYSTEM - Consolidated into main file
# ============================================================================

# Emergency shutdown state tracking
emergency_shutdown_active = False
emergency_shutdown_timestamp = None
emergency_shutdown_trigger = None
emergency_shutdown_admin = None
emergency_shutdown_snapshot = {}
emergency_shutdown_locked_users = set()
emergency_recovery_stage = 0  # 0=full shutdown, 1=read-only, 2=chat-only, 3=full recovery

# Emergency shutdown logging
emergency_shutdown_log = []
def _emergency_log(message: str, level: str = "INFO", admin: str = None):
    """Log emergency shutdown events with timestamp."""
    try:
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message,
            'admin': admin or 'SYSTEM',
            'stage': emergency_recovery_stage
        }
        emergency_shutdown_log.append(log_entry)
        
        # Keep only last 1000 log entries to prevent memory issues
        if len(emergency_shutdown_log) > 1000:
            emergency_shutdown_log[:] = emergency_shutdown_log[-1000:]
            
        # Also log to console for debugging
        print(f"[EMERGENCY] {timestamp} [{level}] {message}")
        
    except Exception as e:
        print(f"[EMERGENCY] Failed to log: {e}")

def _emergency_create_snapshot(get_db_func, get_setting_func, connected_sockets, spam_strikes):
    """Create a snapshot of current system state for recovery analysis."""
    try:
        snapshot = {
            'timestamp': datetime.utcnow().isoformat(),
            'active_users': [],
            'recent_messages': [],
            'system_settings': {},
            'database_stats': {},
            'socket_connections': len(connected_sockets),
            'spam_strikes': dict(spam_strikes),
            'maintenance_mode': get_setting_func('MAINTENANCE_MODE', '0')
        }
        
        # Capture active users (last 5 minutes)
        try:
            db = get_db_func()
            cur = db.cursor()
            five_min_ago = datetime.utcnow() - timedelta(minutes=5)
            cur.execute("""
                SELECT DISTINCT username FROM messages 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC LIMIT 100
            """, (five_min_ago,))
            snapshot['active_users'] = [row[0] for row in cur.fetchall()]
        except Exception as e:
            snapshot['active_users'] = ['Error capturing users: ' + str(e)]
        
        # Capture recent messages (last 10)
        try:
            db = get_db_func()
            cur = db.cursor()
            cur.execute("""
                SELECT username, text, timestamp FROM messages 
                ORDER BY timestamp DESC LIMIT 10
            """)
            snapshot['recent_messages'] = [
                {'user': row[0], 'text': row[1][:100], 'time': str(row[2])}
                for row in cur.fetchall()
            ]
        except Exception as e:
            snapshot['recent_messages'] = ['Error capturing messages: ' + str(e)]
        
        # Capture key system settings
        try:
            settings_to_capture = [
                'MAINTENANCE_MODE', 'PUBLIC_ENABLED', 'DM_ENABLED', 'GDM_ENABLED',
                'ANNOUNCEMENTS_ONLY', 'SPAM_MAX_CHARS', 'SPAM_SENSITIVITY'
            ]
            for setting in settings_to_capture:
                snapshot['system_settings'][setting] = get_setting_func(setting, 'N/A')
        except Exception as e:
            snapshot['system_settings'] = {'error': str(e)}
        
        # Database statistics
        try:
            db = get_db_func()
            cur = db.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]
            
            for table in tables[:10]:  # Limit to first 10 tables
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {table}")
                    snapshot['database_stats'][table] = cur.fetchone()[0]
                except Exception:
                    snapshot['database_stats'][table] = 'Error'
        except Exception as e:
            snapshot['database_stats'] = {'error': str(e)}
        
        return snapshot
        
    except Exception as e:
        return {'error': f'Failed to create snapshot: {e}', 'timestamp': datetime.utcnow().isoformat()}

def _emergency_backup_database(db_path):
    """Create a backup of the database for post-incident analysis."""
    try:
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_path = f"{db_path}.emergency_backup_{timestamp}"
        
        # Create backup
        shutil.copy2(db_path, backup_path)
        
        _emergency_log(f"Database backup created: {backup_path}", "INFO")
        return backup_path
        
    except Exception as e:
        _emergency_log(f"Failed to create database backup: {e}", "ERROR")
        return None

def emergency_shutdown_activate(trigger: str, admin: str = None, auto_backup: bool = True, 
                               db_path=None, get_db_func=None, get_setting_func=None, 
                               set_setting_func=None, connected_sockets=None, spam_strikes=None,
                               notify_func=None):
    """
    Activate emergency shutdown mode.
    
    Args:
        trigger: Reason for shutdown (e.g., "ADMIN_COMMAND", "SECURITY_INCIDENT", "SYSTEM_ERROR")
        admin: Admin username who triggered shutdown (if applicable)
        auto_backup: Whether to automatically create database backup
    """
    global emergency_shutdown_active, emergency_shutdown_timestamp, emergency_shutdown_trigger
    global emergency_shutdown_admin, emergency_shutdown_snapshot, emergency_recovery_stage
    
    try:
        if emergency_shutdown_active:
            _emergency_log(f"Emergency shutdown already active, ignoring duplicate trigger: {trigger}", "WARNING", admin)
            return False
        
        # Activate emergency mode
        emergency_shutdown_active = True
        emergency_shutdown_timestamp = datetime.utcnow()
        emergency_shutdown_trigger = trigger
        emergency_shutdown_admin = admin
        emergency_recovery_stage = 0
        
        _emergency_log(f"EMERGENCY SHUTDOWN ACTIVATED - Trigger: {trigger}", "CRITICAL", admin)
        
        # Create system snapshot
        if get_db_func and get_setting_func and connected_sockets is not None and spam_strikes is not None:
            emergency_shutdown_snapshot = _emergency_create_snapshot(
                get_db_func, get_setting_func, connected_sockets, spam_strikes
            )
            _emergency_log("System snapshot created", "INFO", admin)
        
        # Create database backup if requested
        if auto_backup and db_path:
            backup_path = _emergency_backup_database(db_path)
            if backup_path:
                emergency_shutdown_snapshot['backup_path'] = backup_path
        
        # Set maintenance mode
        if set_setting_func:
            try:
                set_setting_func('MAINTENANCE_MODE', '1')
                _emergency_log("Maintenance mode activated", "INFO", admin)
            except Exception as e:
                _emergency_log(f"Failed to set maintenance mode: {e}", "ERROR", admin)
        
        # Notify all connected users
        if notify_func:
            try:
                notify_func("Emergency maintenance in progress. Please stand by.")
            except Exception as e:
                _emergency_log(f"Failed to notify users: {e}", "ERROR", admin)
        
        _emergency_log("Emergency shutdown activation complete", "INFO", admin)
        return True
        
    except Exception as e:
        _emergency_log(f"Failed to activate emergency shutdown: {e}", "ERROR", admin)
        return False

def emergency_shutdown_deactivate(admin: str = None, set_setting_func=None, notify_func=None):
    """Deactivate emergency shutdown and return to normal operation."""
    global emergency_shutdown_active, emergency_recovery_stage
    
    try:
        if not emergency_shutdown_active:
            _emergency_log("Emergency shutdown not active, ignoring deactivation", "WARNING", admin)
            return False
        
        _emergency_log("EMERGENCY SHUTDOWN DEACTIVATION STARTED", "CRITICAL", admin)
        
        # Full recovery
        emergency_recovery_stage = 3
        emergency_shutdown_active = False
        
        # Remove maintenance mode
        if set_setting_func:
            try:
                set_setting_func('MAINTENANCE_MODE', '0')
                _emergency_log("Maintenance mode deactivated", "INFO", admin)
            except Exception as e:
                _emergency_log(f"Failed to remove maintenance mode: {e}", "ERROR", admin)
        
        # Clear locked users
        emergency_shutdown_locked_users.clear()
        _emergency_log("All user locks cleared", "INFO", admin)
        
        # Notify users
        if notify_func:
            try:
                notify_func("Emergency maintenance complete. Normal operation resumed.")
            except Exception as e:
                _emergency_log(f"Failed to notify users of recovery: {e}", "ERROR", admin)
        
        _emergency_log("EMERGENCY SHUTDOWN DEACTIVATION COMPLETE", "CRITICAL", admin)
        return True
        
    except Exception as e:
        _emergency_log(f"Failed to deactivate emergency shutdown: {e}", "ERROR", admin)
        return False

def emergency_shutdown_set_stage(stage: int, admin: str = None):
    """
    Set recovery stage for gradual system restoration.
    
    Stages:
    0 = Full shutdown (no operations)
    1 = Read-only mode (view messages only)
    2 = Chat-only mode (messaging enabled, no login/registration)
    3 = Full recovery (all operations enabled)
    """
    global emergency_recovery_stage
    
    try:
        if not emergency_shutdown_active and stage != 3:
            _emergency_log(f"Cannot set stage {stage} - emergency shutdown not active", "WARNING", admin)
            return False
        
        old_stage = emergency_recovery_stage
        emergency_recovery_stage = max(0, min(3, stage))
        
        stage_names = {
            0: "Full Shutdown",
            1: "Read-Only Mode", 
            2: "Chat-Only Mode",
            3: "Full Recovery"
        }
        
        _emergency_log(f"Recovery stage changed: {old_stage} -> {emergency_recovery_stage} ({stage_names.get(emergency_recovery_stage, 'Unknown')})", "INFO", admin)
        
        # If moving to full recovery, deactivate emergency mode
        if emergency_recovery_stage == 3:
            return emergency_shutdown_deactivate(admin)
        
        return True
        
    except Exception as e:
        _emergency_log(f"Failed to set recovery stage: {e}", "ERROR", admin)
        return False

def emergency_shutdown_lock_user(username: str, admin: str = None):
    """Lock a specific user during emergency shutdown."""
    try:
        emergency_shutdown_locked_users.add(username)
        _emergency_log(f"User locked: {username}", "INFO", admin)
        return True
    except Exception as e:
        _emergency_log(f"Failed to lock user {username}: {e}", "ERROR", admin)
        return False

def emergency_shutdown_unlock_user(username: str, admin: str = None):
    """Unlock a specific user during emergency shutdown."""
    try:
        emergency_shutdown_locked_users.discard(username)
        _emergency_log(f"User unlocked: {username}", "INFO", admin)
        return True
    except Exception as e:
        _emergency_log(f"Failed to unlock user {username}: {e}", "ERROR", admin)
        return False

def _emergency_check_gate(username: str = None, operation: str = "general", superadmins=None) -> tuple[bool, str]:
    """
    Check if operation is allowed during emergency shutdown.
    
    Returns:
        (allowed: bool, reason: str)
    """
    try:
        if not emergency_shutdown_active:
            return True, ""
        
        # Superadmins can always operate (for recovery purposes)
        if username and superadmins and username in superadmins:
            return True, ""
        
        # Check if user is specifically locked
        if username and username in emergency_shutdown_locked_users:
            return False, "Your account is temporarily locked during emergency maintenance."
        
        # Check recovery stage permissions
        if emergency_recovery_stage == 0:
            # Full shutdown - no operations allowed
            return False, "System is in emergency maintenance mode. All operations are temporarily disabled."
        
        elif emergency_recovery_stage == 1:
            # Read-only mode - only viewing allowed
            if operation in ['view', 'read', 'get']:
                return True, ""
            return False, "System is in read-only emergency mode. Only viewing is currently allowed."
        
        elif emergency_recovery_stage == 2:
            # Chat-only mode - messaging allowed, no login/registration
            if operation in ['view', 'read', 'get', 'message', 'chat']:
                return True, ""
            if operation in ['login', 'register', 'upload', 'settings']:
                return False, "System is in limited emergency mode. Login and registration are temporarily disabled."
            return False, "System is in limited emergency mode. Some features are temporarily disabled."
        
        elif emergency_recovery_stage == 3:
            # Full recovery - all operations allowed
            return True, ""
        
        # Default: block unknown operations during emergency
        return False, "System is in emergency maintenance mode."
        
    except Exception as e:
        _emergency_log(f"Emergency gate check failed: {e}", "ERROR")
        # Fail safe: block operations during errors
        return False, "System is experiencing technical difficulties."

def _emergency_auto_trigger_check(get_db_func=None, db_path=None):
    """Check for conditions that should automatically trigger emergency shutdown."""
    try:
        # Skip if already in emergency mode
        if emergency_shutdown_active:
            return
        
        # Check database connectivity
        if get_db_func:
            try:
                db = get_db_func()
                cur = db.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            except Exception as e:
                _emergency_log(f"Database connectivity check failed: {e}", "ERROR")
                emergency_shutdown_activate("DATABASE_CONNECTION_FAILURE", auto_backup=False)
                return
        
        # Check memory usage (basic check)
        try:
            import psutil
            memory_percent = psutil.virtual_memory().percent
            if memory_percent > 95:  # 95% memory usage
                _emergency_log(f"High memory usage detected: {memory_percent}%", "WARNING")
                emergency_shutdown_activate("RESOURCE_EXHAUSTION_MEMORY", auto_backup=True)
                return
        except ImportError:
            # psutil not available, skip memory check
            pass
        except Exception as e:
            _emergency_log(f"Memory check failed: {e}", "WARNING")
        
        # Check for excessive error rates (basic implementation)
        # This would need to be integrated with actual error tracking
        
    except Exception as e:
        _emergency_log(f"Auto-trigger check failed: {e}", "ERROR")

def get_emergency_status():
    """Get current emergency shutdown status."""
    return {
        'active': emergency_shutdown_active,
        'timestamp': emergency_shutdown_timestamp.isoformat() if emergency_shutdown_timestamp else None,
        'trigger': emergency_shutdown_trigger,
        'admin': emergency_shutdown_admin,
        'recovery_stage': emergency_recovery_stage,
        'locked_users': list(emergency_shutdown_locked_users),
        'log_entries': len(emergency_shutdown_log),
        'recent_logs': emergency_shutdown_log[-10:] if emergency_shutdown_log else [],
        'snapshot': emergency_shutdown_snapshot
    }

def get_emergency_logs(page=1, per_page=50):
    """Get emergency shutdown logs with pagination."""
    try:
        # Calculate pagination
        total_logs = len(emergency_shutdown_log)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        # Get logs (most recent first)
        logs = list(reversed(emergency_shutdown_log))[start_idx:end_idx]
        
        return {
            'logs': logs,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_logs,
                'pages': (total_logs + per_page - 1) // per_page
            }
        }
        
    except Exception as e:
        return {'error': f'Failed to get logs: {e}'}

# ============================================================================
# END EMERGENCY SHUTDOWN SYSTEM
# ============================================================================


SUPPORTED_LANGUAGES = [
    ("en", "English"),
    ("es", "Spanish"),
    ("fr", "French"),
    ("de", "German"),
    ("it", "Italian"),
    ("pt", "Portuguese"),
    ("ru", "Russian"),
    ("ja", "Japanese"),
    ("ko", "Korean"),
    ("zh-CN", "Chinese (Simplified)"),
    ("zh-TW", "Chinese (Traditional)"),
    ("hi", "Hindi"),
    ("ar", "Arabic"),
]
SUPPORTED_LANGUAGE_CODES = {code for code, _ in SUPPORTED_LANGUAGES}

# Optional timezone conversion to America/New_York
try:
    from zoneinfo import ZoneInfo
    NY_TZ = ZoneInfo("America/New_York")
except Exception:
    NY_TZ = None

def to_ny_time(dt):
    if not dt:
        return None
    try:
        if NY_TZ is None:
            return dt.isoformat()
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(NY_TZ).isoformat()
    except Exception:
        return dt.isoformat()

def _client_id_from_request() -> str:
    try:
        cid = (request.cookies.get('client_id') or '').strip()
        if not cid:
            cid = (request.headers.get('X-Client-ID') or '').strip()
        return cid
    except Exception:
        return ''

def _is_device_banned(cid: str) -> bool:
    if not cid:
        return False

def _b64u(data: bytes) -> str:
    return _b64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def _b64ud(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return _b64.urlsafe_b64decode(s + pad)

def _issue_dbx_token(user: str, ttl_seconds: int = 600) -> str:
    try:
        exp = int(time.time()) + int(ttl_seconds)
        payload = json.dumps({'u': user, 'exp': exp}, separators=(',',':')).encode('utf-8')
        sig = hmac.new(app.secret_key.encode('utf-8'), payload, hashlib.sha256).digest()
        return _b64u(payload) + '.' + _b64u(sig)
    except Exception:
        return ''

def _verify_dbx_token(token: str) -> str:
    try:
        if not token or '.' not in token:
            return ''
        p_b64, s_b64 = token.split('.', 1)
        payload = _b64ud(p_b64)
        sig = _b64ud(s_b64)
        good = hmac.compare_digest(hmac.new(app.secret_key.encode('utf-8'), payload, hashlib.sha256).digest(), sig)
        if not good:
            return ''
        obj = json.loads(payload.decode('utf-8'))
        if int(obj.get('exp') or 0) < int(time.time()):
            return ''
        return str(obj.get('u') or '')
    except Exception:
        return ''

def _dbx_user() -> str:
    try:
        u = session.get('username') or ''
        if u:
            return u
        tok = (
            request.headers.get('X-DBX')
            or (request.cookies.get('dbx') or '')
            or (request.args.get('dbx') or '')
        )
        return _verify_dbx_token(tok) or ''
    except Exception:
        return ''
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid,))
        return cur.fetchone() is not None
    except Exception:
        return False

def _maybe_snapshot_db_on_emergency(old_val: str, new_val: str):
    """When emergency shutdown flips from 0 -> 1, take a best-effort DB snapshot.

    This is intentionally lightweight: it copies the SQLite file and logs the event.
    """
    try:
        if old_val == '0' and new_val == '1':
            try:
                ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            except Exception:
                ts = str(int(time.time()))
            base = os.path.basename(DB_PATH)
            snap_name = f"emergency_{ts}_{base}"
            dest = os.path.join(BACKUP_DIR, snap_name)
            try:
                shutil.copy2(DB_PATH, dest)
            except Exception:
                # If copy fails, still log the attempt
                dest = ''
            meta = {'snapshot': dest or 'failed', 'db_path': DB_PATH}
            try:
                u = session.get('username') or ''
                if u:
                    meta['actor'] = u
            except Exception:
                pass
            _log_incident('emergency_shutdown', meta)
    except Exception:
        pass

# Ensure Group DM schema exists and has required columns
def _ensure_gdm_schema():
    try:
        db = get_db(); cur = db.cursor()
        # Base tables
        cur.execute('CREATE TABLE IF NOT EXISTS group_threads (id INTEGER PRIMARY KEY, name TEXT, created_by TEXT, created_at TIMESTAMP)')
        cur.execute('CREATE TABLE IF NOT EXISTS group_members (thread_id INTEGER, username TEXT)')
        cur.execute('CREATE TABLE IF NOT EXISTS group_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, thread_id INTEGER, username TEXT, text TEXT, attachment TEXT, created_at TIMESTAMP, edited INTEGER DEFAULT 0)')
        # Optional tables used by features
        try: cur.execute('CREATE TABLE IF NOT EXISTS group_bans (thread_id INTEGER, username TEXT)')
        except Exception: pass
        try: cur.execute('CREATE TABLE IF NOT EXISTS group_timeouts (thread_id INTEGER, username TEXT, until_ts INTEGER)')
        except Exception: pass
        # Columns that may be missing on older installs
        for col, default in (('locked', '0'), ('archived', '0')):
            try:
                cur.execute(f"SELECT {col} FROM group_threads LIMIT 1")
            except Exception:
                try:
                    cur.execute(f"ALTER TABLE group_threads ADD COLUMN {col} INTEGER DEFAULT {default}")
                except Exception:
                    pass
        db.commit()
    except Exception:
        try:
            get_db().rollback()
        except Exception:
            pass

def _seed_defaults_if_needed():
    try:
        if str(get_setting('DEFAULTS_SEEDED','0')) == '1':
            return
        defaults_on = [
            'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED',
            'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
            'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_VIEW_HISTORY','MC_SEARCH_MESSAGES','MC_BROADCAST_MESSAGE','MC_PIN_MESSAGE',
            'GD_LOCK_GROUP','GD_UNLOCK_GROUP','GD_REMOVE_USER','GD_TRANSFER_OWNERSHIP','GD_ARCHIVE_GROUP','GD_DELETE_GROUP','GD_CLOSE_ALL_DMS','GD_DM_AS_SYSTEM','GD_SAVE_DM_LOGS','GD_FORCE_LEAVE_GROUP',
            'SEC_DEVICE_BAN_ON_LOGIN','SEC_REG_BAN_SIMILAR_CID'
        ]
        for k in defaults_on:
            try:
                set_setting(k, '1')
            except Exception:
                pass
        try:
            spam_defaults = {
                'SPAM_MAX_CHARS': '1000',
                'SPAM_MAX_BYTES': '4000',
                'SPAM_WINDOW_SECONDS': '10',
                'SPAM_MIN_GAP_SECONDS': '0.7',
                'SPAM_MAX_PER_WINDOW': '8',
                'SPAM_SLOW_SECONDS': '10',
                'SPAM_SENSITIVITY': '1.0',
                'SPAM_AUTO_SPLIT_THRESHOLD': '800',
            }
            for sk, sv in spam_defaults.items():
                try:
                    set_setting(sk, sv)
                except Exception:
                    pass
            set_setting('DEFAULTS_SEEDED', '1')
        except Exception:
            pass
    except Exception:
        pass

def _log_incident(kind: str, meta: dict | None = None):
    """Append a structured incident line to the log file.

    Used for emergency shutdown and other critical events.
    """
    try:
        ts = _format_web_timestamp(datetime.utcnow())
        payload = {
            'kind': kind,
            'time': ts,
        }
        try:
            if isinstance(meta, dict):
                payload.update(meta)
        except Exception:
            pass
        _append_log_line(json.dumps(payload, ensure_ascii=False))
    except Exception:
        pass

# ---- Admins UI script injection (registered later to avoid NameError) ----
def _inject_admins_js(resp):
    # No-op: do not inject Admins section into right sidebar
    return resp

def admins_js():
    js = r'''(() => {
const SELS=['#rightOnlineList','#usersList','#users','.users-list','.usersPane','.right-col .users','.users','.users-container','.sidebar .users','#right .users'];
function bySel(){ for(const s of SELS){ const el=document.querySelector(s); if(el) return el; } return null; }
function findUsersHeading(){
  const cands = Array.from(document.querySelectorAll('h1,h2,h3,div,span'));
  for(const el of cands){
    const t = (el.textContent||'').trim();
    if(/^users\b/i.test(t)) return el;
  }
  return null;
}
function hostOrFallback(){
  const host = bySel(); if(host) return host.parentNode || host;
  const hdr = findUsersHeading(); if(hdr) return hdr.parentNode || document.body;
  return document.querySelector('.right-col') || document.querySelector('#right') || document.querySelector('.sidebar') || document.body;
}
function badge(role){ return role==='superadmin' ? '<span style="margin-left:6px;padding:2px 6px;border-radius:10px;background:#7c3aed;color:#fff;font-size:10px">SUPER</span>' : '<span style="margin-left:6px;padding:2px 6px;border-radius:10px;background:#2563eb;color:#fff;font-size:10px">ADMIN</span>'; }
function render(list){
  const host=bySel(); const target=hostOrFallback(); if(!target) return;
  let sec=document.getElementById('admins-section');
  if(!sec){
    sec=document.createElement('div'); sec.id='admins-section'; sec.style.margin='0 0 8px 0';
    if(host){ host.prepend(sec); }
    else if(target){ target.insertBefore(sec, target.firstChild); }
  }
  const items=(list||[]).map(function(a){ return '<div class="admin-item" style="display:flex;align-items:center;gap:6px;padding:4px 0"><span class="dot" style="width:12px;height:12px;border-radius:50%;background:#22c55e;display:inline-block"></span><span>'+a.username+'</span>'+badge(a.role)+'</div>'; }).join('');
  sec.innerHTML = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><strong>Admins</strong><span style="font-size:12px;color:#9ca3af">(' + (list||[]).length + ' online)</span></div>' + items;
}
function mirror(list){ const host=bySel(); if(!host) return; host.querySelectorAll('.admin-mirror').forEach(function(el){ el.remove(); }); (list||[]).forEach(function(a){ const el=document.createElement('div'); el.className='admin-mirror'; el.style.display='flex'; el.style.alignItems='center'; el.style.gap='6px'; el.style.padding='4px 0'; el.innerHTML = '<span class="dot" style="width:12px;height:12px;border-radius:50%;background:#22c55e;display:inline-block"></span><span>'+a.username+'</span>'+badge(a.role); host.appendChild(el); }); }
function cleanStatuses(){
  const root = bySel() || document;
  const words=new Set(['ONLINE','DND','IDLE','OFFLINE','AWAY','BUSY']);
  const isHeader = (t) => /(ONLINE|OFFLINE)\s*—/i.test(t);
  const wipe = (node) => { if(node) node.textContent=''; };
  ['.status','.user-status','.presence','.presence-text','.status-text'].forEach(function(q){ root.querySelectorAll(q).forEach(wipe); });
  root.querySelectorAll('span,small,div,p').forEach(function(el){
    if(el.childElementCount===0){
      const t=(el.textContent||'').trim();
      if(!t) return;
      if(isHeader(t)) return; // keep section headers
      if(words.has(t.toUpperCase())) el.textContent='';
      else if(/^(ONLINE|DND|IDLE|OFFLINE|AWAY|BUSY)\b/i.test(t)) el.textContent='';
    }
  });
}
function observeStatuses(){
  try{
    const root = bySel() || document.body; if(!root) return;
    const mo = new MutationObserver(()=>cleanStatuses());
    mo.observe(root, {subtree:true, childList:true, characterData:true});
  }catch(e){}
}
async function tick(){ try{ const r=await fetch('/api/admins/online',{credentials:'same-origin'}); const j=await r.json(); if(r.ok&&j&&j.ok){ const list=j.admins||[]; render(list); mirror(list); cleanStatuses(); } }catch(e){} }
function ensureAdminDropdown(){ if(document.getElementById('admin-dropdown')) return; const b=document.createElement('div'); b.id='admin-dropdown'; b.style.position='fixed'; b.style.top='12px'; b.style.right='12px'; b.style.zIndex='9999'; b.innerHTML = '\
<div style="position:relative">\
  <button id="admBtn" style="background:#111827;color:#e5e7eb;border:1px solid #374151;border-radius:8px;padding:8px 10px;cursor:pointer">Admin ▾</button>\
  <div id="admMenu" style="position:absolute;right:0;margin-top:6px;background:#0b1020;border:1px solid #374151;border-radius:8px;display:none;min-width:180px;box-shadow:0 10px 20px rgba(0,0,0,0.4)">\
    <a href="/admin/create_user" style="display:block;padding:8px 10px;color:#e5e7eb;text-decoration:none">Create User</a>\
    <a href="/admin/dbsafe" style="display:block;padding:8px 10px;color:#e5e7eb;text-decoration:none">DB Safe</a>\
    <a href="/dbx" style="display:block;padding:8px 10px;color:#e5e7eb;text-decoration:none">DBX Unlock</a>\
  </div>\
</div>'; document.body.appendChild(b); const btn=b.querySelector('#admBtn'); const menu=b.querySelector('#admMenu'); btn.addEventListener('click',function(){ menu.style.display = (menu.style.display==='none'||!menu.style.display) ? 'block':'none'; }); document.addEventListener('click',function(e){ if(!b.contains(e.target)){ menu.style.display='none'; } }); }
async function maybeShowAdminDropdown(){ try{ const r=await fetch('/api/me/role',{credentials:'same-origin'}); const j=await r.json(); if(r.ok && j && j.ok && (j.is_superadmin || j.is_admin)) { ensureAdminDropdown(); } }catch(e){} }
tick(); setInterval(tick, 5000); maybeShowAdminDropdown(); observeStatuses();
})();
'''
    from flask import make_response
    resp = make_response(js)
    resp.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    return resp

def _rand_code(n=16):
    try:
        alphabet = string.ascii_uppercase + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(n))
    except Exception:
        return 'X'*n

def _get_downtime_code():
    try:
        code = get_setting('DOWNTIME_CODE','') or ''
        if not code:
            code = _rand_code(16)
            set_setting('DOWNTIME_CODE', code)
        return code
    except Exception:
        return _rand_code(16)

# ===================== Superadmin: Create User =====================
def admin_create_user():
    u = session.get('username') or ''
    if not is_superadmin(u):
        return redirect('/')
    if request.method == 'GET':
        html = (
            "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Create User</title><style>body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#0f172a;color:#e5e7eb} .card{max-width:520px;margin:24px auto;background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px} input,select,button{background:#0b1020;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:8px;width:100%;box-sizing:border-box} label{display:block;margin:10px 0 6px} button{cursor:pointer} button:hover{filter:brightness(1.1)}</style></head><body>"
            "<div class='card'><h3 style='margin:0 0 12px'>Create User</h3>"
            "<form method='POST'><label>Username</label><input name='username' placeholder='username' required>"
            "<label>Password</label><input type='password' name='password' placeholder='password' required>"
            "<label>Role (optional)</label><input name='role' placeholder='role e.g. admin or user'>"
            "<div style='height:12px'></div><button type='submit'>Create</button></form>"
            "<div style='height:8px'></div><a href='/' style='color:#93c5fd'>Back</a></div></body></html>"
        )
        return html
    # POST
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    role = (request.form.get('role') or '').strip() or None
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    try:
        db = get_db(); cur = db.cursor()
        # Users table schema
        cols, pk, has_rowid = _dbx_schema(cur, 'users')
        colnames = {c['name'] for c in cols}
        # Check uniqueness
        try:
            cur.execute('SELECT 1 FROM users WHERE username=? LIMIT 1', (username,))
            if cur.fetchone():
                return jsonify({'error': 'username already exists'}), 409
        except Exception:
            pass
        # Hash password
        try:
            from werkzeug.security import generate_password_hash
            pwh = generate_password_hash(password)
        except Exception:
            pwh = password
        values = {}
        # Required fields based on available columns
        if 'username' in colnames:
            values['username'] = username
        if 'password_hash' in colnames:
            values['password_hash'] = pwh
        elif 'password' in colnames:
            values['password'] = pwh
        if role and 'role' in colnames:
            values['role'] = role
        if 'language' in colnames and 'language' not in values:
            values['language'] = 'en'
        # created_at if present
        if 'created_at' in colnames:
            try:
                values['created_at'] = to_ny_time(datetime.now(timezone.utc))
            except Exception:
                values['created_at'] = datetime.utcnow().isoformat()
        if not values:
            return jsonify({'error': 'users table does not have supported columns'}), 500
        ks = list(values.keys())
        cur.execute(
            f"INSERT INTO users (" + ','.join(ks) + ") VALUES (" + ','.join(['?']*len(ks)) + ")",
            [values[k] for k in ks]
        )
        db.commit()
        try:
            log_admin_action(u, 'create_user', target=username, details={'via':'page','is_admin': bool(role and role.lower()=='admin')})
        except Exception:
            pass
        return redirect('/'), 302
    except Exception as e:
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500

def _ensure_dbx_code():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)")
        cur.execute("SELECT value FROM app_settings WHERE key='DBX_CODE'")
        row = cur.fetchone()
        if row and row[0]:
            return row[0]
        code = _rand_code(24)
        try:
            cur.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES('DBX_CODE',?)", (code,))
            db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        return code
    except Exception:
        return _rand_code(24)

def _get_dbx_code():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key='DBX_CODE'")
        row = cur.fetchone()
        if row and row[0]:
            return row[0]
        return _ensure_dbx_code()
    except Exception:
        return _ensure_dbx_code()

# Serve uploaded files
try:
    @app.route('/uploads/<path:filename>')
    def _serve_uploads(filename):
        try:
            folder = UPLOAD_FOLDER
        except Exception:
            folder = os.path.join(os.getcwd(), 'uploads')
        return send_from_directory(folder, filename)
except Exception:
    pass

# ---- Auth decorator (must be defined before any @login_required usage) ----
from functools import wraps as _wraps_login
def login_required(fn=None):
    def decorator(f):
        @_wraps_login(f)
        def wrapper(*args, **kwargs):
            try:
                u = session.get('username') or _verify_dbx_token(request.headers.get('X-DBX') or '')
                if not u:
                    wants_json = 'application/json' in (request.headers.get('Accept','') or '') or (request.path or '').startswith('/api/')
                    return (jsonify({'error': 'not logged in'}), 401) if wants_json else redirect('/')
                g.username = u
                return f(*args, **kwargs)
            except Exception:
                return jsonify({'error': 'not logged in'}), 401
        return wrapper
    return decorator(fn) if fn else decorator

# Also expose to builtins for modules pasted without import ordering
try:
    import builtins as _bi
    if not getattr(_bi, 'login_required', None):
        _bi.login_required = login_required
except Exception:
    pass

# -------- Admin helpers for main UI --------
def _admins_from_settings():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)")
        cur.execute("SELECT value FROM app_settings WHERE key='ADMINS'")
        row = cur.fetchone()
        if not row or not row[0]:
            return set()
        raw = str(row[0])
        return set([x.strip() for x in raw.split(',') if x.strip()])
    except Exception:
        return set()

def _is_adminish(username: str) -> bool:
    try:
        if not username:
            return False
        s = username.lower()
        # Baseline default sets
        try:
            if any((u == username) or (getattr(u, 'lower', lambda: u)() == s) for u in SUPERADMINS):
                return True
        except Exception:
            pass
        try:
            if any((u == username) or (getattr(u, 'lower', lambda: u)() == s) for u in ADMINS):
                return True
        except Exception:
            pass
        # DB-backed roles and extra table
        try:
            db = get_db(); cur = db.cursor()
            try:
                cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
            except Exception:
                pass
            try:
                cur.execute('SELECT role FROM users WHERE lower(username)=? LIMIT 1', (s,))
                r = cur.fetchone()
                if r:
                    role = r[0] if not isinstance(r, sqlite3.Row) else r['role']
                    if (role or '').lower() in ('admin','superadmin'):
                        return True
            except Exception:
                pass
            try:
                cur.execute('SELECT 1 FROM extra_admins WHERE lower(username)=? LIMIT 1', (s,))
                if cur.fetchone():
                    return True
            except Exception:
                pass
        except Exception:
            pass
        return False
    except Exception:
        return False

def api_admins_online():
    try:
        # Stealth mode: hide admins from online list entirely when enabled
        try:
            if get_setting('ADMINS_STEALTH','0') == '1':
                return jsonify({'ok': True, 'admins': []})
        except Exception:
            pass
        db = get_db(); cur = db.cursor()
        # Load extra_admins set for origin tagging
        extra_set = set()
        try:
            cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
            cur.execute('SELECT username FROM extra_admins')
            for r in cur.fetchall() or []:
                try:
                    extra_set.add(r[0] if not isinstance(r, sqlite3.Row) else r['username'])
                except Exception:
                    pass
        except Exception:
            pass
        online = set()
        # 1) DB table chatter_online if present
        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chatter_online'")
            if cur.fetchone():
                try:
                    cur.execute("SELECT DISTINCT username FROM chatter_online")
                    online.update([r[0] for r in cur.fetchall() if r and r[0]])
                except Exception:
                    try:
                        cur.execute("SELECT DISTINCT user FROM chatter_online")
                        online.update([r[0] for r in cur.fetchall() if r and r[0]])
                    except Exception:
                        pass
        except Exception:
            pass
        # 2) In-memory trackers
        try:
            online.update(list(getattr(globals().get('online_users', {}), 'keys', lambda: [])()))
        except Exception:
            try:
                online.update(list(online_users.keys()))
            except Exception:
                pass
        try:
            vals = list(getattr(globals().get('connected_sockets', {}), 'values', lambda: [])())
            if vals:
                online.update([v for v in vals if v])
        except Exception:
            try:
                online.update(list(connected_sockets.values()))
            except Exception:
                pass
        # 3) Current session user
        try:
            u = session.get('username')
            if u:
                online.add(u)
        except Exception:
            pass
        out = []
        for u in sorted(list(online)):
            try:
                if _is_adminish(u):
                    role = 'superadmin' if (("is_superadmin" in globals()) and is_superadmin(u)) else 'admin'
                    out.append({'username': u, 'role': role, 'extra': (False if role=='superadmin' else (u in extra_set))})
            except Exception:
                pass
        return jsonify({'ok': True, 'admins': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def api_admin_create_user():
    try:
        me = session.get('username')
        if not me or not (('is_superadmin' in globals()) and is_superadmin(me)):
            return jsonify({'error': 'forbidden'}), 403
        data = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        password = (data.get('password') or '').strip()
        is_admin_flag = True if data.get('is_admin') in (True, '1', 1, 'true', 'on') else False
        try:
            username = sanitize_username(username)
        except Exception:
            pass
        # Mirror register() validations
        if not username or len(username) > 20:
            return jsonify({'error': 'Invalid username (max 20 characters)'}), 400
        if not password:
            return jsonify({'error': 'Provide password'}), 400
        if username.lower() == 'system':
            return jsonify({'error': 'Reserved username'}), 400
        # Hash like register()
        try:
            from werkzeug.security import generate_password_hash as _gph
            pw_hash = _gph(password)
        except Exception:
            pw_hash = generate_password_hash(password)  # type: ignore

        db = get_db(); cur = db.cursor()
        try:
            cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, theme TEXT, avatar TEXT, bio TEXT, status TEXT, language TEXT DEFAULT \'en\', allow_dm_nonfriends INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        except Exception:
            pass
        # INSERT only (no replace) to avoid clobbering existing users
        try:
            try:
                cur.execute('INSERT INTO users (username, password_hash, language) VALUES (?, ?, ?)', (username, pw_hash, 'en'))
            except sqlite3.OperationalError:
                cur.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username taken'}), 409
        if is_admin_flag:
            try:
                cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
                cur.execute('INSERT OR REPLACE INTO extra_admins(username, created_at, created_by) VALUES (?,?,?)', (username, datetime.utcnow(), me))
            except Exception:
                pass
        db.commit()
        try:
            log_admin_action(me, 'create_user', target=username, details={'via':'api','is_admin': bool(is_admin_flag)})
        except Exception:
            pass
        try:
            socketio.emit('user_list_refresh', {'new_user': username})
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500

def api_admin_reset_password():
    try:
        me = session.get('username')
        if not me or not (('is_superadmin' in globals()) and is_superadmin(me)):
            return jsonify({'error': 'forbidden'}), 403
        data = request.get_json(silent=True) or {}
        username = sanitize_username((data.get('username') or '').strip())
        new_pw = (data.get('password') or '').strip()
        if not username or not new_pw:
            return jsonify({'error': 'missing username or password'}), 400
        # Guard: superadmins cannot reset other superadmins' passwords
        try:
            if username in SUPERADMINS and username != me:
                try:
                    log_admin_action(me, 'reset_password_blocked', target=username)
                except Exception:
                    pass
                return jsonify({'error': 'cannot reset password for another superadmin'}), 403
        except Exception:
            pass
        try:
            from werkzeug.security import generate_password_hash as _gph
            pw_hash = _gph(new_pw)
        except Exception:
            try:
                pw_hash = generate_password_hash(new_pw)  # type: ignore
            except Exception:
                pw_hash = new_pw
        db = get_db(); cur = db.cursor()
        try:
            cur.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, created_at TEXT)')
        except Exception:
            pass
        # Update if exists; otherwise create user with current timestamp
        cur.execute('INSERT OR REPLACE INTO users(username, password_hash, created_at) VALUES (?,?,COALESCE((SELECT created_at FROM users WHERE username=?),?))', (username, pw_hash, username, datetime.utcnow()))
        db.commit()
        try:
            log_admin_action(me, 'reset_password', target=username)
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500

def api_pinned():
    try:
        kind = (request.args.get('type') or 'public').lower()
        all_pins = request.args.get('all', '').lower() == 'true'
        if kind not in ('public','gdm'):
            return jsonify({'error':'bad params'}), 400
        db = get_db(); cur = db.cursor()
        _ensure_pin_table()
        if kind == 'public':
            if all_pins:
                # Return all pinned messages, ordered by created_at DESC
                cur.execute('SELECT message_id, created_at FROM pinned_messages WHERE kind=? ORDER BY created_at DESC', ('public',))
                rows = cur.fetchall()
                messages = []
                for row in rows:
                    mid = row[0]
                    try:
                        cur.execute('SELECT id, username, text, attachment, created_at FROM messages WHERE id=?', (mid,))
                        r = cur.fetchone()
                        if r:
                            messages.append({'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None, 'pinned_at': to_ny_time(row[1]) if row[1] else None})
                    except Exception:
                        pass
                return jsonify({'ok': True, 'messages': messages})
            else:
                # Return latest pinned message
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? ORDER BY created_at DESC LIMIT 1', ('public',))
                row = cur.fetchone(); mid = row[0] if row else None
                if not mid:
                    return jsonify({'ok': True, 'message': None})
                try:
                    cur.execute('SELECT id, username, text, attachment, created_at FROM messages WHERE id=?', (mid,))
                    r = cur.fetchone()
                    if not r:
                        return jsonify({'ok': True, 'message': None})
                    msg = {'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None}
                    return jsonify({'ok': True, 'message': msg})
                except Exception:
                    return jsonify({'ok': True, 'message': None})
        else:
            try:
                tid = int(request.args.get('thread_id') or 0)
            except Exception:
                tid = 0
            if not tid:
                return jsonify({'error':'bad params'}), 400
            if all_pins:
                # Return all pinned messages for this thread
                cur.execute('SELECT message_id, created_at FROM pinned_messages WHERE kind=? AND thread_id=? ORDER BY created_at DESC', ('gdm', tid))
                rows = cur.fetchall()
                messages = []
                for row in rows:
                    mid = row[0]
                    try:
                        cur.execute('SELECT id, username, text, attachment, created_at FROM group_messages WHERE id=?', (mid,))
                        r = cur.fetchone()
                        if r:
                            messages.append({'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None, 'thread_id': tid, 'pinned_at': to_ny_time(row[1]) if row[1] else None})
                    except Exception:
                        pass
                return jsonify({'ok': True, 'messages': messages})
            else:
                # Return latest pinned message for this thread
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? AND thread_id=? ORDER BY created_at DESC LIMIT 1', ('gdm', tid))
                row = cur.fetchone(); mid = row[0] if row else None
                if not mid:
                    return jsonify({'ok': True, 'message': None})
                try:
                    cur.execute('SELECT id, username, text, attachment, created_at FROM group_messages WHERE id=?', (mid,))
                    r = cur.fetchone()
                    if not r:
                        return jsonify({'ok': True, 'message': None})
                    msg = {'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None, 'thread_id': tid}
                    return jsonify({'ok': True, 'message': msg})
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def api_me_role():
    try:
        u = session.get('username') or ''
        is_sup = False
        is_adm = False
        try:
            is_sup = is_superadmin(u)
        except Exception:
            is_sup = False
        try:
            if 'is_admin' in globals() and callable(globals().get('is_admin')):
                is_adm = globals()['is_admin'](u)
            else:
                is_adm = (not is_sup) and _is_adminish(u)
        except Exception:
            is_adm = (not is_sup) and _is_adminish(u)
        return jsonify({'ok': True, 'username': u, 'is_superadmin': bool(is_sup), 'is_admin': bool(is_adm)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _bool_from_setting(v: str) -> bool:
    try:
        return str(v).strip().lower() in ('1','true','yes','on')
    except Exception:
        return False

def api_admins_resets():
    try:
        me = session.get('username') or ''
        is_sa = bool(me and (('is_superadmin' in globals()) and is_superadmin(me)))
        is_ad = False
        try:
            if 'is_admin' in globals() and callable(globals().get('is_admin')):
                is_ad = globals()['is_admin'](me)
            else:
                is_ad = _is_adminish(me)
        except Exception:
            is_ad = _is_adminish(me)
        # Allow GET for admins and superadmins; restrict POST to superadmins
        if request.method == 'GET':
            if not (is_sa or is_ad):
                return jsonify({'error': 'forbidden'}), 403
            settings = {
                # Default to ON if not set, so toggles don't appear all off on first load
                'reset_public': _bool_from_setting(get_setting('RESET_PUBLIC_IDS','1')),
                'reset_dm': _bool_from_setting(get_setting('RESET_DM_IDS','1')),
                'reset_gdm': _bool_from_setting(get_setting('RESET_GDM_IDS','1')),
                'reset_group_threads': _bool_from_setting(get_setting('RESET_GROUP_THREADS_IDS','1')),
            }
            return jsonify({'ok': True, 'settings': settings})
        else:
            if not is_sa:
                return jsonify({'error': 'forbidden'}), 403
            data = request.get_json(silent=True) or {}
            try: set_setting('RESET_PUBLIC_IDS', '1' if (data.get('reset_public') in (True, '1', 1, 'true', 'on')) else '0')
            except Exception: pass
            try: set_setting('RESET_DM_IDS', '1' if (data.get('reset_dm') in (True, '1', 1, 'true', 'on')) else '0')
            except Exception: pass
            try: set_setting('RESET_GDM_IDS', '1' if (data.get('reset_gdm') in (True, '1', 1, 'true', 'on')) else '0')
            except Exception: pass
            try: set_setting('RESET_GROUP_THREADS_IDS', '1' if (data.get('reset_group_threads') in (True, '1', 1, 'true', 'on')) else '0')
            except Exception: pass
            return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def api_admins_resets_get():
    # Compatibility alias returning same as GET /api/admins/resets
    try:
        request.method = 'GET'  # hint for tooling
    except Exception:
        pass
    return api_admins_resets()

# ---------- DB Safe: generic key/value editor ----------
@login_required
def admin_dbsafe():
    me = session.get('username') or ''
    if not is_superadmin(me):
        return redirect('/')
    try:
        tbl = (request.args.get('table') or 'app_settings').strip()
        kcol = (request.args.get('key_col') or 'key').strip()
        vcol = (request.args.get('val_col') or 'value').strip()
        import re
        safe = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
        if not (safe.match(tbl) and safe.match(kcol) and safe.match(vcol)):
            return "Bad table or column name", 400
        if tbl == 'app_settings':
            _ensure_app_settings()
        db = get_db(); cur = db.cursor()
        cur.execute(f'SELECT {kcol}, {vcol} FROM {tbl} ORDER BY {kcol} ASC')
        rows = cur.fetchall() or []
        pairs = [(r[0] if not isinstance(r, sqlite3.Row) else r[kcol], r[1] if not isinstance(r, sqlite3.Row) else r[vcol]) for r in rows]
    except Exception:
        pairs = []
        tbl = (request.args.get('table') or 'app_settings').strip()
        kcol = (request.args.get('key_col') or 'key').strip()
        vcol = (request.args.get('val_col') or 'value').strip()
    html = [
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>DB Safe – {tbl}</title>",
        "<style>body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#0f172a;color:#e5e7eb}",
        ".wrap{max-width:900px;margin:24px auto;padding:0 12px}",
        ".card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px}",
        "input.k,input.v{width:100%;box-sizing:border-box;background:#0b1020;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:8px}",
        ".btn{padding:8px 12px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff;cursor:pointer}",
        ".row{display:grid;grid-template-columns:240px 1fr;gap:10px;align-items:center}",
        ".muted{color:#9ca3af;font-size:12px}",
        "a{color:#93c5fd}",
        "</style></head><body>",
        "<div class='wrap'><div class='card'>",
        f"<h3 style='margin:0 0 12px'>DB Safe – {tbl}</h3>",
        "<div class='muted'>Edit values and click Save All. Adds new rows if key is new.</div>",
        "<div id='rows'>",
    ]
    for k, v in pairs:
        try:
            html.append(f"<div class='row'><input class='k' value='{_html.escape(str(k))}' /><input class='v' value='{_html.escape(str(v or ''))}' /></div>")
        except Exception:
            pass
    html.append("<div class='row'><input class='k' placeholder='new key' /><input class='v' placeholder='value' /></div>")
    html += [
        "</div>",
        "<div style='display:flex;gap:8px;margin-top:12px'><button id='add' class='btn' type='button' style='background:#374151'>Add Row</button><button id='saveAll' class='btn' type='button'>Save All</button><a href='/' style='margin-left:auto;text-decoration:underline'>Back</a></div>",
        "<div id='note' class='muted' style='margin-top:8px'></div>",
        "</div></div>",
        "<script>(function(){\n",
        "const rows = document.getElementById('rows');\n",
        "document.getElementById('add').onclick = ()=>{ const d=document.createElement('div'); d.className='row'; d.innerHTML=\"<input class='k' placeholder='new key'/><input class='v' placeholder='value'/>\"; rows.appendChild(d); };\n",
        "document.getElementById('saveAll').onclick = async ()=>{\n",
        "  const data = {}; rows.querySelectorAll('.row').forEach(r=>{ const k=r.querySelector('.k').value.trim(); const v=r.querySelector('.v').value; if(k) data[k]=v; });\n",
        "  try{ const res = await fetch('/api/admin/dbsafe/save_all'+(window.location.search||''), { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) }); const j = await res.json();\n",
        "    document.getElementById('note').textContent = (res.ok && j && j.ok) ? 'Saved.' : (j && j.error ? j.error : 'Failed');\n",
        "  }catch(e){ document.getElementById('note').textContent = 'Failed'; }\n",
        "};\n",
        "})();</script>",
        "</body></html>"
    ]
    return ''.join(html)

@login_required
def api_admin_dbsafe_save_all():
    try:
        me = session.get('username') or ''
        if not is_superadmin(me):
            return jsonify({'error': 'forbidden'}), 403
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({'error': 'bad payload'}), 400
        tbl = (request.args.get('table') or 'app_settings').strip()
        kcol = (request.args.get('key_col') or 'key').strip()
        vcol = (request.args.get('val_col') or 'value').strip()
        import re
        safe = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
        if not (safe.match(tbl) and safe.match(kcol) and safe.match(vcol)):
            return jsonify({'error': 'bad table or column'}), 400
        if tbl == 'app_settings':
            _ensure_app_settings()
        db = get_db(); cur = db.cursor()
        ok = True
        for k, v in data.items():
            try:
                try:
                    cur.execute(f"INSERT INTO {tbl} ({kcol}, {vcol}) VALUES (?, ?) ON CONFLICT({kcol}) DO UPDATE SET {vcol}=excluded.{vcol}", (str(k), str(v)))
                except Exception:
                    try:
                        cur.execute(f"REPLACE INTO {tbl} ({kcol}, {vcol}) VALUES (?, ?)", (str(k), str(v)))
                    except Exception:
                        cur.execute(f"SELECT 1 FROM {tbl} WHERE {kcol}=? LIMIT 1", (str(k),))
                        if cur.fetchone():
                            cur.execute(f"UPDATE {tbl} SET {vcol}=? WHERE {kcol}=?", (str(v), str(k)))
                        else:
                            cur.execute(f"INSERT INTO {tbl} ({kcol}, {vcol}) VALUES (?, ?)", (str(k), str(v)))
            except Exception:
                ok = False
        try:
            db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
            ok = False
        return jsonify({'ok': ok})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _register_admins_routes(a):
    try:
        a.add_url_rule('/api/admins/online', 'api_admins_online', api_admins_online, methods=['GET'])
        a.add_url_rule('/api/me/role', 'api_me_role', api_me_role, methods=['GET'])
        a.add_url_rule('/api/pinned', 'api_pinned', api_pinned, methods=['GET'])
        a.add_url_rule('/admins.js', 'admins_js', admins_js, methods=['GET'])
        # DB Safe routes (guarded)
        # Register legacy key/value editor at a non-conflicting path so /admin/dbsafe maps to the full tables UI below
        try:
            if 'admin_dbsafe_kv' not in a.view_functions:
                a.add_url_rule('/admin/dbsafe/kv', 'admin_dbsafe_kv', admin_dbsafe, methods=['GET'])
        except Exception:
            pass
        try:
            if 'api_admin_dbsafe_save_all' not in a.view_functions:
                a.add_url_rule('/api/admin/dbsafe/save_all', 'api_admin_dbsafe_save_all', api_admin_dbsafe_save_all, methods=['POST'])
        except Exception:
            pass
        # ID Reset toggles
        a.add_url_rule('/api/admins/resets', 'api_admins_resets', api_admins_resets, methods=['GET','POST'])
        a.add_url_rule('/api/admins/resets/get', 'api_admins_resets_get', api_admins_resets_get, methods=['GET'])
        # after_request must be registered per-app
        try:
            a.after_request(_inject_admins_js)
        except Exception:
            pass
        # Superadmin create-user routes
        a.add_url_rule('/admin/create_user', 'admin_create_user', admin_create_user, methods=['GET','POST'])
        a.add_url_rule('/api/admin/create_user', 'api_admin_create_user', api_admin_create_user, methods=['POST'])
        a.add_url_rule('/api/admin/reset_password', 'api_admin_reset_password', api_admin_reset_password, methods=['POST'])
        # Pinned messages API
        a.add_url_rule('/api/pinned', 'api_pinned', api_pinned, methods=['GET'])
    except Exception:
        pass

# Best-effort auto-register if app is already defined in this module
try:
    if 'app' in globals() and app:
        _register_admins_routes(app)
except Exception:
    pass

# Final safety: bind admin/pinned routes just before first request, in case
# the earlier auto-register ran before `app` existed.
try:
    @app.before_first_request
    def __bind_admin_routes_once():
        try:
            if not getattr(app, '_admins_routes_bound', False):
                _register_admins_routes(app)
                setattr(app, '_admins_routes_bound', True)
        except Exception:
            pass
        return None
except Exception:
    pass

def _rotate_downtime_code():
    try:
        set_setting('DOWNTIME_CODE', _rand_code(16))
    except Exception:
        pass

def enforce_device_ban():
    try:
        # Allow login, static and recovery always
        path = request.path or ''
        if path.startswith('/static/') or path.startswith('/preview/') or path.startswith('/uploads/'):
            return
        # Allow downtime unlock and smite always
        if path.startswith('/api/downtime/unlock') or path.rstrip('/') == '/smite':
            return
        # Superadmins bypass
        u = session.get('username')
        if u and is_superadmin(u):
            return
        cid = _client_id_from_request()
        if cid and _is_device_banned(cid):
            return ("Forbidden: device banned", 403)
    except Exception:
        return

# Ensure self-contained app setup
try:
    app  # type: ignore
except NameError:
    from flask import Flask
    app = Flask(__name__)
    try:
        if not getattr(app, 'secret_key', None):
            app.secret_key = os.environ.get('SECRET_KEY') or 'devkey'
    except Exception:
        pass
    try:
        _register_admins_routes(app)
    except Exception:
        pass
    # File upload defaults
    try:
        UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    except Exception:
        UPLOAD_FOLDER = 'uploads'
    try:
        MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', str(20*1024*1024)))
    except Exception:
        MAX_CONTENT_LENGTH = 20*1024*1024
    try:
        app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
    except Exception:
        pass

# Helper: sanitize usernames to plain text (no HTML). Markdown punctuation is allowed.
def sanitize_username(u: str) -> str:
    try:
        import re
        # Strip HTML entirely then allow only a safe charset (no markdown semantics)
        text = _html.unescape(bleach.clean(u or '', tags=[], attributes={}, styles=[], strip=True))
        # Keep letters, numbers, space, underscore, hyphen, and dot
        text = re.sub(r"[^A-Za-z0-9._\- ]+", "", text)
        # Collapse multiple spaces
        text = re.sub(r"\s+", " ", text).strip()
        # Limit length to 20 characters
        if len(text) > 20:
            text = text[:20].rstrip()
        return text
    except Exception:
        return (u or '').strip()

def is_gdm_owner(tid: int, user: str) -> bool:
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
        row = cur.fetchone()
        owner = (row[0] if row and not isinstance(row, sqlite3.Row) else (row['created_by'] if row else None))
        return owner == user
    except Exception:
        return False

def is_superadmin(user: str = None) -> bool:
    try:
        u = user or session.get('username') or _verify_dbx_token(request.headers.get('X-DBX') or '')
        return u in SUPERADMINS
    except Exception:
        return False

# Ensure a consistent admin checker for all permission gates (override any legacy one)
def is_admin(user: str = None) -> bool:
    try:
        u = user or session.get('username') or ''
        if not u:
            return False
        # Recognize DB role admins and extra_admins as admins; superadmins are handled by is_superadmin
        if is_superadmin(u):
            return False
        return _is_adminish(u)
    except Exception:
        return False

def _list_all_admin_usernames() -> list:
    try:
        db = get_db(); cur = db.cursor()
        names = set()
        # Defaults
        try:
            for x in SUPERADMINS:
                try: names.add(str(x))
                except Exception: pass
        except Exception:
            pass
        try:
            for x in ADMINS:
                try: names.add(str(x))
                except Exception: pass
        except Exception:
            pass
        # DB roles
        try:
            cur.execute("SELECT username FROM users WHERE lower(role) IN ('admin','superadmin')")
            for r in cur.fetchall() or []:
                try:
                    names.add(r[0] if not isinstance(r, sqlite3.Row) else r['username'])
                except Exception:
                    pass
        except Exception:
            pass
        # Extra admins table
        try:
            cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
            cur.execute('SELECT username FROM extra_admins')
            for r in cur.fetchall() or []:
                try:
                    names.add(r[0] if not isinstance(r, sqlite3.Row) else r['username'])
                except Exception:
                    pass
        except Exception:
            pass
        return sorted([n for n in names if n])
    except Exception:
        return []

# Configuration
DB_PATH = "chatter.db"
UPLOAD_FOLDER = "uploads"
LOG_UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
MAX_UPLOAD_MB = 200
MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
ADMINS = {"SpyDrone", "octolinkyt", "swim67667"}
SUPERADMINS = {"SpyDrone", "octolinkyt", "buster427"}
PREVIEW_EXTS = {"png", "jpg", "jpeg", "gif", "mp4", "webm", "html"}
ZIP_EXT = "zip"
DEFAULT_SYS_AVATAR = "sys_pfp.png"
DEFAULT_AVATAR = "default_pfp.png"  # Update this path if you change the default avatar asset
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(APP_ROOT, 'em_backup')
try:
    os.makedirs(BACKUP_DIR, exist_ok=True)
except Exception:
    pass

# Tor exit node blocking
_TOR_CACHE = {"ips": set(), "fetched_at": 0}
_TOR_URL = "https://check.torproject.org/torbulkexitlist"
_TOR_TTL = 15 * 60  # seconds

def _refresh_tor_ips():
    try:
        now = time.time()
        if now - _TOR_CACHE["fetched_at"] < _TOR_TTL:
            return
        r = requests.get(_TOR_URL, timeout=5)
        r.raise_for_status()
        _TOR_CACHE["ips"] = {
            line.strip()
            for line in r.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        _TOR_CACHE["fetched_at"] = now
    except Exception:
        pass  # keep last good cache

def _client_ip_for_tor():
    try:
        xff = request.headers.get("X-Forwarded-For") or request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        return request.remote_addr or ""
    except Exception:
        return ""

def _block_tor():
    _refresh_tor_ips()
    try:
        ip = _client_ip_for_tor()
    except Exception:
        ip = ""
    if ip in _TOR_CACHE["ips"]:
        return Response("You can't access Chatter with Tor.", status=403, mimetype="text/plain")

try:
    app.before_request(_block_tor)
except Exception:
    pass

# Server-side anti-duplicate guard (per-user recent send)
user_last_send = {}

# ---------- File/Attachment helpers ----------
def _safe_ext(name: str) -> str:
    try:
        ext = (name.rsplit('.', 1)[-1] or '').lower()
        return ext
    except Exception:
        return ''

def _unique_name(base: str) -> str:
    try:
        base = secure_filename(base or 'file')
        if not base:
            base = 'file'
        root, ext = os.path.splitext(base)
        ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        rand = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
        return f"{root}_{ts}_{rand}{ext}"
    except Exception:
        return f"file_{int(time.time())}.bin"

def safe_save_file_from_b64(filename: str, content_b64: str) -> str | None:
    try:
        if not content_b64:
            return None
        data = content_b64.strip()
        # Strip data URL prefix if present
        try:
            if data.lower().startswith('data:'):
                # form: data:<mime>;base64,<payload>
                comma = data.find(',')
                if comma != -1:
                    data = data[comma+1:]
        except Exception:
            pass
        # Normalize padding for base64 variants
        def _b64_decode_any(s: str) -> bytes:
            s = s.strip()
            # First try standard base64
            try:
                pad = '=' * (-len(s) % 4)
                return _b64.b64decode(s + pad, validate=False)
            except Exception:
                pass
            # Try urlsafe (replace -_ to +/)
            try:
                s2 = s.replace('-', '+').replace('_', '/')
                pad = '=' * (-len(s2) % 4)
                return _b64.b64decode(s2 + pad, validate=False)
            except Exception:
                pass
            # Last resort: urlsafe decoder directly
            try:
                pad = '=' * (-len(s) % 4)
                return _b64.urlsafe_b64decode(s + pad)
            except Exception:
                raise
        raw = _b64_decode_any(data)
        # Enforce size limit
        try:
            max_bytes = int(MAX_CONTENT_LENGTH)
            if max_bytes and len(raw) > max_bytes:
                return None
        except Exception:
            pass
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        name = _unique_name(filename or 'upload')
        fpath = os.path.join(UPLOAD_FOLDER, name)
        with open(fpath, 'wb') as f:
            f.write(raw)
        return name
    except Exception:
        return None

# Preserve reference to robust implementation for any legacy wrappers
SAFE_SAVE_FILE_B64_IMPL = safe_save_file_from_b64

def safe_save_file(file) -> str | None:
    try:
        if not file:
            return None
        fname = secure_filename(file.filename or 'upload')
        if not fname:
            fname = 'upload'
        # Enforce max size if possible
        try:
            file.stream.seek(0, os.SEEK_END)
            size = file.stream.tell()
            file.stream.seek(0)
            max_bytes = int(MAX_CONTENT_LENGTH)
            if max_bytes and size > max_bytes:
                return None
        except Exception:
            pass
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        name = _unique_name(fname)
        dest = os.path.join(UPLOAD_FOLDER, name)
        file.save(dest)
        return name
    except Exception:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            u = session.get('username') or _verify_dbx_token(request.headers.get('X-DBX') or '')
            if not u:
                return jsonify({'error': 'not logged in'}), 401
            g.username = u
            return f(*args, **kwargs)
        except Exception:
            return jsonify({'error': 'not logged in'}), 401
    return decorated

# Make decorator available as a builtin so modules that don't import it explicitly (e.g., chatter.py)
# can still resolve @login_required without NameError.
try:
    import builtins as _bi
    if not getattr(_bi, 'login_required', None):
        _bi.login_required = login_required
except Exception:
    pass

# App settings helpers
def _ensure_app_settings():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )''')
        db.commit()
    except Exception:
        pass

# Pins table for messages
def _ensure_pin_table():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS pinned_messages (
            kind TEXT,        -- 'public' or 'gdm'
            message_id INTEGER,
            thread_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(kind, message_id)
        )''')
        db.commit()
    except Exception:
        pass

def get_setting(key: str, default=None):
    try:
        _ensure_app_settings()
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT value FROM app_settings WHERE key=?', (key,))
        row = cur.fetchone()
        if not row:
            return default
        v = row[0] if not isinstance(row, sqlite3.Row) else row['value']
        return v
    except Exception:
        return default

def set_setting(key: str, value: str):
    try:
        _ensure_app_settings()
        db = get_db(); cur = db.cursor()
        # For emergency toggle, read old value so we can detect 0->1 transitions
        old_val = None
        try:
            if key == 'ADMIN_EMERGENCY_SHUTDOWN':
                cur.execute('SELECT value FROM app_settings WHERE key=?', (key,))
                row = cur.fetchone()
                if row is not None:
                    old_val = row[0] if not isinstance(row, sqlite3.Row) else row['value']
        except Exception:
            old_val = None
        cur.execute('INSERT OR REPLACE INTO app_settings(key, value) VALUES(?,?)', (key, str(value)))
        db.commit()
        try:
            if key == 'ADMIN_EMERGENCY_SHUTDOWN':
                _maybe_snapshot_db_on_emergency(str(old_val or '0'), str(value))
        except Exception:
            pass
        return True
    except Exception:
        return False

# Message/activity log file
LOG_FILE = "chat_messages.txt"

def _plain_text_from_html(html_text: str) -> str:
    try:
        # Remove all tags, keep text content
        stripped = bleach.clean(html_text or "", tags=[], attributes={}, styles=[], strip=True)
        return _html.unescape(stripped).strip()
    except Exception:
        return (html_text or "").strip()

def _append_log_line(line: str):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line.rstrip("\n") + "\n")
    except Exception:
        pass

def _format_web_timestamp(dt: datetime) -> str:
    try:
        d = dt
        if NY_TZ is not None:
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            d = d.astimezone(NY_TZ)
        # Example wanted: Fri Oct 31 2025 7:12:23 PM
        s = d.strftime('%a %b %d %Y %I:%M:%S %p')
        # remove leading zero from hour
        # split before AM/PM
        try:
            prefix, ampm = s.rsplit(' ', 1)
            head, timepart = prefix.rsplit(' ', 1)
            timepart = timepart.lstrip('0') or '0'
            s = f"{head} {timepart} {ampm}"
        except Exception:
            pass
        # remove leading zero from day (e.g., 'Oct 03' -> 'Oct 3')
        # pattern: '... %b %d %Y ...'
        # We'll rebuild that part roughly
        try:
            parts = s.split(' ')
            # parts: [Fri, Oct, 31, 2025, 7:12:23, PM]
            if len(parts) >= 6:
                day = parts[2].lstrip('0') or '0'
                parts[2] = day
                s = ' '.join(parts)
        except Exception:
            pass
        return s
    except Exception:
        # fallback to ISO if anything fails
        return to_ny_time(dt)

# Flask app setup
app = Flask(__name__)
app.secret_key = "dev-secret-key-change-this-in-production"
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.before_request(enforce_device_ban)

# Seed defaults eagerly at startup (Flask 3 removed before_first_request)
try:
    _ensure_app_settings()
    _seed_defaults_if_needed()
    _ensure_gdm_schema()
except Exception:
    pass

# Socket.IO setup with better configuration
# Let Flask-SocketIO auto-detect async_mode (threading/gevent/eventlet) to avoid invalid mode errors
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# Register admin routes on the main app
try:
    _register_admins_routes(app)
except Exception:
    pass

# Global state
try:
    app.add_url_rule('/api/admins/online', view_func=api_admins_online, methods=['GET'])
except Exception:
    pass

# Superadmin-only: toggle stealth mode for admins list
def api_admins_set_stealth():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get('enabled'))
    try:
        set_setting('ADMINS_STEALTH', '1' if enabled else '0')
        return jsonify({'ok': True, 'enabled': enabled})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

try:
    app.add_url_rule('/api/admins/stealth', view_func=api_admins_set_stealth, methods=['POST'])
except Exception:
    pass

# Superadmin-only: get stealth mode state
def api_admins_get_stealth():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    try:
        enabled = (get_setting('ADMINS_STEALTH','0') == '1')
        return jsonify({'ok': True, 'enabled': enabled})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

try:
    app.add_url_rule('/api/admins/stealth', view_func=api_admins_get_stealth, methods=['GET'])
except Exception:
    pass

# Superadmin-only: get/set ID reset toggles
def api_admins_resets_get():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    try:
        return jsonify({'ok': True,
                        'public': get_setting('RESET_ID_PUBLIC','0')=='1',
                        'dm': get_setting('RESET_ID_DM','0')=='1',
                        'gdm': get_setting('RESET_ID_GDM','0')=='1',
                        'group_threads': get_setting('RESET_ID_GROUP_THREADS','0')=='1'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def api_admins_resets_set():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    try:
        if 'public' in data:
            set_setting('RESET_ID_PUBLIC','1' if data.get('public') else '0')
        if 'dm' in data:
            set_setting('RESET_ID_DM','1' if data.get('dm') else '0')
        if 'gdm' in data:
            set_setting('RESET_ID_GDM','1' if data.get('gdm') else '0')
        if 'group_threads' in data:
            set_setting('RESET_ID_GROUP_THREADS','1' if data.get('group_threads') else '0')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

try:
    app.add_url_rule('/api/admins/reset_ids', view_func=api_admins_resets_get, methods=['GET'])
    app.add_url_rule('/api/admins/reset_ids', view_func=api_admins_resets_set, methods=['POST'])
except Exception:
    pass

# Superadmin-only: clear ALL DMs globally (includes system messages) and optionally reset sequence
def api_admin_dm_clear_all():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    db = get_db(); cur = db.cursor()
    try:
        cur.execute('DELETE FROM direct_messages')
        try:
            if get_setting('RESET_ID_DM','0')=='1':
                try:
                    cur.execute("DELETE FROM sqlite_sequence WHERE name='direct_messages'")
                except Exception:
                    pass
        except Exception:
            pass
        db.commit()
        try:
            socketio.emit('dm_cleared', {'global': True})
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

try:
    app.add_url_rule('/api/admin/dm_clear_all', view_func=api_admin_dm_clear_all, methods=['POST'])
except Exception:
    pass

# Superadmin-only: reset all autoincrement IDs (messages, direct_messages, group_messages, group_threads)
@app.route('/api/admins/reset_all_ids', methods=['POST'])
@login_required
def api_admins_reset_all_ids():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    try:
        db = get_db(); cur = db.cursor()
        try:
            cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('messages','direct_messages','group_messages','group_threads')")
        except Exception:
            # sqlite_sequence may not exist or tables may not use AUTOINCREMENT; ignore
            pass
        try:
            set_setting('RESET_ID_PUBLIC','1')
            set_setting('RESET_ID_DM','1')
            set_setting('RESET_ID_GDM','1')
            set_setting('RESET_ID_GROUP_THREADS','1')
            # Also maintain legacy/alternate keys used elsewhere
            set_setting('RESET_PUBLIC_IDS','1')
            set_setting('RESET_DM_IDS','1')
            set_setting('RESET_GDM_IDS','1')
            set_setting('RESET_GROUP_THREADS_IDS','1')
        except Exception:
            pass
        db.commit()
        return jsonify({'ok': True})
    except Exception as e:
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500
online_users = defaultdict(lambda: 0)
user_timeouts = {}
banned_users = set()
banned_ips = set()  # Track banned IP addresses
user_ips = {}  # Track username -> IP mapping
connected_sockets = {}  # Track connected sockets for better message delivery
typing_users = {}  # username -> expiry timestamp
voice_channels = defaultdict(set)  # channel -> set(usernames)

# Comprehensive Anti-Spam System with All 7 Requested Features
import time
import hashlib
import re
import difflib
import zlib
from collections import defaultdict

# Anti-spam state tracking
spam_public = defaultdict(list)  # username -> [ts,...]
spam_dm = defaultdict(list)      # username -> [ts,...]
spam_gdm = defaultdict(list)     # username -> [ts,...]

# Message content tracking for duplicate detection
spam_message_hashes = defaultdict(list)  # username -> [(hash, timestamp), ...]
spam_recent_messages = defaultdict(list)  # username -> [(text, timestamp), ...]

# Progressive sanction system
spam_strikes = defaultdict(lambda: {'count': 0, 'violations': [], 'last_violation': 0})
spam_slow_until = defaultdict(float)   # username -> unix timestamp until slow-mode expires
spam_block_until = defaultdict(float)  # username -> unix timestamp until hard block expires

# Auto-split queue with rate limiting
spam_split_queue = defaultdict(list)  # username -> [(scheduled_time, chunk), ...]

def _spam_message_length_check(text: str, max_chars: int = 1000) -> tuple[bool, str]:
    """1. Message Length Limit - Check if message exceeds character limit."""
    if not text:
        return True, ""
    
    if len(text) > max_chars:
        return False, f"Message too long ({len(text)} chars). Maximum allowed: {max_chars} characters. Please shorten your message."
    
    return True, ""

def _spam_create_message_hash(text: str) -> str:
    """Create a hash fingerprint of message content for duplicate detection."""
    # Normalize text: lowercase, remove extra whitespace, strip punctuation
    normalized = re.sub(r'[^\w\s]', '', text.lower())
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    
    # Create hash
    return hashlib.md5(normalized.encode('utf-8')).hexdigest()


def _spam_is_whitelisted_content(text: str) -> bool:
    """Check if content is whitelisted (common legitimate words/phrases)."""
    if not text or not text.strip():
        return True
    
    # Clean the text
    clean_text = text.strip().lower()
    
    # Common single letters and short words that should NEVER be blocked
    common_single_chars = {
        "a", "i", "e", "o", "u", "y",  # vowels
        "b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "q", "r", "s", "t", "v", "w", "x", "z"  # consonants
    }
    
    # Common short words (1-3 characters)
    common_short_words = {
        "ok", "hi", "bye", "yes", "no", "lol", "omg", "wtf", "brb", "ttyl", "gg", "gj", "ty", "np", "yw",
        "is", "it", "to", "be", "we", "he", "me", "at", "on", "in", "or", "and", "the", "for", "you", "are",
        "was", "but", "not", "can", "had", "her", "his", "she", "one", "our", "out", "day", "get", "has",
        "him", "how", "man", "new", "now", "old", "see", "two", "way", "who", "boy", "did", "its", "let",
        "put", "say", "she", "too", "use"
    }
    
    # Common expressions and reactions
    common_expressions = {
        "haha", "hehe", "lmao", "rofl", "nice", "cool", "wow", "omg", "damn", "shit", "fuck", "hell",
        "what", "when", "where", "why", "how", "who", "which", "that", "this", "here", "there",
        "good", "bad", "great", "awesome", "terrible", "amazing", "perfect", "wrong", "right",
        "hello", "goodbye", "thanks", "thank", "please", "sorry", "excuse", "welcome"
    }
    
    # If it is just a single character, always allow (people say "e", "a", "i" legitimately)
    if len(clean_text) == 1 and clean_text in common_single_chars:
        return True
    
    # If it is a common short word, always allow
    if clean_text in common_short_words:
        return True
    
    # If it is a common expression, always allow
    if clean_text in common_expressions:
        return True
    
    # Check if it is just repeated common characters (like "hahaha", "lololol")
    if len(set(clean_text)) <= 2 and len(clean_text) <= 10:
        # Allow repeated patterns of common letters (ha, he, lo, etc.)
        unique_chars = set(clean_text)
        if unique_chars.issubset(common_single_chars):
            return True
    
    # Check for common punctuation-only messages
    punctuation_chars = ".,!?;:-()[]{}\"" + chr(9) + chr(10)
    if all(c in punctuation_chars for c in clean_text):
        return True
    return False

def _spam_is_user_showing_spam_behavior(username: str, text: str, timeframe: int = 60) -> bool:
    """Check if user is exhibiting spam-like behavior patterns."""
    now = time.time()
    
    # Get user recent messages
    user_messages = spam_recent_messages.get(username, [])
    recent_messages = [(msg, ts) for msg, ts in user_messages if now - ts < timeframe]
    
    if len(recent_messages) < 3:  # Need at least 3 messages to detect pattern
        return False
    
    # Check for rapid single-character spam (like "e e e e e")
    single_char_count = 0
    for msg, ts in recent_messages:
        if len(msg.strip()) == 1:
            single_char_count += 1
    
    if single_char_count >= 5:  # 5+ single characters in timeframe = spam behavior
        return True
    
    # Check for rapid identical messages
    identical_count = 0
    for msg, ts in recent_messages:
        if msg.strip().lower() == text.strip().lower():
            identical_count += 1
    
    if identical_count >= 3:  # 3+ identical messages = spam behavior
        return True
    
    # Check for excessive message frequency (more than 1 message per 2 seconds)
    if len(recent_messages) >= 10:  # 10+ messages in 1 minute = spam behavior
        return True
    
    return False

def _spam_is_near_duplicate(text: str, stored_msg: str, text_length: int) -> bool:
    """Enhanced near-duplicate detection for paragraph variations."""
    # Normalize both messages for comparison
    def normalize_text(msg):
        # Remove extra whitespace and convert to lowercase
        normalized = re.sub(r'\s+', ' ', msg.lower().strip())
        # Remove common filler words that users often add/remove
        filler_words = {'the', 'a', 'an', 'and', 'or', 'but', 'so', 'very', 'really', 'just', 'also', 'too', 'quite', 'pretty', 'actually', 'basically', 'literally'}
        words = [w for w in normalized.split() if w not in filler_words]
        return ' '.join(words)
    
    # Normalize both messages
    norm_text = normalize_text(text)
    norm_stored = normalize_text(stored_msg)
    
    # If either is too short after normalization, use regular similarity
    if len(norm_text) < 10 or len(norm_stored) < 10:
        return difflib.SequenceMatcher(None, text.lower(), stored_msg.lower()).ratio() > 0.85
    
    # Calculate different types of similarity
    char_similarity = difflib.SequenceMatcher(None, norm_text, norm_stored).ratio()
    
    # Word-level similarity (order-independent)
    text_words = set(norm_text.split())
    stored_words = set(norm_stored.split())
    if len(text_words) == 0 or len(stored_words) == 0:
        word_similarity = 0
    else:
        common_words = len(text_words.intersection(stored_words))
        total_words = len(text_words.union(stored_words))
        word_similarity = common_words / total_words if total_words > 0 else 0
    
    # Length-aware thresholds for different message sizes
    if text_length < 100:  # Short messages
        char_threshold = 0.90
        word_threshold = 0.85
    elif text_length < 500:  # Medium messages
        char_threshold = 0.80
        word_threshold = 0.75
    else:  # Long messages (paragraphs)
        char_threshold = 0.70
        word_threshold = 0.65
    
    # Combined similarity score (weighted average)
    combined_similarity = (char_similarity * 0.6) + (word_similarity * 0.4)
    
    # Return True if either character similarity OR word similarity OR combined score exceeds threshold
    return (char_similarity > char_threshold or 
            word_similarity > word_threshold or 
            combined_similarity > ((char_threshold + word_threshold) / 2))

def _spam_duplicate_detection(username: str, text: str, timeframe: int = 300) -> tuple[bool, str]:
    """2. Intelligent Duplicate & Near-Duplicate Detection - Smart about common words."""
    if not text.strip():
        return True, ""
    
    now = time.time()
    
    # SMART FILTERING: Don't flag common legitimate content
    if _spam_is_whitelisted_content(text):
        return True, ""
    
    # Check if user is showing spam behavior patterns
    if _spam_is_user_showing_spam_behavior(username, text):
        _spam_record_violation(username, "spam_behavior_detected", 3)
        return False, "Spam-like behavior detected. Please slow down and vary your messages."
    
    message_hash = _spam_create_message_hash(text)
    
    # Clean old hashes
    user_hashes = spam_message_hashes[username]
    spam_message_hashes[username] = [(h, ts) for h, ts in user_hashes if now - ts < timeframe]
    
    # Check for exact duplicate (but only if not whitelisted)
    for stored_hash, timestamp in spam_message_hashes[username]:
        if stored_hash == message_hash and now - timestamp < timeframe:
            return False, f"Duplicate message detected. Please wait {int(timeframe - (now - timestamp))} seconds before sending similar content."
    
    # ENHANCED NEAR-DUPLICATE DETECTION: Catches paragraph variations
    user_messages = spam_recent_messages[username]
    spam_recent_messages[username] = [(msg, ts) for msg, ts in user_messages if now - ts < timeframe]
    
    # Check for sophisticated near-duplicates (paragraph variations)
    text_length = len(text)
    for stored_msg, timestamp in spam_recent_messages[username]:
        if now - timestamp < timeframe:  # Check within full timeframe for near-duplicates
            # Skip similarity check for whitelisted content
            if _spam_is_whitelisted_content(stored_msg):
                continue
                
            # Use enhanced detection for paragraph variations
            if _spam_is_near_duplicate(text, stored_msg, text_length):
                return False, f"Similar message detected. Please wait {int(timeframe - (now - timestamp))} seconds before sending similar content."
    
    # Also check for rapid-fire behavior (multiple messages quickly)
    recent_similar_count = 0
    for stored_msg, timestamp in spam_recent_messages[username]:
        if now - timestamp < 60:  # Only check last minute for behavioral patterns
            if _spam_is_whitelisted_content(stored_msg):
                continue
            if _spam_is_near_duplicate(text, stored_msg, text_length):
                recent_similar_count += 1
    
    # Flag rapid similar messages as spam behavior
    if recent_similar_count >= 3:  # 3+ similar messages in 1 minute = spam behavior
        return False, f"Rapid similar messages detected. Please slow down and vary your messages."
    
    # Store this message
    spam_message_hashes[username].append((message_hash, now))
    spam_recent_messages[username].append((text, now))
    
    return True, ""
    

def _spam_payload_size_check(text: str, max_bytes: int = 8192) -> tuple[bool, str]:
    """3. Payload Size Monitoring - Check message byte size."""
    if not text:
        return True, ""
    
    # Check raw byte size
    byte_size = len(text.encode('utf-8'))
    if byte_size > max_bytes:
        return False, f"Message payload too large ({byte_size} bytes). Maximum allowed: {max_bytes} bytes."
    
    # Check compressed size to detect encoded spam
    try:
        compressed_size = len(zlib.compress(text.encode('utf-8')))
        compression_ratio = compressed_size / byte_size if byte_size > 0 else 1
        
        # If compression ratio is very low, it might be repetitive spam
        if compression_ratio < 0.1 and byte_size > 1000:
            return False, "Message appears to contain repetitive content. Please vary your message content."
    except Exception:
        pass
    
    return True, ""

def _spam_auto_split_with_rate_limit(username: str, text: str, max_chars: int = 500) -> tuple[bool, list[str], str]:
    """4. Auto-Split with Rate Limiting - Split large messages and apply rate limiting."""
    if not text or len(text) <= max_chars:
        return True, [text] if text else [], ""
    
    # Split message into chunks
    chunks = []
    
    # Try to split by paragraphs first
    paragraphs = text.split('\n\n')
    current_chunk = ""
    
    for paragraph in paragraphs:
        if len(current_chunk) + len(paragraph) + 2 <= max_chars:
            if current_chunk:
                current_chunk += '\n\n' + paragraph
            else:
                current_chunk = paragraph
        else:
            if current_chunk:
                chunks.append(current_chunk)
                current_chunk = paragraph
            else:
                # Paragraph is too long, split by sentences
                sentences = re.split(r'[.!?]+', paragraph)
                temp_chunk = ""
                for sentence in sentences:
                    if sentence.strip():
                        sentence = sentence.strip() + '.'
                        if len(temp_chunk) + len(sentence) + 1 <= max_chars:
                            if temp_chunk:
                                temp_chunk += ' ' + sentence
                            else:
                                temp_chunk = sentence
                        else:
                            if temp_chunk:
                                chunks.append(temp_chunk)
                            temp_chunk = sentence
                if temp_chunk:
                    current_chunk = temp_chunk
    
    if current_chunk:
        chunks.append(current_chunk)
    
    # If still too long, split by words
    final_chunks = []
    for chunk in chunks:
        if len(chunk) <= max_chars:
            final_chunks.append(chunk)
        else:
            words = chunk.split()
            temp_chunk = ""
            for word in words:
                if len(temp_chunk) + len(word) + 1 <= max_chars:
                    if temp_chunk:
                        temp_chunk += ' ' + word
                    else:
                        temp_chunk = word
                else:
                    if temp_chunk:
                        final_chunks.append(temp_chunk)
                    temp_chunk = word
            if temp_chunk:
                final_chunks.append(temp_chunk)
    
    # Apply rate limiting - 1 message per second for split parts
    now = time.time()
    scheduled_chunks = []
    
    for i, chunk in enumerate(final_chunks):
        scheduled_time = now + i  # 1 second delay between chunks
        spam_split_queue[username].append((scheduled_time, chunk))
        scheduled_chunks.append(chunk)
    
    return False, scheduled_chunks, f"Large message auto-split into {len(final_chunks)} parts. Parts will be sent at 1-second intervals to prevent flooding."

def _spam_individual_slow_mode_check(username: str) -> tuple[bool, str]:
    """5. Individual Slow Mode - Check if user is in slow mode."""
    now = time.time()
    
    if username in spam_slow_until and now < spam_slow_until[username]:
        remaining = int(spam_slow_until[username] - now)
        return False, f"You are in slow mode. Please wait {remaining} seconds before sending another message."
    
    return True, ""

def _spam_content_pattern_analysis(text: str) -> tuple[bool, str]:
    """6. Intelligent Content Pattern Analysis - Smart about legitimate content."""
    if not text:
        return True, ""
    
    # SMART FILTERING: Don't flag whitelisted content
    if _spam_is_whitelisted_content(text):
        return True, ""
    
    # Check for excessive whitespace (but be more lenient)
    whitespace_ratio = len(re.findall(r'\s', text)) / len(text) if text else 0
    if whitespace_ratio > 0.85:  # Increased from 0.7 to 0.85
        return False, "Message contains excessive whitespace. Please use normal formatting."
    
    # Check for repeated characters (but ignore common patterns)
    repeated_chars = re.findall(r'(.)\1{15,}', text)  # Increased from 10+ to 15+ characters
    if repeated_chars:
        # Allow common repeated patterns like "hahaha", "lololol", "nooooo"
        allowed_repeated = {'a', 'e', 'h', 'l', 'o', 'n', 's', 't'}
        if not all(char.lower() in allowed_repeated for char in repeated_chars):
            return False, "Message contains excessive repeated characters. Please use normal text."
    
    # Check for HTML/CSS patterns (but be more selective)
    suspicious_html_patterns = [
        r'<script[^>]*>',  # Scripts are definitely suspicious
        r'<iframe[^>]*>',  # Iframes are suspicious
        r'javascript:',    # JavaScript URLs are suspicious
        r"on\w+\s*=\s*["'][^"']*["']",  # Event handlers are suspicious
    ]
    
    html_matches = 0
    for pattern in suspicious_html_patterns:
        html_matches += len(re.findall(pattern, text, re.IGNORECASE))
    
    if html_matches > 2:  # Reduced threshold, focus on truly suspicious patterns
        return False, "Message appears to contain potentially malicious code. Please use plain text for chat."
    
    # Check for excessive line breaks (but be more lenient)
    line_breaks = text.count("\n")
    line_breaks = text.count("\n")
    if line_breaks > 30:  # Increased from 20 to 30
        return False, "Message contains too many line breaks. Please format your message more concisely."
    
    # Check for massive code dumps (but allow reasonable code sharing)
    if len(text) > 2000:  # Only check very long messages
        code_indicators = [
            r'function\s+\w+\s*\(',
            r'class\s+\w+\s*[:{]',
            r'\w+\s*=\s*function\s*\(',
            r'import\s+\w+',
            r'from\s+\w+\s+import'
        ]
        
        code_matches = 0
        for pattern in code_indicators:
            code_matches += len(re.findall(pattern, text, re.IGNORECASE))
        
        if code_matches > 10:  # Only flag obvious code dumps
            return False, "Message appears to be a large code dump. Please use a code sharing service for large code blocks."
    
    return True, ""
    
    # Check for excessive whitespace
    whitespace_ratio = len(re.findall(r'\s', text)) / len(text) if text else 0
    if whitespace_ratio > 0.7:
        return False, "Message contains excessive whitespace. Please use normal formatting."
    
    # Check for repeated characters
    repeated_chars = re.findall(r'(.)\1{10,}', text)  # 10+ repeated characters
    if repeated_chars:
        return False, "Message contains excessive repeated characters. Please use normal text."
    
    # Check for HTML/CSS patterns
    html_patterns = [
        r'<div[^>]*>',
        r'<script[^>]*>',
        r'<style[^>]*>',
        r'<br\s*/?>',
        r'&[a-zA-Z]+;',
        r'style\s*=\s*["\'][^"\']*["\']'
    ]
    
    html_matches = 0
    for pattern in html_patterns:
        html_matches += len(re.findall(pattern, text, re.IGNORECASE))
    
    if html_matches > 5:
        return False, "Message appears to contain HTML/CSS code dumps. Please use plain text for chat."
    
    # Check for excessive line breaks
    line_breaks = text.count('\n')
    if line_breaks > 20:
        return False, "Message contains too many line breaks. Please format your message more concisely."
    
    # Check for code block patterns
    code_patterns = [
        r'```[\s\S]*```',
        r'`[^`\n]{50,}`',
        r'^\s*[\w\-]+\s*:\s*[\w\-]+\s*;?\s*$'  # CSS-like patterns
    ]
    
    code_matches = 0
    for pattern in code_patterns:
        code_matches += len(re.findall(pattern, text, re.MULTILINE))
    
    if code_matches > 10:
        return False, "Message appears to contain large code blocks. Please use a code sharing service for large code snippets."
    
    return True, ""

def _spam_record_violation(username: str, violation_type: str, severity: int = 1):
    """Record a spam violation for progressive sanctions."""
    now = time.time()
    user_strikes = spam_strikes[username]
    
    user_strikes['count'] += severity
    user_strikes['last_violation'] = now
    user_strikes['violations'].append({
        'type': violation_type,
        'timestamp': now,
        'severity': severity
    })
    
    # Clean old violations (older than 1 hour)
    user_strikes['violations'] = [
        v for v in user_strikes['violations'] 
        if now - v['timestamp'] < 3600
    ]
    
    # Recalculate strike count based on recent violations
    user_strikes['count'] = sum(v['severity'] for v in user_strikes['violations'])

def _spam_progressive_sanctions(username: str) -> tuple[bool, str]:
    """7. Progressive Sanction System - Apply escalating punishments."""
    user_strikes = spam_strikes[username]
    strike_count = user_strikes['count']
    now = time.time()
    
    if strike_count == 0:
        return True, ""
    
    # First violation (1-2 strikes) - Warning
    if strike_count <= 2:
        return False, "⚠️ Warning: Please follow chat guidelines. Continued violations may result in restrictions."
    
    # Second violation (3-4 strikes) - Temporary slow mode (30 seconds)
    elif strike_count <= 4:
        spam_slow_until[username] = now + 30
        return False, "🐌 Slow mode applied (30 seconds). Please wait before sending another message."
    
    # Third violation (5+ strikes) - Extended slow mode (2 minutes)
    elif strike_count >= 5:
        spam_slow_until[username] = now + 120
        return False, "🚫 Extended slow mode applied (2 minutes). Multiple violations detected. Please review chat guidelines."
    
    return True, ""

def _spam_process_split_queue(username: str):
    """Process queued auto-split message chunks."""
    try:
        now = time.time()
        split_queue = spam_split_queue[username]
        
        # Process ready chunks
        ready_chunks = []
        remaining_chunks = []
        
        for scheduled_time, chunk in split_queue:
            if now >= scheduled_time:
                ready_chunks.append(chunk)
            else:
                remaining_chunks.append((scheduled_time, chunk))
        
        # Update queue
        split_queue[:] = remaining_chunks
        
        return ready_chunks
                
    except Exception:
        return []

def _spam_comprehensive_gate(kind: str, username: str, text: str, *, has_attachment: bool = False, get_setting_func=None):
    """
    Intelligent Comprehensive Anti-Spam Gate with Smart Content Recognition.
    
    This system is designed to:
    - NEVER block common words like "a", "e", "i", "ok", "hi", "lol", etc.
    - Focus on USER BEHAVIOR patterns rather than content patterns
    - Only flag actual spam behavior, not legitimate single letters or words
    
    Returns:
        (allowed: bool, reason: str, auto_split_chunks: list[str] or None)
    """
    try:
        if not username or not text:
            return True, "", None
        
        # SMART PRE-CHECK: Always allow whitelisted content
        if _spam_is_whitelisted_content(text):
            return True, "", None
        
        # Get settings with defaults
        max_chars = int(get_setting_func('SPAM_MAX_CHARS', '1000')) if get_setting_func else 1000
        max_bytes = int(get_setting_func('SPAM_MAX_BYTES', '8192')) if get_setting_func else 8192
        
        # 5. Individual Slow Mode Check (first, as it's time-based)
        allowed, reason = _spam_individual_slow_mode_check(username)
        if not allowed:
            return False, reason, None
        
        # 1. Message Length Limit
        allowed, reason = _spam_message_length_check(text, max_chars)
        if not allowed:
            _spam_record_violation(username, "message_too_long", 1)
            # Check if we should auto-split instead
            if len(text) <= max_chars * 3:  # Only auto-split if not excessively long
                allowed, chunks, split_reason = _spam_auto_split_with_rate_limit(username, text, max_chars // 2)
                if not allowed:  # Auto-split was applied
                    return False, split_reason, chunks
            else:
                return False, reason, None
        
        # 2. Duplicate & Near-Duplicate Detection
        allowed, reason = _spam_duplicate_detection(username, text)
        if not allowed:
            _spam_record_violation(username, "duplicate_content", 2)
            return False, reason, None
        
        # 3. Payload Size Monitoring
        allowed, reason = _spam_payload_size_check(text, max_bytes)
        if not allowed:
            _spam_record_violation(username, "payload_too_large", 2)
            return False, reason, None
        
        # 6. Content Pattern Analysis
        allowed, reason = _spam_content_pattern_analysis(text)
        if not allowed:
            _spam_record_violation(username, "suspicious_patterns", 1)
            return False, reason, None
        
        # 7. Progressive Sanction System
        allowed, reason = _spam_progressive_sanctions(username)
        if not allowed:
            return False, reason, None
        
        # All checks passed
        return True, "", None
        
    except Exception as e:
        # Fail safe: allow message but log error
        print(f"Anti-spam error: {e}")
        return True, "", None

    """Process queued auto-split message chunks."""
    try:
        now = time.time()
        split_queue = spam_split_queue[username]
        
        # Process ready chunks
        ready_chunks = []
        remaining_chunks = []
        
        for ts, chunk in split_queue:
            if now >= ts:
                ready_chunks.append(chunk)
            else:
                remaining_chunks.append((ts, chunk))
        
        # Update queue
        split_queue[:] = remaining_chunks
        
        return ready_chunks
                
    except Exception:
        return []


# Socket.IO connection management
@socketio.on('connect')
def _on_connect():
    try:
        u = session.get('username') or ''
        if not u:
            # reject anonymous socket connections for chat
            return False
        sid = request.sid
        connected_sockets[sid] = u
        try:
            join_room('chat_room')
        except Exception:
            pass
        try:
            join_room(f'user:{u}')
        except Exception:
            pass
        # If user is currently timed out, remind client
        try:
            until = user_timeouts.get(u) or 0
            if until and time.time() < float(until):
                emit('timeout_set', { 'until': int(until) }, room=sid)
        except Exception:
            pass
    except Exception:
        return False

@socketio.on('disconnect')
def _on_disconnect():
    try:
        sid = request.sid
        try:
            connected_sockets.pop(sid, None)
        except Exception:
            pass
        try:
            # Remove from any voice channel memberships
            u = None
            try:
                u = session.get('username') or ''
            except Exception:
                u = None
            if u:
                for ch in list(voice_channels.keys()):
                    if u in voice_channels[ch]:
                        try:
                            voice_channels[ch].discard(u)
                            leave_room(f"voice:{ch}")
                            socketio.emit('voice_participants', {'channel': ch, 'participants': sorted(list(voice_channels[ch]))}, room=f"voice:{ch}")
                        except Exception:
                            pass
        except Exception:
            pass
    except Exception:
        pass

# WebRTC Voice channel signaling and presence
@socketio.on('voice_join')
def _voice_join(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        join_room(f"voice:{ch}")
        voice_channels[ch].add(u)
        socketio.emit('voice_participants', {'channel': ch, 'participants': sorted(list(voice_channels[ch]))}, room=f"voice:{ch}")
    except Exception:
        pass

@socketio.on('voice_leave')
def _voice_leave(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        try:
            voice_channels[ch].discard(u)
        except Exception:
            pass
        leave_room(f"voice:{ch}")
        socketio.emit('voice_participants', {'channel': ch, 'participants': sorted(list(voice_channels[ch]))}, room=f"voice:{ch}")
    except Exception:
        pass

@socketio.on('voice_mute')
def _voice_mute(data):
    try:
        ch = (data or {}).get('channel') or ''
        muted = bool((data or {}).get('muted'))
        u = session.get('username') or ''
        if not ch or not u:
            return
        socketio.emit('voice_mute', {'channel': ch, 'user': u, 'muted': muted}, room=f"voice:{ch}")
    except Exception:
        pass

@socketio.on('voice_offer')
def _voice_offer(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        payload = {'channel': ch, 'from': u, 'sdp': (data or {}).get('sdp')}
        emit('voice_offer', payload, room=f"voice:{ch}", include_self=False)
    except Exception:
        pass

@socketio.on('voice_answer')
def _voice_answer(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        payload = {'channel': ch, 'from': u, 'sdp': (data or {}).get('sdp')}
        emit('voice_answer', payload, room=f"voice:{ch}", include_self=False)
    except Exception:
        pass

@socketio.on('voice_ice')
def _voice_ice(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        payload = {'channel': ch, 'from': u, 'candidate': (data or {}).get('candidate')}
        emit('voice_ice', payload, room=f"voice:{ch}", include_self=False)
    except Exception:
        pass

def _session_user_valid() -> bool:
    try:
        uid = session.get('user_id')
        uname = session.get('username')
        if not uid or not uname:
            return False
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT username FROM users WHERE id=?', (uid,))
        row = cur.fetchone()
        if not row:
            return False
        db_uname = row[0] if not isinstance(row, sqlite3.Row) else row['username']
        return db_uname == uname
    except Exception:
        return False

@app.before_request
def _enforce_bans_global():
    try:
        # Emergency shutdown auto-trigger check (periodic)
        try:
            _emergency_auto_trigger_check(
                get_db_func=get_db, db_path=DB_PATH
            )
        except Exception:
            pass
        ep = (request.endpoint or '')
        if ep and (ep.startswith('static') or ep in ('healthcheck',)):
            return
        # Enforce IP bans using private first, then public
        u = session.get('username') or ''
        priv, pub = detect_client_ips()
        if u:
            _update_user_ips(u, priv, pub)
            if _is_ip_blocked_for(u, priv, pub):
                return ("Your IP address is banned", 403)
        else:
            # Anonymous access: block by public/private as available
            if (priv and is_ip_banned(priv)) or (pub and is_ip_banned(pub)):
                return ("Your IP address is banned", 403)
        u = session.get('username')
        if u and is_banned(u):
            session.clear()
            return redirect(url_for('login'))
        # If a session exists but the user row is missing, force logout
        if session.get('user_id'):
            try:
                db = get_db(); cur = db.cursor()
                cur.execute('SELECT 1 FROM users WHERE id=?', (session['user_id'],))
                if not cur.fetchone():
                    session.clear()
                    return redirect(url_for('login'))
            except Exception:
                pass
    except Exception:
        pass

# Database helpers
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        db.row_factory = sqlite3.Row
        try:
            # Improve concurrency and durability/perf tradeoff for chat workloads
            db.execute('PRAGMA journal_mode=WAL;')
            db.execute('PRAGMA synchronous=NORMAL;')
            db.execute('PRAGMA temp_store=MEMORY;')
            db.execute('PRAGMA mmap_size=268435456;')  # 256MB
            db.execute('PRAGMA cache_size=-65536;')     # ~64MB page cache
        except Exception:
            pass
    return db

@app.teardown_appcontext
def close_connection(exc):
    db = getattr(g, "_database", None)
    if db:
        db.close()

# Downtime allowlist table
def _ensure_downtime_table():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS downtime_ip_allow (ip TEXT PRIMARY KEY)')
        db.commit()
    except Exception:
        pass

def _get_ip():
    try:
        return request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or request.remote_addr or ''
    except Exception:
        return request.remote_addr or ''

def _is_ip_allowed_during_downtime(ip: str) -> bool:
    try:
        _ensure_downtime_table()
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM downtime_ip_allow WHERE ip=?', (ip,))
        return cur.fetchone() is not None
    except Exception:
        return False

def _allow_ip_during_downtime(ip: str):
    try:
        _ensure_downtime_table()
        db = get_db(); cur = db.cursor()
        cur.execute('INSERT OR IGNORE INTO downtime_ip_allow(ip) VALUES(?)', (ip,))
        db.commit()
    except Exception:
        pass

def _clear_downtime_ips():
    try:
        _ensure_downtime_table()
        db = get_db(); cur = db.cursor()
        cur.execute('DELETE FROM downtime_ip_allow')
        db.commit()
    except Exception:
        pass

def _is_emergency_shutdown() -> bool:
    """Return True if emergency shutdown is active."""
    try:
        return emergency_shutdown_active
    except Exception:
        return False
def _emergency_write_block(user: str | None = None) -> bool:
    """Return True if writes should be blocked for this user due to emergency shutdown."""
    try:
        allowed, reason = _emergency_check_gate(
            username=user, 
            operation="message", 
            superadmins=SUPERADMINS
        )
        
        if not allowed:
            # Notify user of the block reason
            try:
                if user and reason:
                    emit("system_message", reason, room=f"user:{user}")
            except Exception:
                pass
            return True
        
        return False
    except Exception:
        # Fail safe: block writes during errors
        return True
def _downtime_gate():
    try:
        # Emergency shutdown piggybacks on downtime gate: either flag triggers the gate.
        is_emergency = _is_emergency_shutdown()
        if str(get_setting('DOWNTIME_ENABLED','0')) != '1' and not is_emergency:
            # reset allowlist when downtime ends (but keep it during an emergency)
            try: _clear_downtime_ips()
            except Exception: pass
            return
        # Always allow unlock API, /smite, and static/media so admins can generate/use codes
        path = request.path or ''
        if path.startswith('/api/downtime/unlock') or path.startswith('/smite') or path.startswith('/uploads/') or path.startswith('/static/'):
            return
        # Allow superadmins
        u = session.get('username') or ''
        if u and (u in SUPERADMINS):
            return
        # Allow whitelisted IPs
        ip = _get_ip()
        if ip and _is_ip_allowed_during_downtime(ip):
            return
        # Return downtime / emergency page
        reason = get_setting('DOWNTIME_REASON','') or ''
        if not reason:
            # Ensure a row exists in app_settings so DB tools will show it
            reason = 'No reason provided'
            try:
                set_setting('DOWNTIME_REASON', reason)
            except Exception:
                pass
        reason_html = ("<div style='height:10px'></div><div class='reason'>Reason: " + reason + "</div>")
        if is_emergency:
            heading = 'Emergency shutdown in progress'
            sub = 'An emergency maintenance is in progress. Please try again later.'
        else:
            heading = 'Chatter is temporarily unavailable'
            sub = 'We are performing maintenance. Please check back later.'
        html = (
            "<!doctype html>\n"
            "<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>\n"
            "<title>Chatter Down</title>\n"
            "<style>body{margin:0;font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh} .card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;max-width:640px;margin:16px;box-shadow:0 10px 30px rgba(0,0,0,.3)} .muted{color:#9ca3af} .reason{white-space:pre-wrap;word-break:break-word} .modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:center;justify-content:center;z-index:10000} .modal>.box{background:#111827;border:1px solid #374151;border-radius:12px;padding:16px;max-width:360px;width:92%} .input{width:100%;padding:10px;border-radius:8px;border:1px solid #374151;background:#0b1020;color:#e5e7eb} .btn{padding:8px 10px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff}</style>\n"
            "</head><body>\n"
            "  <div class='card'>\n"
            f"    <h2 style='margin:0 0 6px'>{heading}</h2>\n"
            f"    <div class='muted'>{sub}</div>\n"
            + reason_html +
            "    <div style='height:14px'></div>\n"
            "    <div class='muted' id='hint'></div>\n"
            "  </div>\n"
            "  <div class='modal' id='dtModal'><div class='box'>\n"
            "    <div style='font-weight:600;margin-bottom:6px'>Enter access code</div>\n"
            "    <input id='dtCode' type='password' class='input' placeholder='16-character code' autocomplete='off'/>\n"
            "    <div style='display:flex;gap:8px;justify-content:flex-end;margin-top:10px'>\n"
            "      <button id='dtCancel' class='btn' style='background:#374151'>Cancel</button>\n"
            "      <button id='dtSubmit' class='btn'>Unlock</button>\n"
            "    </div>\n"
            "  </div></div>\n"
            "<script>\n"
            "(function(){\n"
            "  let pressed = new Set();\n"
            "  document.addEventListener('keydown', async (e)=>{\n"
            "    pressed.add(e.key.toLowerCase());\n"
            "    if (pressed.has('control') && pressed.has('shift') && pressed.has('u')){\n"
            "      pressed.clear();\n"
            "      try{\n"
            "        const m = prompt('Enter master code'); if (!m) return;\n"
            "        const r = await fetch('/smite', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ master: m })});\n"
            "        const j = await r.json().catch(()=>({}));\n"
            "        if (r.ok && j && j.ok && j.code){\n"
            "          const modal = document.getElementById('dtModal'); const codeInput = document.getElementById('dtCode');\n"
            "          try{ codeInput.value = ''; modal.style.display='flex'; codeInput.focus(); }catch(_){ }\n"
            "          alert('Code copied to clipboard. Paste it into the box to unlock.');\n"
            "          try{ navigator.clipboard.writeText(j.code); }catch(_){ }\n"
            "        } else { alert((j&&j.error)||'Invalid'); }\n"
            "      }catch(_){ alert('Failed'); }\n"
            "    }\n"
            "  });\n"
            "  document.addEventListener('keyup', (e)=>{ pressed.delete(e.key.toLowerCase()); });\n"
            "  try{ document.getElementById('hint').textContent = ''; }catch(_){ }\n"
            "  try{\n"
            "    const modal = document.getElementById('dtModal');\n"
            "    const codeInput = document.getElementById('dtCode');\n"
            "    const cancelBtn = document.getElementById('dtCancel');\n"
            "    const submitBtn = document.getElementById('dtSubmit');\n"
            "    cancelBtn.onclick = ()=>{ modal.style.display='none'; codeInput.value=''; };\n"
            "    async function submit(){\n"
            "      const pass = (codeInput.value||'').trim(); if (!pass) return;\n"
            "      try{ const r = await fetch('/api/downtime/unlock', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ code: pass })}); if (r.ok){ codeInput.value=''; location.reload(); } else { alert('Invalid code'); } }catch(_){ alert('Failed'); }\n"
            "    }\n"
            "    submitBtn.onclick = submit; codeInput.onkeydown = (e)=>{ if (e.key==='Enter') submit(); };\n"
            "  }catch(_){ }\n"
            "})();\n"
            "</script>\n"
            "</body></html>\n"
        )
        return html
    except Exception:
        pass

# ===================== Datasette Reverse Proxy (superadmin only) =====================
def _proxy_filter_headers(src):
    # Remove hop-by-hop headers
    excluded = {
        'connection','keep-alive','proxy-authenticate','proxy-authorization',
        'te','trailers','transfer-encoding','upgrade','content-length'
    }
    return {k: v for k, v in src.items() if k.lower() not in excluded}
@app.route('/admin/sqlite', defaults={'subpath': ''}, methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
@app.route('/admin/sqlite/<path:subpath>', methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
@login_required
def admin_sqlite_proxy(subpath: str):
    return abort(404)

@app.route('/admin/datasette')
@login_required
def admin_datasette_helper():
    return abort(404)

# Proxy py4web DB admin under this Flask app
@app.route('/db_admin', defaults={'subpath': ''}, methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
@app.route('/db_admin/<path:subpath>', methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
def proxy_db_admin(subpath: str):
    try:
        base = 'http://127.0.0.1:8000/db_admin'
        qs = (request.query_string or b'').decode('utf-8', 'ignore')
        url = base + ('/' + subpath if subpath else '') + (('?' + qs) if qs else '')
        headers = _proxy_filter_headers(request.headers)
        # Forward request body and cookies
        r = requests.request(
            request.method,
            url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
            timeout=30,
        )
        resp = Response(r.content, status=r.status_code)
        for k, v in r.headers.items():
            kl = k.lower()
            if kl in ('connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailers','transfer-encoding','upgrade','content-length'):
                continue
            resp.headers[k] = v
        return resp
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/api/downtime/unlock', methods=['POST'])
def api_downtime_unlock():
    try:
        data = request.get_json(silent=True) or {}
        code = (data.get('code') or data.get('passcode') or '').strip()
        if not code:
            return jsonify({'error':'missing'}), 400
        # Compare in a case-insensitive safe way
        cur_code = _get_downtime_code()
        if code and cur_code and secrets.compare_digest(code.upper(), cur_code.upper()):
            _allow_ip_during_downtime(_get_ip())
            _rotate_downtime_code()
            return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ======== DBX code-gate helpers ========
def _get_dbx_code():
    try:
        code = get_setting('DBX_CODE','') or ''
        if not code:
            code = _rand_code(8)
            set_setting('DBX_CODE', code)
        return code
    except Exception:
        return _rand_code(8)

def _make_dbxok_cookie() -> str:
    try:
        payload = json.dumps({'ok': True, 'ts': int(time.time())}, separators=(',',':')).encode('utf-8')
        sig = hmac.new(app.secret_key.encode('utf-8'), payload, hashlib.sha256).digest()
        return _b64u(payload) + '.' + _b64u(sig)
    except Exception:
        return ''

def _verify_dbxok_cookie(val: str) -> bool:
    try:
        if not val or '.' not in val:
            return False
        p, s = val.split('.',1)
        payload = _b64ud(p); sig = _b64ud(s)
        good = hmac.compare_digest(hmac.new(app.secret_key.encode('utf-8'), payload, hashlib.sha256).digest(), sig)
        return bool(good)
    except Exception:
        return False

def _dbx_ok() -> bool:
    try:
        # superadmin always ok
        if is_superadmin():
            return True
        # code cookie
        v = request.cookies.get('dbxok') or ''
        if _verify_dbxok_cookie(v):
            return True
        return False
    except Exception:
        return False
    return jsonify({'error':'invalid'}), 403

# Alerts API
@app.route('/api/alerts')
def api_alerts():
    try:
        enabled = str(get_setting('ALERTS_ENABLED','0'))=='1'
        text = get_setting('ALERTS_TEXT','') or ''
        return jsonify({'enabled': enabled, 'text': text})
    except Exception:
        return jsonify({'enabled': False, 'text': ''})

# Admin settings for downtime and alerts
@app.route('/api/admin/settings', methods=['POST'])
@login_required
def api_admin_settings():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    keys = ['DOWNTIME_ENABLED','DOWNTIME_REASON','ALERTS_ENABLED','ALERTS_TEXT']
    try:
        for k in keys:
            if k in data:
                set_setting(k, str(data[k]))
        try:
            if str(get_setting('DOWNTIME_ENABLED','0')) != '1':
                _clear_downtime_ips()
                set_setting('DOWNTIME_CODE','')
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/whoami')
def api_whoami():
    try:
        sess = session.get('username') or ''
        hdr = request.headers.get('X-DBX') or ''
        q = request.args.get('dbx') or ''
        cook = request.cookies.get('dbx') or ''
        hdr_u = _verify_dbx_token(hdr)
        q_u = _verify_dbx_token(q)
        c_u = _verify_dbx_token(cook)
        eff = sess or hdr_u or q_u or c_u
        return jsonify({ 'session': sess, 'x_dbx_user': hdr_u, 'q_dbx_user': q_u, 'cookie_dbx_user': c_u, 'effective': eff, 'is_superadmin': bool(eff in SUPERADMINS) })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# Emergency Shutdown API Routes
@app.route('/api/emergency/status')
def api_emergency_shutdown_status():
    """Get current emergency shutdown status."""
    try:
        username = session.get('username', '')
        
        # Only admins and superadmins can view status
        if not (is_admin(username) or is_superadmin(username)):
            return jsonify({'error': 'Unauthorized'}), 403
        
        status = get_emergency_status()
        
        # Include snapshot for superadmins only
        if not is_superadmin(username):
            status.pop('snapshot', None)
        
        return jsonify({'ok': True, 'status': status})
        
    except Exception as e:
        return jsonify({'error': f'Failed to get status: {e}'}), 500

@app.route('/api/emergency/activate', methods=['POST'])
def api_emergency_shutdown_activate():
    """Activate emergency shutdown (superadmin only)."""
    try:
        username = session.get('username', '')
        
        # Only superadmins can activate emergency shutdown
        if not is_superadmin(username):
            return jsonify({'error': 'Unauthorized - Superadmin required'}), 403
        
        data = request.get_json() or {}
        trigger = data.get('trigger', 'ADMIN_COMMAND')
        auto_backup = data.get('auto_backup', True)
        
        # Helper function to notify all users
        def notify_all_users(message):
            try:
                emit('emergency_notification', {'message': message}, broadcast=True)
            except Exception as e:
                _emergency_log(f"Failed to send emergency notification: {e}", "ERROR")
        
        success = emergency_shutdown_activate(
            trigger=trigger,
            admin=username,
            auto_backup=auto_backup,
            db_path=DB_PATH,
            get_db_func=get_db,
            get_setting_func=get_setting,
            set_setting_func=set_setting,
            connected_sockets=connected_sockets,
            spam_strikes=spam_strikes,
            notify_func=notify_all_users
        )
        
        if success:
            return jsonify({'ok': True, 'message': 'Emergency shutdown activated'})
        else:
            return jsonify({'error': 'Failed to activate emergency shutdown'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Failed to activate: {e}'}), 500

@app.route('/api/emergency/deactivate', methods=['POST'])
def api_emergency_shutdown_deactivate():
    """Deactivate emergency shutdown (superadmin only)."""
    try:
        username = session.get('username', '')
        
        # Only superadmins can deactivate emergency shutdown
        if not is_superadmin(username):
            return jsonify({'error': 'Unauthorized - Superadmin required'}), 403
        
        # Helper function to notify all users
        def notify_all_users(message):
            try:
                emit('emergency_notification', {'message': message}, broadcast=True)
            except Exception as e:
                _emergency_log(f"Failed to send emergency notification: {e}", "ERROR")
        
        success = emergency_shutdown_deactivate(
            admin=username,
            set_setting_func=set_setting,
            notify_func=notify_all_users
        )
        
        if success:
            return jsonify({'ok': True, 'message': 'Emergency shutdown deactivated'})
        else:
            return jsonify({'error': 'Failed to deactivate emergency shutdown'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Failed to deactivate: {e}'}), 500

@app.route('/api/emergency/stage', methods=['POST'])
def api_emergency_shutdown_set_stage():
    """Set recovery stage (superadmin only)."""
    try:
        username = session.get('username', '')
        
        # Only superadmins can set recovery stage
        if not is_superadmin(username):
            return jsonify({'error': 'Unauthorized - Superadmin required'}), 403
        
        data = request.get_json() or {}
        stage = data.get('stage', 0)
        
        if not isinstance(stage, int) or stage < 0 or stage > 3:
            return jsonify({'error': 'Invalid stage - must be 0-3'}), 400
        
        success = emergency_shutdown_set_stage(stage, username)
        
        if success:
            return jsonify({'ok': True, 'message': f'Recovery stage set to {stage}'})
        else:
            return jsonify({'error': 'Failed to set recovery stage'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Failed to set stage: {e}'}), 500

@app.route('/api/emergency/lock_user', methods=['POST'])
def api_emergency_shutdown_lock_user():
    """Lock a user during emergency (admin only)."""
    try:
        username = session.get('username', '')
        
        # Only admins and superadmins can lock users
        if not (is_admin(username) or is_superadmin(username)):
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json() or {}
        target_user = data.get('username', '').strip()
        
        if not target_user:
            return jsonify({'error': 'Username required'}), 400
        
        # Prevent locking superadmins
        if target_user in SUPERADMINS:
            return jsonify({'error': 'Cannot lock superadmin'}), 400
        
        success = emergency_shutdown_lock_user(target_user, username)
        
        if success:
            return jsonify({'ok': True, 'message': f'User {target_user} locked'})
        else:
            return jsonify({'error': 'Failed to lock user'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Failed to lock user: {e}'}), 500

@app.route('/api/emergency/unlock_user', methods=['POST'])
def api_emergency_shutdown_unlock_user():
    """Unlock a user during emergency (admin only)."""
    try:
        username = session.get('username', '')
        
        # Only admins and superadmins can unlock users
        if not (is_admin(username) or is_superadmin(username)):
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json() or {}
        target_user = data.get('username', '').strip()
        
        if not target_user:
            return jsonify({'error': 'Username required'}), 400
        
        success = emergency_shutdown_unlock_user(target_user, username)
        
        if success:
            return jsonify({'ok': True, 'message': f'User {target_user} unlocked'})
        else:
            return jsonify({'error': 'Failed to unlock user'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Failed to unlock user: {e}'}), 500

@app.route('/api/emergency/logs')
def api_emergency_shutdown_logs():
    """Get emergency shutdown logs (admin only)."""
    try:
        username = session.get('username', '')
        
        # Only admins and superadmins can view logs
        if not (is_admin(username) or is_superadmin(username)):
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get pagination parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = max(1, min(100, int(request.args.get('per_page', 50))))
        
        result = get_emergency_logs(page, per_page)
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 500
        
        return jsonify({'ok': True, **result})
        
    except Exception as e:
        return jsonify({'error': f'Failed to get logs: {e}'}), 500


@app.route('/smite', methods=['GET','POST'])
def api_smite():
    if request.method == 'GET':
        # If redirected after a successful POST, show the code once and then clear it
        show = (request.args.get('show') or '').lower()
        if show == 'code':
            code_once = session.pop('smite_code', None)
            if code_once:
                return (
                    "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Downtime Code</title>"
                    "<style>body{margin:0;font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh}"
                    ".card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;max-width:480px;margin:16px;box-shadow:0 10px 30px rgba(0,0,0,.3)}"
                    ".muted{color:#9ca3af}.code{font-size:20px;letter-spacing:2px;background:#0b1020;border:1px solid #374151;padding:10px;border-radius:8px;display:flex;gap:8px;align-items:center;justify-content:space-between}"
                    ".btn{padding:8px 10px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff}</style></head><body>"
                    "<div class='card'><h3 style='margin-top:0'>Current downtime code</h3>"
                    "<div class='code'><span>••••••••••••••••</span> "
                    f"<button class='btn' onclick=\"navigator.clipboard.writeText('{code_once}')\">Copy</button></div>"
                    "<div class='muted' style='margin-top:8px'>Code rotates after each successful unlock.</div>"
                    "</div></body></html>"
                )
        # Default: Simple HTML form (available even during downtime)
        return ("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                "<title>/smite</title>"
                "<style>body{margin:0;font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh}"
                ".card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;max-width:480px;margin:16px;box-shadow:0 10px 30px rgba(0,0,0,.3)}"
                ".input{width:100%;padding:10px;border-radius:8px;border:1px solid #374151;background:#0b1020;color:#e5e7eb}"
                ".btn{padding:8px 10px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff}</style></head><body>"
                "<div class='card'><h3 style='margin-top:0'>/smite</h3>"
                "<form method='post'><input name='master' type='password' placeholder='Master code' class='input' style='margin-bottom:8px' autocomplete='off'>"
                "<button type='submit' class='btn'>Get current downtime code</button></form>"
                "</div></body></html>")
    # POST (form or JSON)
    try:
        is_json = bool(request.is_json)
        master_form = (request.form.get('master') if not is_json else None)
        master_json = ((request.get_json(silent=True) or {}).get('master') if is_json else None)
        master = (master_form or master_json or '').strip()
        if master == 'Smite6741':
            code = _get_downtime_code()
            if not is_json and (master_form is not None):
                # Store code for one-time display on redirected GET
                try:
                    session['smite_code'] = code
                except Exception:
                    pass
                return redirect(url_for('api_smite', show='code'))
            # JSON client (Ctrl+Shift+U flow)
            return jsonify({'ok': True, 'code': code})
        return jsonify({'error':'invalid'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Back-compat: Admin app settings endpoint used by some clients
@app.route('/api/admin/app_settings', methods=['GET','POST'])
@login_required
def api_admin_app_settings_v2():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    if request.method == 'GET':
        try:
            _seed_defaults_if_needed()
            db = get_db(); cur = db.cursor()
            try:
                cur.execute('SELECT key, value FROM app_settings')
            except Exception:
                _ensure_app_settings(); cur.execute('SELECT key, value FROM app_settings')
            out = {}
            for row in cur.fetchall():
                k = row[0] if not isinstance(row, sqlite3.Row) else row['key']
                v = row[1] if not isinstance(row, sqlite3.Row) else row['value']
                out[k] = v
            return jsonify({'ok': True, 'settings': out})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    # POST
    data = request.get_json(silent=True) or {}
    settings = data.get('settings') if isinstance(data.get('settings'), dict) else data
    try:
        # Ensure table exists before writes
        try:
            _ensure_app_settings()
        except Exception:
            pass
        for k, v in (settings or {}).items():
            set_setting(str(k), str(v))
        try:
            if str(get_setting('DOWNTIME_ENABLED','0')) != '1':
                _clear_downtime_ips()
                set_setting('DOWNTIME_CODE','')
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Admin toggles: accept flat or {settings:{}} payload
@app.route('/api/admin/toggles', methods=['POST'])
@login_required
def api_admin_toggles():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    settings = data.get('settings') if isinstance(data.get('settings'), dict) else data
    try:
        keys = set([
            # Global/chat
            'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED','MAINTENANCE_MODE','INVITE_ONLY_MODE','ANNOUNCEMENTS_ONLY',
            # User management
            'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
            # Message controls
            'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_SEARCH_MESSAGES','MC_PURGE_CHANNEL','MC_PIN_MESSAGE','MC_BROADCAST_MESSAGE','MC_VIEW_HISTORY','MC_MESSAGE_LIFESPAN','MC_MESSAGE_LIFESPAN_DAYS',
            # Group tools
            'GD_LOCK_GROUP','GD_UNLOCK_GROUP','GD_REMOVE_USER','GD_TRANSFER_OWNERSHIP','GD_ARCHIVE_GROUP','GD_DELETE_GROUP','GD_CLOSE_ALL_DMS','GD_DM_AS_SYSTEM','GD_SAVE_DM_LOGS','GD_FORCE_LEAVE_GROUP',
            # Admin tools
            'ADMIN_SYNC_PERMS','ADMIN_VIEW_ACTIVE','ADMIN_STEALTH_MODE','ADMIN_EMERGENCY_SHUTDOWN',
            # Downtime & Alerts
            'DOWNTIME_ENABLED','DOWNTIME_REASON','ALERTS_ENABLED','ALERTS_TEXT',
            # Security
            'SEC_STRICT_ASSOCIATED_BAN','SEC_DEVICE_BAN_ON_LOGIN','SEC_REG_BAN_SIMILAR_CID',
        ])
        for k, v in (settings or {}).items():
            if k not in keys:
                continue
            if k == 'MC_MESSAGE_LIFESPAN_DAYS':
                try:
                    v = str(max(0, int(str(v).strip() or '0')))
                except Exception:
                    v = '0'
            else:
                v = str(v)
            set_setting(k, v)
        # Clear downtime allowlist if downtime disabled and reset code
        try:
            if str(get_setting('DOWNTIME_ENABLED','0')) != '1':
                _clear_downtime_ips()
                set_setting('DOWNTIME_CODE','')
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Superadmin DB editor
@app.route('/api/admin/sql_run', methods=['POST'])
@login_required
def api_admin_sql_run():
    me = session.get('username')
    if not (me in SUPERADMINS):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    sql = (data.get('sql') or '').strip()
    if not sql:
        return jsonify({'error':'missing sql'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute(sql)
        rows = cur.fetchall() if sql.strip().lower().startswith('select') else []
        db.commit()
        out = []
        for r in rows:
            if isinstance(r, sqlite3.Row):
                out.append({ k:r[k] for k in r.keys() })
            else:
                out.append(list(r))
        return jsonify({'ok': True, 'rows': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ===================== New DB Browser (from scratch) =====================
def _dbx_tables(cur):
    cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name")
    return [ (r[0] if not isinstance(r, sqlite3.Row) else r['name']) for r in cur.fetchall() ]

def _dbx_schema(cur, table):
    # Use tuple-based PRAGMA to avoid any row_factory/keys() nuances
    c2 = cur.connection.cursor()
    c2.execute(f"PRAGMA table_info({table})")
    cols = []
    for r in c2.fetchall():
        # PRAGMA table_info returns: (cid, name, type, notnull, dflt_value, pk)
        try:
            name = r[1]
            pkflag = r[5]
            cols.append({'name': name, 'pk': pkflag})
        except Exception:
            pass
    pk = [ c['name'] for c in cols if c.get('pk') ]
    # detect rowid availability
    has_rowid = False
    try:
        cur.execute(f"SELECT rowid FROM {table} LIMIT 1")
        cur.fetchone(); has_rowid = True
    except Exception:
        has_rowid = False
    return cols, pk, has_rowid

def _dbx_select(cur, table, limit=100, offset=0, search=None, sort=None, desc=False):
    cols, pk, has_rowid = _dbx_schema(cur, table)
    names = [c['name'] for c in cols]
    where = []
    params = []
    if search:
        like_clause = ' OR '.join([f"CAST({n} AS TEXT) LIKE ?" for n in names])
        where.append(f"({like_clause})")
        params.extend([f"%{search}%"]*len(names))
    where_sql = (" WHERE "+" AND ".join(where)) if where else ""
    order_sql = f" ORDER BY {sort} {'DESC' if desc else 'ASC'}" if sort and sort in names else ""
    # Use a fresh connection without detect_types to avoid sqlite's timestamp
    # auto-decoder raising "too many values to unpack" on non-standard values.
    try:
        tmp_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    except Exception:
        tmp_conn = cur.connection
    c2 = tmp_conn.cursor()
    sel = f"SELECT {'rowid AS rid, ' if has_rowid else ''}* FROM {table}{where_sql}{order_sql} LIMIT ? OFFSET ?"
    c2.execute(sel, params + [limit, offset])
    # Build dicts from cursor.description to avoid row_factory quirks
    cols_meta = c2.description or []
    colnames = [d[0] for d in cols_meta]
    rows = []
    for tup in c2.fetchall():
        obj = {}
        for i, k in enumerate(colnames):
            try:
                v = tup[i]
            except Exception:
                v = None
            # Coerce datetimes to string for JSON
            try:
                from datetime import datetime as _dt
                if isinstance(v, _dt):
                    v = to_ny_time(v)
            except Exception:
                pass
            # Coerce bytes-like to base64 string
            try:
                if isinstance(v, (bytes, bytearray, memoryview)):
                    v = _b64u(bytes(v))
            except Exception:
                pass
            obj[k] = v
        rows.append(obj)
    try:
        if tmp_conn is not cur.connection:
            tmp_conn.close()
    except Exception:
        pass
    return { 'columns': cols, 'pk': (['rid'] if has_rowid else pk), 'has_rowid': has_rowid, 'rows': rows }

@app.route('/api/admin/dbx/tables')
def api_admin_dbx_tables():
    return abort(404)

@app.route('/api/admin/dbx/table')
def api_admin_dbx_table():
    return abort(404)

@app.route('/api/admin/dbx/save', methods=['POST'])
def api_admin_dbx_save():
    return abort(404)

@app.route('/dbx')
def dbx_unlock_ui():
    # Show unlock UI always so superadmins can view/copy the code
    code_hint = '[code set]'
    if is_superadmin(session.get('username') or ''):
        try:
            code_hint = _ensure_dbx_code()
        except Exception:
            pass
    html = (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>DBX Unlock</title><style>body{margin:0;font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh} .card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;max-width:520px;margin:16px} .label{font-size:12px;color:#9ca3af} .input{width:100%;padding:10px;border-radius:8px;border:1px solid #374151;background:#0b1020;color:#e5e7eb} .btn{padding:8px 10px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff}</style></head><body>"
        f"<div class='card'><h3>Enter DB Admin Code</h3><div style='height:8px'></div><input id='code' class='input' placeholder='Enter code'/>"
        f"<div style='height:8px'></div><button id='go' class='btn'>Unlock</button>"
        f"<div style='height:12px'></div><div class='label'>Current code (visible to superadmins only):</div><input class='input' value='{code_hint}' readonly onclick=\"this.select();document.execCommand('copy');\" title='Click to copy'/>"
        "</div><script>document.getElementById('go').onclick=async()=>{const v=(document.getElementById('code').value||'').trim(); if(!v) return; const r=await fetch('/api/dbx/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:v})}); if(r.ok){ location.href='/admin/dbsafe'; } else { alert('Invalid code'); } };</script></body></html>"
    )
    return html

# ===================== Single-file Safe DB Admin (superadmin-only) =====================
@app.route('/admin/dbsafe')
def admin_dbsafe_index():
    if not _dbx_ok():
        return redirect('/dbx')
    db = get_db(); cur = db.cursor()
    tables = _dbx_tables(cur)
    items = ''.join([f"<li><a href='/admin/dbsafe/table?name={_html.escape(t)}'>{_html.escape(t)}</a></li>" for t in tables])
    html = (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>DB Safe Admin</title><style>body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#0f172a;color:#e5e7eb} .wrap{display:flex;min-height:100vh} .side{width:260px;border-right:1px solid #1f2937;padding:12px;background:#111827} .main{flex:1;padding:16px} a{color:#93c5fd;text-decoration:none} ul{list-style:none;margin:0;padding:0} li{margin:6px 0} input,select,button{background:#0b1020;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:6px} button{cursor:pointer} button:hover{filter:brightness(1.1)} .toolbar{display:flex;gap:8px;align-items:center;margin-bottom:12px} .toast{position:fixed;right:12px;top:12px;background:#1f2937;color:#e5e7eb;border:1px solid #374151;border-radius:8px;padding:10px 12px;z-index:9999;display:none}</style></head><body>"
        "<div class='wrap'><div class='side'><b>Tables</b><ul>"+items+"</ul></div><div class='main'>"
        "<div class='toolbar'><h3 style='margin:0'>DB Safe Admin</h3>"
        "<button onclick=\"if(confirm('Delete ALL rows from ALL tables except app_settings?')) fetch('/admin/dbsafe/clear_all',{method:'POST'}).then(r=>r.json()).then(()=>location.reload()).catch(()=>alert('Failed'));\">Clear All (keep app_settings)</button>"
        "<button onclick=\"saveAllForms()\">Save All</button>"
        "</div><p>Select a table from the left.</p><div id='toast' class='toast'></div>"
        "</div></div><script>function showToast(t){try{const el=document.getElementById('toast'); el.textContent=t; el.style.display='block'; setTimeout(()=>{el.style.display='none'}, 1600);}catch(_){}} async function saveAllForms(){ const forms=[...document.querySelectorAll('tbody form[action=\"/admin/dbsafe/apply\"]')]; if(!forms.length){ showToast('Nothing to save'); return;} for(const f of forms){ const fd=new FormData(f); fd.set('action','update'); try{ await fetch('/admin/dbsafe/apply',{method:'POST', body: fd}); }catch(e){} } location.reload(); }</script></body></html>"
    )
    return html

@app.route('/dbsafe')
def dbsafe_alias_root():
    if not _dbx_ok():
        return redirect('/dbx')
    return redirect('/admin/dbsafe')

@app.route('/admin/dbsafe/table')
def admin_dbsafe_table():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.args.get('name') or '').strip()
    if not name:
        return redirect('/admin/dbsafe')
    try:
        limit = max(1, min(200, int(request.args.get('limit') or '50')))
    except Exception:
        limit = 50
    try:
        offset = max(0, int(request.args.get('offset') or '0'))
    except Exception:
        offset = 0
    search = (request.args.get('search') or '').strip() or None
    sort = (request.args.get('sort') or '').strip() or None
    desc = (request.args.get('desc') or '').strip() == '1'
    db = get_db(); cur = db.cursor()
    cols, pk, has_rowid = _dbx_schema(cur, name)
    data = _dbx_select(cur, name, limit=limit, offset=offset, search=search, sort=sort, desc=desc)
    rows = data.get('rows') or []
    # Header
    ths = ''.join([f"<th style='padding:6px;border-bottom:1px solid #1f2937;text-align:left'>{_html.escape(c['name'])}</th>" for c in cols])
    # Rows with update/delete forms
    trs = []
    for r in rows:
        inputs = []
        for c in cols:
            v = r.get(c['name'])
            sval = '' if v is None else str(v)
            inputs.append(f"<td style='padding:6px;border-top:1px solid #1f2937'><input name='val_{_html.escape(c['name'])}' value='{_html.escape(sval)}' /></td>")
        # Identity hidden fields
        hidden = []
        if has_rowid and ('rid' in r):
            hidden.append(f"<input type='hidden' name='rid' value='{_html.escape(str(r['rid']))}'>")
        for k in (pk or []):
            if k in r and r[k] is not None:
                hidden.append(f"<input type='hidden' name='pk_{_html.escape(k)}' value='{_html.escape(str(r[k]))}'>")
        form_update = (
            "<form method='POST' action='/admin/dbsafe/apply' style='display:inline'>"
            f"<input type='hidden' name='table' value='{_html.escape(name)}'>"
            + ''.join(hidden) + ''.join(inputs) +
            "<td style='padding:6px;border-top:1px solid #1f2937'>"
            "<button name='action' value='update'>Save</button> "
            "<button name='action' value='delete' onclick=\"return confirm('Delete row?')\">Delete</button>"
            "</td></form>"
        )
        trs.append(f"<tr>{form_update}</tr>")
    body = ''.join(trs) or "<tr><td colspan='99' style='padding:8px;color:#9ca3af'>No rows</td></tr>"
    # Insert form
    ins_inputs = ''.join([f"<td style='padding:6px;border-top:1px solid #1f2937'><input name='val_{_html.escape(c['name'])}' placeholder='{_html.escape(c['name'])}' /></td>" for c in cols if not c.get('pk')])
    insert_form = (
        "<form method='POST' action='/admin/dbsafe/apply'><tr>"
        f"<input type='hidden' name='table' value='{_html.escape(name)}'>"
        + ins_inputs +
        "<td style='padding:6px;border-top:1px solid #1f2937'><button name='action' value='insert'>Insert</button></td>"
        "</tr></form>"
    )
    # Sidebar tables
    tables = _dbx_tables(cur)
    links = ''.join([f"<li><a href='/admin/dbsafe/table?name={_html.escape(t)}'>{_html.escape(t)}</a></li>" for t in tables])
    # Controls
    controls = (
        "<form method='GET' action='/admin/dbsafe/table' style='margin-bottom:10px'>"
        f"<input type='hidden' name='name' value='{_html.escape(name)}'>"
        f"<input name='search' placeholder='Search' value='{_html.escape(request.args.get('search') or '')}' /> "
        f"<input name='limit' type='number' min='1' max='200' value='{limit}' /> "
        f"<input name='offset' type='number' min='0' value='{offset}' /> "
        "<button type='submit'>Apply</button>"
        "</form>"
    )
    # Build an insert row with inputs for ALL columns, including id/key/etc.
    try:
        insert_cells = ''.join([
            (lambda cn: f"<td><input name='val_{_html.escape(cn)}' placeholder='{_html.escape(cn)}' /></td>")(c['name']) for c in cols
        ])
        insert_form = (
            "<tr>"
            "<form method='POST' action='/admin/dbsafe/apply'>"
            f"<input type='hidden' name='table' value='{_html.escape(name)}'>"
            "<input type='hidden' name='action' value='insert'>"
            + insert_cells +
            "<td><button type='submit'>Insert</button></td>"
            "</form>"
            "</tr>"
        )
    except Exception:
        insert_form = ""
    html = (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>DB Safe Admin - { _html.escape(name) }</title>"
        "<style>body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#0f172a;color:#e5e7eb} .wrap{display:flex;min-height:100vh} .side{width:260px;border-right:1px solid #1f2937;padding:12px;background:#111827} .main{flex:1;padding:16px} a{color:#93c5fd;text-decoration:none} ul{list-style:none;margin:0;padding:0} li{margin:6px 0} table{border-collapse:collapse;width:100%} thead th{position:sticky;top:0;background:#0b1327;z-index:1} tbody tr:nth-child(odd){background:#0e1730} tbody tr:nth-child(even){background:#0b1327} td,th{border-bottom:1px solid #1f2937} input,button{background:#0b1020;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:6px} button{cursor:pointer} button:hover{filter:brightness(1.1)} .toolbar{display:flex;gap:8px;align-items:center;margin-bottom:12px} .toast{position:fixed;right:12px;top:12px;background:#1f2937;color:#e5e7eb;border:1px solid #374151;border-radius:8px;padding:10px 12px;z-index:9999;display:none}</style></head><body>"
        "<div class='wrap'>"
        f"<div class='side'><b>Tables</b><ul>{links}</ul><div style='margin-top:12px'><a href='/admin/dbsafe'>Home</a></div></div>"
        f"<div class='main'><div class='toolbar'><h3 style='margin:0'>{_html.escape(name)}</h3>"
        "<button onclick=\"saveAllForms()\">Save All</button>"
        f"<form method='POST' action='/admin/dbsafe/clear_table' style='display:inline;margin-left:8px'><input type='hidden' name='name' value='{_html.escape(name)}'><button onclick=\"return confirm('Clear this table?')\">Clear This Table</button></form>"
        f"<a href='/admin/dbsafe/export?name={_html.escape(name)}' style='margin-left:8px'><button type='button'>Export CSV</button></a>"
        f"<form method='POST' action='/admin/dbsafe/import' enctype='multipart/form-data' style='display:inline;margin-left:8px'><input type='hidden' name='name' value='{_html.escape(name)}'><input type='file' name='file' accept='.csv' required><button type='submit'>Import CSV</button></form>"
        "</div>" + controls + f"<div id='toast' class='toast'></div><table><thead><tr>{ths}<th>Actions</th></tr></thead><tbody>" + body + insert_form + "</tbody></table>"
        "</div></div><script>function showToast(t){try{const el=document.getElementById('toast'); el.textContent=t; el.style.display='block'; setTimeout(()=>{el.style.display='none'}, 1600);}catch(_){}} async function saveAllForms(){ const forms=[...document.querySelectorAll('tbody form[action=\"/admin/dbsafe/apply\"]')]; if(!forms.length){ showToast('Nothing to save'); return;} for(const f of forms){ const fd=new FormData(f); if(!fd.get('action')){ fd.set('action','update'); } try{ await fetch('/admin/dbsafe/apply',{method:'POST', body: fd}); }catch(e){} } location.reload(); }</script></body></html>"
    )
    return html

@app.route('/dbsafe/table')
def dbsafe_alias_table():
    if not _dbx_ok():
        return redirect('/dbx')
    # preserve query string (name, limit, offset, etc.)
    qs = (request.query_string or b'').decode('utf-8', 'ignore')
    return redirect('/admin/dbsafe/table' + (('?' + qs) if qs else ''))

@app.route('/admin/dbsafe/apply', methods=['POST'])
def admin_dbsafe_apply():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.form.get('table') or '').strip()
    action = (request.form.get('action') or '').strip()
    if not name or action not in ('insert','update','delete'):
        return redirect('/admin/dbsafe')
    db = get_db(); cur = db.cursor()
    cols, pk, has_rowid = _dbx_schema(cur, name)
    # Build value dict from form
    values = {}
    for c in cols:
        k = f"val_{c['name']}"
        if k in request.form:
            values[c['name']] = request.form.get(k)
    new_dbx_after = False
    try:
        if action == 'insert':
            if values:
                ks = list(values.keys())
                cur.execute(f"INSERT INTO {name} ("+','.join(ks)+") VALUES ("+','.join(['?']*len(ks))+")", [values[k] for k in ks])
                if name == 'app_settings':
                    try:
                        if (values.get('key') == 'DBX_CODE') or (request.form.get('val_key') == 'DBX_CODE'):
                            new_dbx_after = True
                    except Exception:
                        pass
        elif action in ('update','delete'):
            where_sql = ''
            where_params = []
            # Prefer rowid if present
            rid = request.form.get('rid')
            if has_rowid and rid not in (None, ''):
                where_sql = 'rowid = ?'; where_params = [rid]
            elif pk:
                parts = []
                for k in pk:
                    parts.append(f"{k}=?"); where_params.append(request.form.get(f'pk_{k}'))
                where_sql = ' AND '.join(parts)
            else:
                return redirect(f"/admin/dbsafe/table?name={name}")
            if action == 'update':
                set_ks = [k for k in values.keys()]
                if set_ks:
                    cur.execute(f"UPDATE {name} SET " + ','.join([f"{k}=?" for k in set_ks]) + f" WHERE {where_sql}", [values[k] for k in set_ks] + where_params)
                    if name == 'app_settings':
                        try:
                            # If editing the DBX_CODE row and value provided, refresh cookie after commit
                            target_key = request.form.get('pk_key') or request.form.get('val_key')
                            if (target_key == 'DBX_CODE') and ('value' in values or 'val_value' in request.form):
                                new_dbx_after = True
                        except Exception:
                            pass
            else:
                cur.execute(f"DELETE FROM {name} WHERE {where_sql}", where_params)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    # Build redirect response; if DBX_CODE changed, refresh dbxok cookie so user stays authorized
    from flask import make_response
    resp = make_response(redirect(f"/admin/dbsafe/table?name={name}"))
    if new_dbx_after:
        try:
            resp.set_cookie('dbxok', _make_dbxok_cookie(), max_age=3600, secure=True, httponly=True, samesite='Lax', path='/')
        except Exception:
            pass
    return resp

@app.route('/admin/dbsafe/clear_all', methods=['POST'])
def admin_dbsafe_clear_all():
    if not _dbx_ok():
        return jsonify({'error':'forbidden'}), 403
    try:
        db = get_db(); cur = db.cursor()
        tables = _dbx_tables(cur)
        protected = {'app_settings'}
        cleared = []
        skipped = []
        try:
            cur.execute('BEGIN')
        except Exception:
            pass
        for t in tables:
            if t in protected:
                skipped.append(t)
                continue
            try:
                cur.execute(f'DELETE FROM {t}')
                # Reset AUTOINCREMENT sequence if present
                try:
                    cur.execute('DELETE FROM sqlite_sequence WHERE name=?', (t,))
                except Exception:
                    pass
                cleared.append(t)
            except Exception:
                # Skip tables we cannot delete from (e.g., views)
                skipped.append(t)
        try:
            db.commit()
        except Exception:
            pass
        try:
            actor = session.get('username') or ''
            details = {'cleared': cleared, 'skipped': skipped}
            try:
                details['audit_ids_reset'] = bool('admin_audit' in cleared)
            except Exception:
                pass
            log_admin_action(actor, 'dbsafe_clear_all', details=details)
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500
    return redirect(f"/admin/dbsafe/table?name={name}")

@app.route('/admin/dbsafe/clear_table', methods=['POST'])
def admin_dbsafe_clear_table():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.form.get('name') or '').strip()
    if not name:
        return redirect('/admin/dbsafe')
    try:
        db = get_db(); cur = db.cursor()
        cur.execute(f'DELETE FROM {name}')
        # Reset AUTOINCREMENT sequence if present
        try:
            cur.execute('DELETE FROM sqlite_sequence WHERE name=?', (name,))
        except Exception:
            pass
        db.commit()
    except Exception:
        try: get_db().rollback()
        except Exception: pass
    try:
        actor = session.get('username') or ''
        det = {}
        try:
            det['audit_ids_reset'] = bool(name == 'admin_audit')
        except Exception:
            pass
        log_admin_action(actor, 'dbsafe_clear_table', target=name, details=det)
    except Exception:
        pass
    return redirect(f"/admin/dbsafe/table?name={name}")

@app.route('/admin/dbsafe/export')
def admin_dbsafe_export():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.args.get('name') or '').strip()
    if not name:
        return redirect('/admin/dbsafe')
    # Use a fresh connection without detect_types to avoid sqlite converters
    # raising unpack errors on non-standard timestamps
    try:
        tmp_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    except Exception:
        tmp_conn = get_db()
    try:
        tmp_conn.row_factory = None
    except Exception:
        pass
    cur = tmp_conn.cursor()
    try:
        cur.execute(f'SELECT * FROM {name}')
        rows = cur.fetchall()
        desc = cur.description or []
        headers = [d[0] for d in desc]
        index_map = {h: i for i, h in enumerate(headers)}
        import io, csv
        buf = io.StringIO()
        w = csv.writer(buf)
        if headers:
            w.writerow(headers)
        from datetime import datetime as _dt
        for r in rows:
            out = []
            for h in headers:
                try:
                    v = r[index_map[h]]
                except Exception:
                    v = None
                # serialize bytes
                try:
                    if isinstance(v, (bytes, bytearray, memoryview)):
                        v = _b64u(bytes(v))
                except Exception:
                    pass
                # serialize datetimes
                try:
                    if isinstance(v, _dt):
                        v = to_ny_time(v)
                except Exception:
                    pass
                out.append(v)
            w.writerow(out)
        data = buf.getvalue().encode('utf-8')
        from flask import make_response
        resp = make_response(data)
        resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
        resp.headers['Content-Disposition'] = f"attachment; filename={name}.csv"
        return resp
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            if tmp_conn is not get_db():
                tmp_conn.close()
        except Exception:
            pass

@app.route('/admin/dbsafe/import', methods=['POST'])
def admin_dbsafe_import():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.form.get('name') or '').strip()
    f = request.files.get('file')
    if not name or not f:
        return redirect('/admin/dbsafe')
    try:
        raw = f.read()
        import io, csv
        txt = raw.decode('utf-8-sig', errors='replace')
        reader = csv.DictReader(io.StringIO(txt))
        db = get_db(); cur = db.cursor()
        # determine table columns
        cols, pk, has_rowid = _dbx_schema(cur, name)
        table_cols = [c['name'] for c in cols]
        try:
            cur.execute('BEGIN')
        except Exception:
            pass
        count = 0
        for row in reader:
            vals = {k: v for k, v in (row or {}).items() if k in table_cols}
            if not vals:
                continue
            # normalize empties and 'NULL' to None, trim whitespace
            for k in list(vals.keys()):
                v = vals[k]
                if isinstance(v, str):
                    v2 = v.strip()
                    if v2 == '' or v2.upper() == 'NULL':
                        vals[k] = None
                    else:
                        vals[k] = v2
            # if id provided but blank/None, let sqlite autogenerate by removing it
            if 'id' in vals and (vals['id'] is None or str(vals['id']).strip() == ''):
                vals.pop('id', None)
            ks = list(vals.keys())
            vs = [vals[k] for k in ks]
            # Prefer ON CONFLICT upsert when table has a PK
            if pk:
                non_pk = [c for c in ks if c not in pk]
                if non_pk:
                    try:
                        set_sql = ', '.join([f"{c}=excluded.{c}" for c in non_pk])
                        conflict_sql = ','.join(pk)
                        cur.execute(
                            f"INSERT INTO {name} (" + ','.join(ks) + ") VALUES (" + ','.join(['?']*len(ks)) + ") "
                            f"ON CONFLICT(" + conflict_sql + ") DO UPDATE SET " + set_sql,
                            vs
                        )
                    except Exception:
                        # Fallback to REPLACE if SQLite is older
                        cur.execute(
                            f"INSERT OR REPLACE INTO {name} (" + ','.join(ks) + ") VALUES (" + ','.join(['?']*len(ks)) + ")",
                            vs
                        )
                else:
                    # Only PK columns present -> ensure row exists or noop
                    try:
                        placeholders = ','.join(['?']*len(ks))
                        cur.execute(f"INSERT OR IGNORE INTO {name} (" + ','.join(ks) + ") VALUES (" + placeholders + ")", vs)
                    except Exception:
                        pass
            else:
                cur.execute(
                    f"INSERT OR REPLACE INTO {name} (" + ','.join(ks) + ") VALUES (" + ','.join(['?']*len(ks)) + ")",
                    vs
                )
            count += 1
        db.commit()
        return redirect(f"/admin/dbsafe/table?name={name}")
    except Exception as e:
        try: get_db().rollback()
        except Exception: pass
        return jsonify({'error': str(e)}), 500

@app.route('/api/dbx/unlock', methods=['POST'])
def api_dbx_unlock():
    try:
        data = request.get_json(silent=True) or {}
        code = (data.get('code') or '').strip()
        if not code:
            return jsonify({'error':'missing'}), 400
        cur_code = _get_dbx_code()
        if cur_code and code and secrets.compare_digest(cur_code.upper(), code.upper()):
            from flask import make_response
            resp = make_response(jsonify({'ok': True}))
            resp.set_cookie('dbxok', _make_dbxok_cookie(), max_age=3600, secure=True, httponly=True, samesite='Lax', path='/')
            return resp
        return jsonify({'error':'invalid'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dbx/app')
def admin_db_new_ui():
    if not _dbx_ok():
        return redirect('/dbx')
    return redirect('/admin/dbsafe')

@app.route('/api/dbx/code')
def api_dbx_code():
    u = session.get('username')
    if not is_superadmin(u):
        return jsonify({'error': 'forbidden'}), 403
    return jsonify({'code': _get_dbx_code()})

def init_db():
    db = get_db()
    cur = db.cursor()
    # Users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT,
            theme TEXT DEFAULT 'light',
            bio TEXT,
            status TEXT,
            language TEXT DEFAULT 'en',
            allow_dm_nonfriends INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # Messages table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            text TEXT,
            attachment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    # Banned users table
    cur.execute("CREATE TABLE IF NOT EXISTS banned_users (username TEXT PRIMARY KEY)")
    cur.execute("CREATE TABLE IF NOT EXISTS banned_ips (ip_address TEXT PRIMARY KEY)")
    # Direct messages table (1:1)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS direct_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            text TEXT,
            attachment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # Group DMs (threads)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS group_threads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS group_members (
            thread_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (thread_id, username)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            text TEXT,
            attachment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited INTEGER DEFAULT 0
        )
        """
    )
    # Optional reply_to columns (id of the message being replied to)
    try:
        cur.execute("ALTER TABLE messages ADD COLUMN reply_to INTEGER")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE direct_messages ADD COLUMN reply_to INTEGER")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE group_messages ADD COLUMN reply_to INTEGER")
    except Exception:
        pass
    db.commit()
    # Admin audit log (actor, action, optional target, optional details JSON)
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.commit()
    except Exception:
        pass
    # Attempt to add optional columns for profiles (ignore if already exist)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN avatar TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN theme TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN bio TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN status TEXT")  # 'online' | 'idle' | 'dnd'
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en'")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN allow_dm_nonfriends INTEGER")
    except Exception:
        pass
    # friends feature removed: friendships table no longer created
    try:
        cur.execute("CREATE TABLE IF NOT EXISTS group_invites (token TEXT PRIMARY KEY, thread_id INTEGER NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL)")
    except Exception:
        pass
    try:
        cur.execute("CREATE TABLE IF NOT EXISTS group_bans (thread_id INTEGER NOT NULL, username TEXT NOT NULL, PRIMARY KEY(thread_id, username))")
    except Exception:
        pass
    try:
        cur.execute("CREATE TABLE IF NOT EXISTS group_timeouts (thread_id INTEGER NOT NULL, username TEXT NOT NULL, until_ts INTEGER NOT NULL, PRIMARY KEY(thread_id, username))")
    except Exception:
        pass
    # Device logs (username, client_id, public_ip, private_ips JSON, mdns JSON, remote_port, user_agent, created_at)
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                client_id TEXT NOT NULL,
                public_ip TEXT,
                private_ips TEXT,
                mdns TEXT,
                remote_port TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    except Exception:
        pass
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_bans (
                client_id TEXT PRIMARY KEY,
                username TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    except Exception:
        pass
    # Optional columns for IP/immunity; ignore if present
    try:
        cur.execute("ALTER TABLE users ADD COLUMN private_ip TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN public_ip TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN immune INTEGER DEFAULT 0")
    except Exception:
        pass
    # Username change history for rollback on crash/timeout
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS username_change_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                old_username TEXT NOT NULL,
                new_username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                rolled_back INTEGER DEFAULT 0
            )
            """
        )
        db.commit()
    except Exception:
        pass
    db.commit()

def recover_failed_username_changes():
    """Recover from failed username changes by rolling back to old username if new username is invalid"""
    try:
        db = get_db(); cur = db.cursor()
        # Find recent username changes that haven't been rolled back and check if they're valid
        cur.execute('''
            SELECT id, user_id, old_username, new_username 
            FROM username_change_history 
            WHERE rolled_back = 0 
            AND created_at > datetime('now', '-1 hour')
            ORDER BY id DESC
        ''')
        rows = cur.fetchall()
        for row in rows:
            hist_id = row[0] if not isinstance(row, sqlite3.Row) else row['id']
            user_id = row[1] if not isinstance(row, sqlite3.Row) else row['user_id']
            old_username = row[2] if not isinstance(row, sqlite3.Row) else row['old_username']
            new_username = row[3] if not isinstance(row, sqlite3.Row) else row['new_username']
            
            # Check if new username is too long or invalid
            if len(new_username) > 20:
                # Rollback to old username
                try:
                    cur.execute('UPDATE users SET username=? WHERE id=?', (old_username, user_id))
                    cur.execute('UPDATE messages SET username=? WHERE username=?', (old_username, new_username))
                    cur.execute('UPDATE direct_messages SET from_user=? WHERE from_user=?', (old_username, new_username))
                    cur.execute('UPDATE direct_messages SET to_user=? WHERE to_user=?', (old_username, new_username))
                    cur.execute('UPDATE group_members SET username=? WHERE username=?', (old_username, new_username))
                    cur.execute('UPDATE group_threads SET created_by=? WHERE created_by=?', (old_username, new_username))
                    cur.execute('UPDATE username_change_history SET rolled_back=1 WHERE id=?', (hist_id,))
                    db.commit()
                except Exception:
                    try:
                        db.rollback()
                    except Exception:
                        pass
    except Exception:
        pass

def log_admin_action(actor, action, target='', details=None):
    try:
        db = get_db(); cur = db.cursor()
        payload = None
        if details is not None:
            try:
                payload = json.dumps(details, ensure_ascii=False)
            except Exception:
                try:
                    payload = str(details)
                except Exception:
                    payload = None
        cur.execute('INSERT INTO admin_audit(actor, action, target, details) VALUES(?,?,?,?)', (actor or '', action or '', target or '', payload))
        db.commit()
    except Exception:
        pass

# Authentication helpers
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def is_admin(username=None):
    if username is None:
        username = session.get("username")
    return username in ADMINS

def is_ip_banned(ip_address):
    # Never ban loopback to avoid locking out all local users/admin
    if ip_address in ("127.0.0.1", "::1"):
        return False
    if ip_address in banned_ips:
        return True

"""Overseer for superadmin IP bans is stored in DB by user_id so renames do not break it."""
IPBAN_OVERSEER_USER_ID = None  # cached in-memory

def _ensure_settings_table(cur):
    try:
        cur.execute('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)')
    except Exception:
        pass

def _get_overseer_user_id():
    global IPBAN_OVERSEER_USER_ID
    if IPBAN_OVERSEER_USER_ID is not None:
        return IPBAN_OVERSEER_USER_ID
    try:
        db = get_db(); cur = db.cursor()
        _ensure_settings_table(cur)
        cur.execute('SELECT value FROM app_settings WHERE key=?', ('ipban_overseer_user_id',))
        row = cur.fetchone()
        if row and row[0]:
            try:
                IPBAN_OVERSEER_USER_ID = int(row[0])
            except Exception:
                IPBAN_OVERSEER_USER_ID = None
        return IPBAN_OVERSEER_USER_ID
    except Exception:
        return None

def _set_overseer_by_username(username: str) -> bool:
    global IPBAN_OVERSEER_USER_ID
    if not username:
        return False
    try:
        db = get_db(); cur = db.cursor()
        _ensure_settings_table(cur)
        cur.execute('SELECT id FROM users WHERE username=?', (username,))
        r = cur.fetchone()
        if not r:
            return False
        uid = int(r[0])
        cur.execute('INSERT INTO app_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                    ('ipban_overseer_user_id', str(uid)))
        db.commit()
        IPBAN_OVERSEER_USER_ID = uid
        return True
    except Exception:
        return False

def _issuer_user_id(issuer: str):
    if not issuer:
        return None
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT id FROM users WHERE username=?', (issuer,))
        r = cur.fetchone()
        return int(r[0]) if r else None
    except Exception:
        return None

def _can_ipban_superadmin_ips(issuer: str) -> bool:
    overseer_id = _get_overseer_user_id()
    if overseer_id is None:
        return False
    return _issuer_user_id(issuer) == overseer_id

def _can_unban(issuer: str, target: str) -> bool:
    # Mirror ban rules
    if not issuer or not target:
        return False
    if issuer not in ADMINS and issuer not in SUPERADMINS:
        return False
    if target in SUPERADMINS:
        return False
    if issuer in ADMINS and target in ADMINS:
        return False
    return True

def is_superadmin(username=None):
    if username is None:
        username = session.get("username")
    return username in SUPERADMINS

def _can_ban(issuer: str, target: str) -> bool:
    if not issuer or not target:
        return False
    if issuer not in ADMINS and issuer not in SUPERADMINS:
        return False
    if target in SUPERADMINS:
        return False
    # Admins cannot ban other admins
    if issuer in ADMINS and target in ADMINS:
        return False
    return True

def is_banned(username):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT 1 FROM banned_users WHERE username=?", (username,))
    return cur.fetchone() is not None

def load_banned_ips():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ip_address FROM banned_ips")
    dirty = False
    for row in cur.fetchall():
        ip = row[0]
        if ip in ("127.0.0.1", "::1"):
            # Clean up accidental loopback bans
            cur.execute("DELETE FROM banned_ips WHERE ip_address=?", (ip,))
            dirty = True
            continue
        banned_ips.add(ip)
    if dirty:
        try:
            db.commit()
        except Exception:
            pass

def _is_private_ip(ip: str) -> bool:
    try:
        if not ip:
            return False
        ip = ip.strip()
        if ip.startswith('127.') or ip == '::1':
            return True
        if ip.startswith('10.'):
            return True
        if ip.startswith('192.168.'):
            return True
        if ip.startswith('172.'):
            try:
                second = int(ip.split('.')[1])
                return 16 <= second <= 31
            except Exception:
                return False
        # IPv6 ULA fc00::/7
        if ':' in ip:
            try:
                h = ip.lower()
                return h.startswith('fc') or h.startswith('fd') or h == '::1'
            except Exception:
                return False
        return False
    except Exception:
        return False

def _is_loopback_ip(ip: str) -> bool:
    try:
        if not ip:
            return False
        ip = ip.strip()
        return ip.startswith('127.') or ip == '::1'
    except Exception:
        return False

def _first_rfc1918(ips) -> str:
    try:
        for p in ips or []:
            if isinstance(p, str) and p.strip() and _is_private_ip(p) and not _is_loopback_ip(p):
                return p.strip()
    except Exception:
        pass
    return None

def get_client_ip():
    try:
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            parts = [p.strip() for p in xff.split(',') if p.strip()]
            # Prefer private/local IPs if present (first match)
            for p in parts:
                if _is_private_ip(p):
                    return p
            # Otherwise take first valid public IP
            for p in parts:
                if not _is_private_ip(p):
                    return p
            # Fallback to last entry
            if parts:
                return parts[-1]
        xri = request.headers.get('X-Real-IP')
        if xri:
            return xri
        return request.remote_addr
    except Exception:
        return request.remote_addr

def detect_client_ips():
    """Return (private_ip_or_None, public_ip_or_None) from headers safely."""
    try:
        private_ip = None
        public_ip = None
        loopback_ip = None
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            parts = [p.strip() for p in xff.split(',') if p.strip()]
            for p in parts:
                if _is_private_ip(p):
                    if p in ("127.0.0.1", "::1"):
                        loopback_ip = loopback_ip or p
                    else:
                        private_ip = private_ip or p
                else:
                    public_ip = public_ip or p
        xri = (request.headers.get('X-Real-IP') or '').strip()
        if xri:
            if _is_private_ip(xri):
                if xri in ("127.0.0.1", "::1"):
                    loopback_ip = loopback_ip or xri
                else:
                    private_ip = private_ip or xri
            else:
                public_ip = public_ip or xri
        ra = (request.remote_addr or '').strip()
        if ra:
            if _is_private_ip(ra):
                if ra in ("127.0.0.1", "::1"):
                    loopback_ip = loopback_ip or ra
                else:
                    private_ip = private_ip or ra
            else:
                public_ip = public_ip or ra
        # Only use loopback as private if no better private was found and there is no public
        if not private_ip and not public_ip and loopback_ip:
            private_ip = loopback_ip
        return (private_ip, public_ip)
    except Exception:
        return (None, request.remote_addr)

def _user_immune(username: str) -> bool:
    try:
        if username in SUPERADMINS:
            return True
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT COALESCE(immune,0) FROM users WHERE username=?', (username,))
        r = cur.fetchone()
        return bool((r[0] if r and not isinstance(r, sqlite3.Row) else (r['COALESCE(immune,0)'] if r else 0)))
    except Exception:
        return False

def _update_user_ips(username: str, private_ip: str, public_ip: str):
    try:
        db = get_db(); cur = db.cursor()
        try:
            cur.execute('UPDATE users SET private_ip=?, public_ip=?, immune=CASE WHEN ? IN (SELECT username FROM users WHERE username IN (%s)) THEN 1 ELSE COALESCE(immune,0) END WHERE username=?' % (','.join('?'*len(SUPERADMINS)) if SUPERADMINS else "''"),
                        (private_ip, public_ip, username, *list(SUPERADMINS), username))
        except Exception:
            # Fallback: set columns if exist
            try:
                cur.execute('UPDATE users SET private_ip=?, public_ip=? WHERE username=?', (private_ip, public_ip, username))
            except Exception:
                pass
        db.commit()
    except Exception:
        pass
    try:
        user_ips[username] = { 'private': private_ip, 'public': public_ip, 'immune': _user_immune(username) }
    except Exception:
        user_ips[username] = { 'private': private_ip, 'public': public_ip, 'immune': False }

def _is_ip_blocked_for(username: str, private_ip: str, public_ip: str) -> bool:
    try:
        if username in SUPERADMINS:
            # Superadmins bypass IP bans silently to avoid log spam
            return False
        if _user_immune(username):
            return False
        # Prefer private IP ban
        if private_ip and is_ip_banned(private_ip):
            return True
        # Fallback to public IP ban
        if public_ip and is_ip_banned(public_ip):
            return True
        return False
    except Exception:
        return False

# File handling helpers
def safe_save_file(file):
    prefix = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    filename = secure_filename(file.filename)
    saved = f"{prefix}_{filename}"
    file.save(os.path.join(UPLOAD_FOLDER, saved))
    return saved

def user_exists(username: str) -> bool:
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM users WHERE username=?', (username,))
        return cur.fetchone() is not None
    except Exception:
        return False

@app.route('/api/admin/delete_user', methods=['POST'])
def api_admin_delete_user():
    me = session.get('username')
    if not me or not is_superadmin(me):
        return jsonify({'error': 'Forbidden'}), 403
    try:
        data = request.get_json(silent=True) or {}
        target = (data.get('username') or '').strip()
        if not target:
            return jsonify({'error': 'Username required'}), 400
        if target in SUPERADMINS:
            try:
                log_admin_action(me, 'delete_user_blocked', target=target)
            except Exception:
                pass
            return jsonify({'error': 'Cannot delete another superadmin'}), 400
        db = get_db(); cur = db.cursor()
        # Find user id
        cur.execute('SELECT id FROM users WHERE username=?', (target,))
        row = cur.fetchone()
        if not row:
            return jsonify({'ok': True, 'note': 'User not found (already deleted)'}), 200
        uid = row['id']
        # Remove memberships
        try:
            cur.execute('DELETE FROM group_members WHERE username=?', (target,))
        except Exception:
            pass
        # Remove DMs involving user
        try:
            cur.execute('DELETE FROM direct_messages WHERE from_user=? OR to_user=?', (target, target))
        except Exception:
            pass
        # Remove messages by user (public and group)
        try:
            cur.execute('DELETE FROM messages WHERE user_id=?', (uid,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM group_messages WHERE username=?', (target,))
        except Exception:
            pass
        # Finally delete user
        cur.execute('DELETE FROM users WHERE id=?', (uid,))
        db.commit()
        # Disconnect live sockets
        for sid, uname in list(connected_sockets.items()):
            if uname == target:
                try:
                    socketio.server.disconnect(sid)
                except Exception:
                    pass
                try:
                    del connected_sockets[sid]
                except Exception:
                    pass
        try:
            online_users.pop(target, None)
            user_ips.pop(target, None)
        except Exception:
            pass
        # Broadcast updates
        try:
            socketio.emit('user_list_refresh', {'deleted': target})
            socketio.emit('system_message', store_system_message(f"{target} was deleted by {me}"))
        except Exception:
            pass
        try:
            log_admin_action(me, 'delete_user', target=target)
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/gdm/transfer', methods=['POST'])
@login_required
def api_gdm_transfer():
    me = session.get('username')
    # Toggle gate
    try:
        if get_setting('GD_TRANSFER_OWNERSHIP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    new_owner = sanitize_username((data.get('new_owner') or '').strip())
    if not tid or not new_owner:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    owner = row[0] if not isinstance(row, sqlite3.Row) else row['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Ensure new owner exists
    cur.execute('SELECT 1 FROM users WHERE username=? LIMIT 1', (new_owner,))
    if not cur.fetchone():
        return jsonify({'error':'user not found'}), 404
    # Make sure new owner is a member
    try:
        cur.execute('INSERT OR IGNORE INTO group_members(thread_id, username) VALUES (?,?)', (tid, new_owner))
    except Exception:
        pass
    cur.execute('UPDATE group_threads SET created_by=? WHERE id=?', (new_owner, tid))
    db.commit()
    # notify all members to refresh
    try:
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        members = [r[0] for r in cur.fetchall()]
        for u in members:
            socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/account/delete', methods=['POST'])
@login_required
def api_account_delete():
    me = session.get('username')
    uid = session.get('user_id')
    if not me or not uid:
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()
    if not password:
        return jsonify({'error': 'password required'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT id, password_hash FROM users WHERE id=?', (uid,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'not found'}), 404
        if not check_password_hash(row['password_hash'], password):
            return jsonify({'error': 'invalid password'}), 400
        # Remove memberships and content authored by this user
        try:
            cur.execute('DELETE FROM group_members WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM direct_messages WHERE from_user=? OR to_user=?', (me, me))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM messages WHERE user_id=?', (uid,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM group_messages WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM device_logs WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM device_bans WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM banned_users WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM users WHERE id=?', (uid,))
        except Exception:
            pass
        try:
            db.commit()
        except Exception:
            pass
        # Disconnect sockets
        try:
            for sid, uname in list(connected_sockets.items()):
                if uname == me:
                    try: socketio.server.disconnect(sid)
                    except Exception: pass
        except Exception:
            pass
        # Clear session last
        try:
            session.clear()
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# True Ban: ban user + device + IPs in one action
@app.route('/api/admin/true_ban', methods=['POST'])
@login_required
def api_admin_true_ban():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    client_id = (data.get('client_id') or '').strip()
    if not user:
        return jsonify({'error': 'bad params'}), 400
    if not _can_ban(me, user):
        return jsonify({'error':'not allowed'}), 403
    db = get_db(); cur = db.cursor()
    # Ban user
    try:
        cur.execute('INSERT OR IGNORE INTO banned_users(username) VALUES(?)', (user,))
    except Exception:
        pass
    # Resolve client id if missing
    if not client_id:
        try:
            cur.execute('SELECT client_id FROM device_logs WHERE username=? AND client_id IS NOT NULL ORDER BY created_at DESC LIMIT 1', (user,))
            r = cur.fetchone()
            if r:
                client_id = r[0] if not isinstance(r, sqlite3.Row) else r['client_id']
        except Exception:
            client_id = ''
    # Ban device
    try:
        if client_id:
            cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (client_id, user))
    except Exception:
        pass
    # Ban IPs (private+public best-effort)
    ips_to_ban = set()
    try:
        cur.execute('SELECT private_ip, public_ip FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (user,))
        r = cur.fetchone()
        if r:
            priv = r[0] if not isinstance(r, sqlite3.Row) else r['private_ip']
            pub = r[1] if not isinstance(r, sqlite3.Row) else r['public_ip']
            if priv: ips_to_ban.add(priv)
            if pub and not _is_loopback_ip(pub): ips_to_ban.add(pub)
    except Exception:
        pass
    try:
        info = user_ips.get(user) if isinstance(user_ips.get(user), dict) else {}
        if info.get('private'): ips_to_ban.add(info.get('private'))
        if info.get('public') and not _is_loopback_ip(info.get('public')): ips_to_ban.add(info.get('public'))
    except Exception:
        pass
    for ip in ips_to_ban:
        try:
            cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (ip,))
        except Exception:
            pass
    try: db.commit()
    except Exception: pass
    # Disconnect active sockets of the user
    for sid, uname in list(connected_sockets.items()):
        if uname == user:
            try: socketio.server.disconnect(sid)
            except Exception: pass
    return jsonify({'ok': True, 'banned_ips': list(ips_to_ban), 'client_id': client_id})

# True Unban: remove user ban + device ban(s) + relevant IPs
@app.route('/api/admin/true_unban', methods=['POST'])
@login_required
def api_admin_true_unban():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    client_id = (data.get('client_id') or '').strip()
    if not user:
        return jsonify({'error': 'bad params'}), 400
    if not _can_unban(me, user):
        return jsonify({'error':'not allowed'}), 403
    db = get_db(); cur = db.cursor()
    # Remove user ban
    try:
        cur.execute('DELETE FROM banned_users WHERE username=?', (user,))
    except Exception:
        pass
    # Determine client ids to clear
    cids = set()
    if client_id: cids.add(client_id)
    try:
        cur.execute('SELECT DISTINCT client_id FROM device_logs WHERE username=? AND client_id IS NOT NULL ORDER BY created_at DESC LIMIT 3', (user,))
        for r in cur.fetchall():
            cids.add(r[0] if not isinstance(r, sqlite3.Row) else r['client_id'])
    except Exception:
        pass
    for cid in cids:
        try:
            cur.execute('DELETE FROM device_bans WHERE client_id=?', (cid,))
        except Exception:
            pass
    # Remove IP bans best-effort (latest known + in-memory)
    ips_to_unban = set()
    try:
        cur.execute('SELECT private_ip, public_ip FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 3', (user,))
        for r in cur.fetchall():
            priv = r[0] if not isinstance(r, sqlite3.Row) else r['private_ip']
            pub = r[1] if not isinstance(r, sqlite3.Row) else r['public_ip']
            if priv: ips_to_unban.add(priv)
            if pub: ips_to_unban.add(pub)
    except Exception:
        pass
    try:
        info = user_ips.get(user) if isinstance(user_ips.get(user), dict) else {}
        if info.get('private'): ips_to_unban.add(info.get('private'))
        if info.get('public'): ips_to_unban.add(info.get('public'))
    except Exception:
        pass
    for ip in ips_to_unban:
        try:
            cur.execute('DELETE FROM banned_ips WHERE ip_address=?', (ip,))
        except Exception:
            pass
    try: db.commit()
    except Exception: pass
    return jsonify({'ok': True, 'unbanned_ips': list(ips_to_unban), 'cleared_client_ids': list(cids)})

# Device logging endpoint (expects JSON with client_id, private_ips, mdns)
@app.route('/api/device_log', methods=['POST'])
@login_required
def api_device_log():
    try:
        u = session.get('username') or ''
        if not u:
            return jsonify({'error': 'forbidden'}), 403
        data = request.get_json(silent=True) or {}
        client_id = (data.get('client_id') or '').strip()
        private_ips = data.get('private_ips') or []
        mdns = data.get('mdns') or []
        if not isinstance(private_ips, list):
            private_ips = []
        if not isinstance(mdns, list):
            mdns = []
        # Try to record the real public IP, not loopback
        try:
            _priv, _pub = detect_client_ips()
        except Exception:
            _priv, _pub = (None, None)
        pub_ip = _pub if (_pub and not _is_loopback_ip(_pub)) else (request.headers.get('CF-Connecting-IP') or request.headers.get('X-Real-IP') or request.remote_addr)
        if _is_loopback_ip(pub_ip or ''):
            pub_ip = ''
        rport = str(request.environ.get('REMOTE_PORT') or '')
        ua = request.headers.get('User-Agent') or ''
        try:
            db = get_db(); cur = db.cursor()
            cur.execute(
                'INSERT INTO device_logs(username, client_id, public_ip, private_ips, mdns, remote_port, user_agent) VALUES(?,?,?,?,?,?,?)',
                (u, client_id, pub_ip, json.dumps(private_ips), json.dumps(mdns), rport, ua)
            )
            db.commit()
        except Exception:
            pass
        # If user is banned, also ban this device id to follow the account (toggleable)
        try:
            if u and is_banned(u):
                db = get_db(); cur = db.cursor()
                if client_id and get_setting('SEC_DEVICE_BAN_ON_LOGIN','1')=='1':
                    cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (client_id, u))
                # Strict associated ban: also ban public IP if toggle enabled
                try:
                    if (_pub and not _is_loopback_ip(_pub)) and get_setting('SEC_STRICT_ASSOCIATED_BAN','0')=='1':
                        cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (_pub,))
                except Exception:
                    pass
                db.commit()
        except Exception:
            pass
        # Update in-memory private/public for admin dashboard
        try:
            info = user_ips.get(u) if isinstance(user_ips.get(u), dict) else {}
            first_private = next((p for p in private_ips if isinstance(p, str) and p), None)
            merged = {
                'private': first_private or info.get('private'),
                'public': (info.get('public') or pub_ip),
                'immune': info.get('immune', _user_immune(u)),
                'client_id': client_id or info.get('client_id')
            }
            user_ips[u] = merged
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Simple logs view for current user
@app.route('/logs')
@login_required
def view_logs():
    try:
        u = session.get('username')
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT id, client_id, public_ip, private_ips, mdns, remote_port, user_agent, created_at FROM device_logs WHERE username=? ORDER BY created_at DESC', (u,))
        rows = cur.fetchall() or []
        out = [
            '<html><body><h3>Your Devices</h3><table border="1" cellspacing="0" cellpadding="4">',
            '<tr><th>When</th><th>Client ID</th><th>Public IP</th><th>Private IPs</th><th>mDNS</th><th>Remote Port</th><th>User Agent</th></tr>'
        ]
        for r in rows:
            when = r['created_at'] if isinstance(r, sqlite3.Row) else r[7]
            cid = r['client_id'] if isinstance(r, sqlite3.Row) else r[1]
            pip = r['public_ip'] if isinstance(r, sqlite3.Row) else r[2]
            priv = r['private_ips'] if isinstance(r, sqlite3.Row) else r[3]
            md = r['mdns'] if isinstance(r, sqlite3.Row) else r[4]
            rp = r['remote_port'] if isinstance(r, sqlite3.Row) else r[5]
            agent = r['user_agent'] if isinstance(r, sqlite3.Row) else r[6]
            out.append(f'<tr><td>{when}</td><td>{cid}</td><td>{pip or ""}</td><td>{priv or ""}</td><td>{md or ""}</td><td>{rp or ""}</td><td>{(agent or "")[:160]}</td></tr>')
        out.append('</table></body></html>')
        return '\n'.join(out)
    except Exception as e:
        return f'Error: {e}', 500

# Online users + IPs for dashboard
@app.route('/api/admin/online')
@login_required
def api_admin_online():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    items = []
    try:
        for u in sorted(list(online_users.keys()), key=lambda s: s.lower()):
            info = user_ips.get(u) or {}
            if isinstance(info, dict):
                priv_raw = info.get('private') or ''
                priv_ok = priv_raw if (priv_raw and _is_private_ip(priv_raw) and not _is_loopback_ip(priv_raw)) else ''
                pub_raw = info.get('public') or ''
                # Ensure client_id present; fallback to latest device_logs
                cid = info.get('client_id') or ''
                if not cid:
                    try:
                        db = get_db(); cur = db.cursor()
                        cur.execute('SELECT client_id FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (u,))
                        row = cur.fetchone()
                        if row:
                            cid = row[0] if not isinstance(row, sqlite3.Row) else row['client_id']
                    except Exception:
                        cid = ''
                # Flags: device banned? ip banned?
                dev_banned = False; priv_banned = False; pub_banned = False
                try:
                    db = get_db(); cur = db.cursor()
                    if cid:
                        cur.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid,))
                        dev_banned = cur.fetchone() is not None
                    if priv_ok:
                        cur.execute('SELECT 1 FROM banned_ips WHERE ip_address=? LIMIT 1', (priv_ok,))
                        priv_banned = cur.fetchone() is not None
                    if pub_raw:
                        cur.execute('SELECT 1 FROM banned_ips WHERE ip_address=? LIMIT 1', (pub_raw,))
                        pub_banned = cur.fetchone() is not None
                except Exception:
                    pass
                ip_show = priv_ok or pub_raw or ''
                items.append({'username': u, 'private': priv_ok, 'public': pub_raw, 'immune': bool(info.get('immune', False)), 'ip': ip_show, 'client_id': cid, 'device_banned': dev_banned, 'private_banned': priv_banned, 'public_banned': pub_banned})
            else:
                items.append({'username': u, 'private': '', 'public': str(info), 'immune': False, 'ip': str(info), 'client_id': '', 'device_banned': False, 'private_banned': False, 'public_banned': False})
    except Exception:
        pass
    return jsonify({'online': items})

# Toggle immunity (superadmin only)
@app.route('/api/admin/toggle_immunity/<username>', methods=['POST'])
@login_required
def api_admin_toggle_immunity(username):
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    if not username or username in SUPERADMINS:
        # Superadmins are implicitly immune
        return jsonify({'error': 'cannot_toggle_superadmin'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('UPDATE users SET immune = CASE COALESCE(immune,0) WHEN 1 THEN 0 ELSE 1 END WHERE username=?', (username,))
        db.commit()
        cur.execute('SELECT COALESCE(immune,0) FROM users WHERE username=?', (username,))
        row = cur.fetchone(); immune = bool(row[0]) if row else False
        _append_log_line(f"[SECURITY] Superadmin {me} toggled immunity for {username} -> {immune}")
        # refresh cache
        try:
            d = user_ips.get(username) or {}
            user_ips[username] = { 'private': d.get('private'), 'public': d.get('public'), 'immune': immune }
        except Exception:
            pass
        return jsonify({'ok': True, 'immune': immune})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# One-time superadmin recovery via token
@app.route('/admin/recover', methods=['GET','POST'])
def admin_recover():
    if request.method == 'GET':
        return """
        <html><body>
        <h3>Superadmin Recovery</h3>
        <form method='POST'>
          <label>Username (superadmin): <input name='username'></label><br/>
          <label>Token: <input name='token' type='password'></label><br/>
          <button type='submit'>Recover</button>
        </form>
        </body></html>
        """
    import werkzeug.security as wz
    uname = (request.form.get('username') or '').strip()
    token = (request.form.get('token') or '').strip()
    if not uname or uname not in SUPERADMINS or not token:
        return "Invalid", 400
    try:
        db = get_db(); cur = db.cursor(); _ensure_settings_table(cur)
        key = f'recover_{uname}'
        cur.execute('SELECT value FROM app_settings WHERE key=?', (key,))
        row = cur.fetchone(); h = (row[0] if row else '')
        if not h or not wz.check_password_hash(h, token):
            return "Invalid token", 400
        # Invalidate immediately and issue session
        cur.execute('DELETE FROM app_settings WHERE key=?', (key,)); db.commit()
        cur.execute('SELECT id FROM users WHERE username=?', (uname,)); r2 = cur.fetchone()
        if not r2:
            return "User not found", 404
        session.clear(); session['user_id'] = int(r2[0]); session['username'] = uname
        _append_log_line(f"[SECURITY] Superadmin {uname} recovered access via recovery token")
        return redirect(url_for('chat'))
    except Exception as e:
        return (f"Error: {e}", 500)

# Set a one-time recovery token (superadmin only). Body: { username, token }
@app.route('/api/admin/set_recovery_token', methods=['POST'])
@login_required
def api_admin_set_recovery_token():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    uname = (data.get('username') or '').strip()
    token = (data.get('token') or '').strip()
    if not uname or uname not in SUPERADMINS or not token:
        return jsonify({'error':'invalid'}), 400
    try:
        import werkzeug.security as wz
        db = get_db(); cur = db.cursor(); _ensure_settings_table(cur)
        key = f'recover_{uname}'
        cur.execute('INSERT OR REPLACE INTO app_settings(key,value) VALUES(?,?)', (key, wz.generate_password_hash(token)))
        db.commit()
        _append_log_line(f"[SECURITY] Superadmin {me} set recovery token for {uname}")
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Cleanup ghost sockets/users (superadmin only)
@app.route('/api/admin/cleanup_sockets', methods=['POST'])
@login_required
def api_admin_cleanup_sockets():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    disconnected = 0
    pruned_users = 0
    try:
        db = get_db(); cur = db.cursor()
        # Disconnect sockets whose session user no longer exists
        for sid, uname in list(connected_sockets.items()):
            try:
                cur.execute('SELECT 1 FROM users WHERE username=?', (uname,))
                ok = cur.fetchone() is not None
            except Exception:
                ok = True
            if not ok:
                try:
                    socketio.server.disconnect(sid)
                except Exception:
                    pass
                try:
                    del connected_sockets[sid]
                except Exception:
                    pass
                disconnected += 1
        # Prune online_users entries whose user no longer exists
        for uname in list(online_users.keys()):
            try:
                cur.execute('SELECT 1 FROM users WHERE username=?', (uname,))
                ok = cur.fetchone() is not None
            except Exception:
                ok = True
            if not ok and uname not in connected_sockets.values():
                try:
                    online_users.pop(uname, None)
                except Exception:
                    pass
                pruned_users += 1
        try:
            socketio.emit('user_list_refresh', { 'cleanup': True })
        except Exception:
            pass
    except Exception as e:
        return jsonify({'error': str(e), 'disconnected': disconnected, 'pruned': pruned_users}), 500
    return jsonify({'ok': True, 'disconnected': disconnected, 'pruned': pruned_users})

# Ban/unban a specific device by client_id (admin or superadmin)
@app.route('/api/admin/ban_device', methods=['POST'])
@login_required
def api_admin_ban_device():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    action = (data.get('action') or 'ban').lower()
    client_id = (data.get('client_id') or '').strip()
    username = (data.get('username') or '').strip()
    if not client_id:
        # Allow username-only: resolve latest client_id from device_logs
        if not username:
            return jsonify({'error': 'client_id_or_username_required'}), 400
        try:
            db = get_db(); cur = db.cursor()
            cur.execute('SELECT client_id FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (username,))
            r = cur.fetchone()
            if r:
                client_id = r[0] if not isinstance(r, sqlite3.Row) else r['client_id']
        except Exception:
            client_id = ''
        if not client_id:
            return jsonify({'error': 'no_client_id_for_user'}), 404
    # Guardrails: superadmins are device-unbannable; admins cannot ban themselves; superadmins may ban admins
    if username:
        if username in SUPERADMINS:
            return jsonify({'error': 'cannot_device_ban_superadmin'}), 403
        if (not is_superadmin(me)) and username == me:
            return jsonify({'error': 'cannot_self_ban'}), 403
    try:
        db = get_db(); cur = db.cursor()
        if action == 'unban':
            # Remove device ban
            cur.execute('DELETE FROM device_bans WHERE client_id=?', (client_id,))
            # Resolve username if not provided
            u_for_unban = username
            if not u_for_unban:
                try:
                    cur.execute('SELECT username FROM device_bans WHERE client_id=? ORDER BY created_at DESC LIMIT 1', (client_id,))
                    r = cur.fetchone()
                    if r:
                        u_for_unban = r[0] if not isinstance(r, sqlite3.Row) else r['username']
                except Exception:
                    u_for_unban = ''
                if not u_for_unban:
                    try:
                        cur.execute('SELECT username FROM device_logs WHERE client_id=? ORDER BY created_at DESC LIMIT 1', (client_id,))
                        r = cur.fetchone()
                        if r:
                            u_for_unban = r[0] if not isinstance(r, sqlite3.Row) else r['username']
                    except Exception:
                        u_for_unban = ''
            # Also fully unban: remove user ban and their IP bans if we can resolve
            if u_for_unban:
                try:
                    cur.execute('DELETE FROM banned_users WHERE username=?', (u_for_unban,))
                except Exception:
                    pass
            # Whitelist this CID prefix to avoid similar-CID registration blocks
            try:
                if client_id:
                    cur.execute('CREATE TABLE IF NOT EXISTS user_device_whitelist (cid_prefix TEXT PRIMARY KEY, username TEXT, created_at TIMESTAMP)')
                    pref = client_id[:8]
                    cur.execute('INSERT OR IGNORE INTO user_device_whitelist(cid_prefix, username, created_at) VALUES(?,?,?)', (pref, u_for_unban or '', datetime.utcnow()))
            except Exception:
                pass
                try:
                    # Look up latest private/public IP for this user
                    cur.execute('SELECT private_ip, public_ip FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (u_for_unban,))
                except Exception:
                    pass
                try:
                    r = cur.fetchone()
                    if r:
                        priv = r[0] if not isinstance(r, sqlite3.Row) else r['private_ip']
                        pub = r[1] if not isinstance(r, sqlite3.Row) else r['public_ip']
                        for ip in (priv, pub):
                            if ip:
                                try:
                                    cur.execute('DELETE FROM banned_ips WHERE ip_address=?', (ip,))
                                except Exception:
                                    pass
                except Exception:
                    pass
        else:
            cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (client_id, username or None))
            # Also ban the user account if provided
            if username:
                cur.execute('INSERT OR IGNORE INTO banned_users(username) VALUES(?)', (username,))
        db.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin Messaging Tools
@app.route('/api/admin/broadcast', methods=['POST'])
@login_required
def api_admin_broadcast():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('MC_BROADCAST_MESSAGE','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    scope = (data.get('scope') or 'public').lower()
    text = (data.get('text') or '').strip()
    tid = int(data.get('thread_id') or 0)
    to_user = (data.get('to_user') or '').strip()
    if not text:
        return jsonify({'error':'bad params'}), 400
    safe_text = render_markdown(text)
    now = to_ny_time(datetime.utcnow())
    # Persist + emit
    if scope == 'public':
        try:
            msg = store_system_message(text)  # persists and returns payload
            socketio.emit('new_message', { 'id': msg['id'], 'user_id': 0, 'username': 'System', 'text': msg['text'], 'attachment': None, 'created_at': now }, room='chat_room')
        except Exception:
            pass
        return jsonify({'ok': True})
    if scope == 'dm' and to_user:
        try:
            db = get_db(); cur = db.cursor()
            cur.execute("""
                INSERT INTO direct_messages (from_user, to_user, text, attachment, created_at, reply_to)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ('System', to_user, safe_text, None, datetime.utcnow(), None))
            db.commit()
            did = cur.lastrowid
            payload = {
                'id': did,
                'from_user': 'System',
                'to_user': to_user,
                'text': safe_text,
                'attachment': None,
                'created_at': now,
                'avatar': '/sys_pfp.png',
                'reply_to': None,
                'reply_username': None,
                'reply_snippet': None,
            }
            # Send DM to target and echo to admins who triggered it (if desired)
            socketio.emit('dm_new', payload, room=f'user:{to_user}')
            socketio.emit('dm_new', payload, room=f'user:{me}')
        except Exception:
            return jsonify({'error':'dm_failed'}), 500
        return jsonify({'ok': True})
    if scope == 'gdm' and tid>0:
        try:
            db = get_db(); cur = db.cursor()
            cur.execute('INSERT INTO group_messages(thread_id, username, text, attachment, created_at) VALUES(?,?,?,?,?)', (tid, 'System', safe_text, None, datetime.utcnow()))
            db.commit()
        except Exception:
            pass
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        members = [r[0] for r in cur.fetchall()]
        payload = { 'id': int(time.time()*1000)%2147483647, 'username':'System', 'text': safe_text, 'attachment': None, 'created_at': now, 'avatar': '/sys_pfp.png', 'thread_id': tid }
        for u in members:
            socketio.emit('gdm_new', payload, room=f'user:{u}')
        return jsonify({'ok': True})
@app.route('/api/admin/pin', methods=['POST'])
def api_admin_pin():
    if not _dbx_ok():
        return jsonify({'error': 'forbidden'}), 403
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('MC_PIN_MESSAGE','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    kind = (data.get('type') or 'public').lower()
    action = (data.get('action') or 'pin').lower()
    mid = int(data.get('id') or 0)
    tid = int(data.get('thread_id') or 0)
    if kind not in ('public','gdm') or mid<=0:
        return jsonify({'error':'bad params'}), 400
    _ensure_pin_table()
    db = get_db(); cur = db.cursor()
    if action == 'pin':
        # Allow multiple pins - just insert the new one
        try:
            # Check if already pinned
            if kind == 'public':
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? AND message_id=?', ('public', mid))
            else:
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? AND thread_id=? AND message_id=?', ('gdm', tid, mid))
            if cur.fetchone():
                return jsonify({'ok': True, 'message': 'Already pinned'})
            # Insert new pin
            cur.execute('INSERT INTO pinned_messages(kind, message_id, thread_id) VALUES(?,?,?)', (kind, mid, tid if kind=='gdm' else None))
            db.commit()
        except Exception as e:
            db.rollback()
            return jsonify({'error': str(e)}), 500
        try:
            if kind == 'public':
                # Lookup latest pinned message to include payload
                try:
                    cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? ORDER BY created_at DESC LIMIT 1', ('public',))
                    latest_row = cur.fetchone()
                    if latest_row:
                        latest_mid = latest_row[0]
                        cur.execute('SELECT id, username, text, attachment, created_at FROM messages WHERE id=?', (latest_mid,))
                        r = cur.fetchone()
                        if r:
                            payload = { 'kind':'public', 'action':'pin', 'message': { 'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) } }
                        else:
                            payload = { 'kind':'public', 'action':'pin', 'message': None }
                    else:
                        payload = { 'kind':'public', 'action':'pin', 'message': None }
                except Exception:
                    payload = { 'kind':'public', 'action':'pin', 'message': None }
                socketio.emit('pin_update', payload, room='chat_room')
        except Exception:
            pass
        return jsonify({'ok': True})
    if action == 'unpin':
        # Unpin specific message by ID
        if kind == 'public':
            cur.execute('DELETE FROM pinned_messages WHERE kind=? AND message_id=?', ('public', mid))
        else:
            cur.execute('DELETE FROM pinned_messages WHERE kind=? AND thread_id=? AND message_id=?', ('gdm', tid, mid))
        db.commit()
        try:
            if kind == 'public':
                # Get latest remaining pin to update UI
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? ORDER BY created_at DESC LIMIT 1', ('public',))
                latest_row = cur.fetchone()
                if latest_row:
                    latest_mid = latest_row[0]
                    cur.execute('SELECT id, username, text, attachment, created_at FROM messages WHERE id=?', (latest_mid,))
                    r = cur.fetchone()
                    if r:
                        payload = { 'kind':'public', 'action':'pin', 'message': { 'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) } }
                    else:
                        payload = { 'kind':'public', 'action':'unpin' }
                else:
                    payload = { 'kind':'public', 'action':'unpin' }
                socketio.emit('pin_update', payload, room='chat_room')
        except Exception:
            pass
        return jsonify({'ok': True})
    return jsonify({'error':'bad action'}), 400

# DM Tools (toggle-gated)
@app.route('/api/admin/dm_close_all', methods=['POST'])
@login_required
def api_admin_dm_close_all():
    me = session.get('username')
    try:
        if get_setting('GD_CLOSE_ALL_DMS','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    db = get_db(); cur = db.cursor()
    try:
        cur.execute('DELETE FROM direct_messages WHERE from_user=? OR to_user=?', (me, me))
        db.commit()
    except Exception:
        pass
    try:
        socketio.emit('dm_cleared', {}, room=f'user:{me}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/admin/dm_as_system', methods=['POST'])
@login_required
def api_admin_dm_as_system():
    me = session.get('username')
    try:
        if get_setting('GD_DM_AS_SYSTEM','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    to_user = sanitize_username((data.get('to') or '').strip())
    text = (data.get('text') or '').strip()
    if not to_user or not text:
        return jsonify({'error':'bad params'}), 400
    safe_text = render_markdown(text)
    db = get_db(); cur = db.cursor()
    try:
        cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', to_user, safe_text, None, datetime.utcnow()))
        db.commit(); did = cur.lastrowid
    except Exception:
        did = int(time.time()*1000) % 2147483647
    payload = { 'id': did, 'from_user': 'System', 'to_user': to_user, 'text': safe_text, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
    try:
        socketio.emit('dm_new', payload, room=f'user:{to_user}')
    except Exception:
        pass
    return jsonify({'ok': True, 'id': did})

@app.route('/api/admin/dm_logs')
@login_required
def api_admin_dm_logs():
    me = session.get('username')
    try:
        if get_setting('GD_SAVE_DM_LOGS','1')=='0':
            return ("disabled", 403)
    except Exception:
        pass
    peer = (request.args.get('peer') or '').strip()
    if not peer:
        return ("peer required", 400)
    db = get_db(); cur = db.cursor()
    cur.execute(
        """
        SELECT id, from_user, to_user, text, created_at
        FROM direct_messages
        WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)
        ORDER BY id ASC
        """,
        (me, peer, peer, me)
    )
    rows = cur.fetchall() or []
    lines = []
    for r in rows:
        ts = to_ny_time(r[4]) if r[4] else ''
        lines.append(f"[{ts}] {r[1]} -> {r[2]}: {_plain_text_from_html(r[3] or '')}")
    content = "\n".join(lines)
    return app.response_class(content, mimetype='text/plain')

@app.route('/api/admin/history')
@login_required
def api_admin_history():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('MC_VIEW_HISTORY','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    kind = (request.args.get('type') or 'public').lower()
    limit = int(request.args.get('limit') or 50)
    limit = max(1, min(200, limit))
    db = get_db(); cur = db.cursor()
    if kind == 'public':
        cur.execute('SELECT id, username, text, attachment, created_at FROM messages ORDER BY id DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        items = [ { 'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4] if isinstance(r[4], datetime) else datetime.utcnow()) } for r in rows ]
        return jsonify({'items': items})

    if kind == 'gdm':
        tid = int(request.args.get('thread_id') or 0)
        if not tid:
            return jsonify({'error':'bad params'}), 400
        cur.execute('SELECT id, username, text, attachment, created_at FROM group_messages WHERE thread_id=? ORDER BY id DESC LIMIT ?', (tid, limit))
        rows = cur.fetchall()
        items = [ { 'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4] if isinstance(r[4], datetime) else datetime.utcnow()) } for r in rows ]
        return jsonify({'items': items})
    return jsonify({'error':'bad params'}), 400

@app.route('/api/admin/history_log')
@login_required
def api_admin_history_log():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('MC_VIEW_HISTORY','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    try:
        # Stream the entire chat_messages.txt file if present
        if not os.path.exists(LOG_FILE):
            return app.response_class('(no history)', mimetype='text/plain')
        with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
            data = f.read()
        return app.response_class(data, mimetype='text/plain')
    except Exception as e:
        return app.response_class(f'Error reading history log: {e}', mimetype='text/plain')

@app.route('/api/admin/restart', methods=['POST'])
@login_required
def api_admin_restart():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    # Schedule a restart shortly after responding
    def _restart():
        try:
            time.sleep(1.0)
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception:
            os._exit(3)
    threading.Thread(target=_restart, daemon=True).start()
    return jsonify({'ok': True, 'message': 'restarting'})

def safe_save_file_from_b64(filename, b64data):
    # Delegate to the robust implementation defined earlier
    try:
        return SAFE_SAVE_FILE_B64_IMPL(filename, b64data)  # type: ignore
    except Exception:
        return None

def store_system_message(text):
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO messages (user_id, username, text, attachment, created_at) 
        VALUES (?, ?, ?, ?, ?)
    """, (0, "System", text, None, datetime.utcnow()))
    db.commit()
    msg_id = cur.lastrowid
    try:
        ts = _format_web_timestamp(datetime.utcnow())
        _append_log_line(f"[{ts}] SYSTEM: {_plain_text_from_html(text)}")
    except Exception:
        pass
    return {
        "id": msg_id,
        "user_id": 0,
        "username": "System",
        "text": render_markdown(text),
        "attachment": None,
        "created_at": to_ny_time(datetime.utcnow())
    }

@app.route('/api/debug/ip')
@login_required
def api_debug_ip():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    return jsonify({
        'ip_detected': get_client_ip(),
        'X-Forwarded-For': request.headers.get('X-Forwarded-For'),
        'X-Real-IP': request.headers.get('X-Real-IP'),
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent')
    })

@app.route('/api/admin/overview')
@login_required
def api_admin_overview():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    # Collect current state
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT username FROM banned_users')
    bu = [r[0] for r in cur.fetchall()]
    cur.execute('SELECT ip_address FROM banned_ips')
    bi = [r[0] for r in cur.fetchall()]
    # Banned devices
    try:
        cur.execute('SELECT client_id, COALESCE(username, "") AS username, created_at FROM device_bans ORDER BY created_at DESC')
        bd = [ {'client_id': r[0], 'username': (r[1] if len(r) > 1 else ''), 'created_at': (r[2] if len(r) > 2 else None)} for r in cur.fetchall() ]
    except Exception:
        bd = []
    # Build merged admins list (defaults + DB roles + extra_admins) but exclude superadmins
    try:
        merged_admins = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
    except Exception:
        merged_admins = sorted(list(ADMINS))
    return jsonify({
        'admins': sorted(merged_admins),
        'superadmins': sorted(list(SUPERADMINS)),
        'banned_users': sorted(bu),
        'banned_ips': sorted(bi),
        'banned_devices': bd,
    })

# Unban all devices for a given username
@app.route('/api/admin/unban_devices_for_user', methods=['POST'])
@login_required
def api_admin_unban_devices_for_user():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('username') or '').strip())
    if not user:
        return jsonify({'error':'bad params'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('DELETE FROM device_bans WHERE username=?', (user,))
        db.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/online_ips')
@login_required
def api_admin_online_ips():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    # Snapshot of online users and their last-seen IP
    items = []
    for u, ts in online_users.items():
        items.append({'username': u, 'ip': user_ips.get(u) or ''})
    # sort by username
    items.sort(key=lambda x: x['username'].lower())
    return jsonify({'online': items})

@app.route('/api/admin/app_settings', methods=['GET','POST'])
@login_required
def api_admin_app_settings():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    keys = [
        # Global Chat Controls
        'PUBLIC_ENABLED',
        'DM_ENABLED',
        'GDM_ENABLED',
        'MAINTENANCE_MODE',
        'INVITE_ONLY_MODE',
        'ANNOUNCEMENTS_ONLY',
        # User Management
        'UM_BAN_USER',
        'UM_TIMEOUT_USER',
        'UM_SEARCH_USER',
        'UM_TEMP_BAN',
        'UM_GLOBAL_WARNING',
        'UM_SHADOW_BAN',
        # Message & Channel Controls
        'MC_DELETE_MESSAGES',
        'MC_EDIT_MESSAGES',
        'MC_SEARCH_MESSAGES',
        'MC_PURGE_CHANNEL',
        'MC_PIN_MESSAGE',
        'MC_BROADCAST_MESSAGE',
        'MC_VIEW_HISTORY',
        'MC_MESSAGE_LIFESPAN',
        'MC_MESSAGE_LIFESPAN_DAYS',
        # Group & DM Controls
        'GD_LOCK_GROUP',
        'GD_UNLOCK_GROUP',
        'GD_REMOVE_USER',
        'GD_TRANSFER_OWNERSHIP',
        'GD_ARCHIVE_GROUP',
        'GD_DELETE_GROUP',
        'GD_CLOSE_ALL_DMS',
        'GD_DM_AS_SYSTEM',
        'GD_SAVE_DM_LOGS',
        'GD_FORCE_LEAVE_GROUP',
        # Admin Tools
        'ADMIN_SYNC_PERMS',
        'ADMIN_VIEW_ACTIVE',
        'ADMIN_STEALTH_MODE',
        'ADMIN_EMERGENCY_SHUTDOWN',
        'ADMIN_SHOW_EMERGENCY_BLOCK',
        # Emergency metadata (read-only status helpers)
        'EMERGENCY_LAST_SNAPSHOT',
        'EMERGENCY_LAST_TIME',
        # Security
        'SEC_STRICT_ASSOCIATED_BAN',
        'SEC_DEVICE_BAN_ON_LOGIN',
        'SEC_REG_BAN_SIMILAR_CID',
    ]
    if request.method == 'GET':
        out = {}
        for k in keys:
            if k == 'MC_MESSAGE_LIFESPAN_DAYS':
                out[k] = get_setting(k, '0')
            else:
                # Defaults: on by default for core chat features, common moderation tools, and selected security heuristics
                defaults_on = (
                    'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED',
                    'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
                    'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_VIEW_HISTORY','MC_SEARCH_MESSAGES','MC_BROADCAST_MESSAGE','MC_PIN_MESSAGE',
                    'SEC_DEVICE_BAN_ON_LOGIN','SEC_REG_BAN_SIMILAR_CID'
                )
                out[k] = get_setting(k, '1' if k in defaults_on else '0')
        return jsonify(out)

@app.route('/api/gdm/thread_info')
@login_required
def api_gdm_thread_info():
    me = session.get('username')
    try:
        tid = int((request.args.get('tid') or '0').strip() or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
        if not cur.fetchone():
            return jsonify({'error':'forbidden'}), 403
        try:
            cur.execute('SELECT COALESCE(locked,0) FROM group_threads WHERE id=?', (tid,))
            row = cur.fetchone()
            locked = int(row[0] if row and not isinstance(row, sqlite3.Row) else (row['COALESCE(locked,0)'] if row else 0))
        except Exception:
            locked = 0
        return jsonify({'ok': True, 'locked': 1 if locked else 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    data = request.get_json(silent=True) or {}
    for k in keys:
        if k in data:
            if k == 'MC_MESSAGE_LIFESPAN_DAYS':
                try:
                    days = max(0, int(str(data[k]).strip() or '0'))
                except Exception:
                    days = 0
                set_setting(k, str(days))
            else:
                set_setting(k, '1' if str(data[k]) in ('1','true','True','on') else '0')
    return jsonify({'ok': True})

@app.route('/api/admin/role', methods=['POST'])
@login_required
def api_admin_role():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    action = (data.get('action') or '').lower()
    role = (data.get('role') or '').lower()
    user = sanitize_username((data.get('username') or '').strip())
    if role != 'admin' or not user:
        return jsonify({'error':'bad params'}), 400
    # ensure persistence table
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
        db.commit()
    except Exception:
        pass
    if action == 'add':
        ADMINS.add(user)
        try:
            db = get_db(); cur = db.cursor()
            cur.execute('INSERT OR REPLACE INTO extra_admins(username, created_at, created_by) VALUES(?,?,?)', (user, datetime.utcnow().isoformat(), me))
            db.commit()
        except Exception:
            pass
        try:
            log_admin_action(me, 'admin_add', target=user)
        except Exception:
            pass
        try:
            socketio.emit('system_message', store_system_message(f"{user} was granted admin by {me}"))
            try:
                merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
            except Exception:
                merged = sorted(list(ADMINS))
            try:
                if get_setting('ADMINS_STEALTH','0')=='1':
                    merged = []
            except Exception:
                pass
            socketio.emit('admin_list', {'admins': merged})
        except Exception:
            pass
        try:
            merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
        except Exception:
            merged = sorted(list(ADMINS))
        return jsonify({'ok': True, 'admins': merged})
    if action == 'remove':
        ADMINS.discard(user)
        try:
            db = get_db(); cur = db.cursor()
            cur.execute('DELETE FROM extra_admins WHERE username=?', (user,))
            db.commit()
        except Exception:
            pass
        try:
            log_admin_action(me, 'admin_remove', target=user)
        except Exception:
            pass
        try:
            socketio.emit('system_message', store_system_message(f"{user} admin role removed by {me}"))
            try:
                merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
            except Exception:
                merged = sorted(list(ADMINS))
            try:
                if get_setting('ADMINS_STEALTH','0')=='1':
                    merged = []
            except Exception:
                pass
            socketio.emit('admin_list', {'admins': merged})
        except Exception:
            pass
        try:
            merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
        except Exception:
            merged = sorted(list(ADMINS))
        return jsonify({'ok': True, 'admins': merged})
    return jsonify({'error':'unknown action'}), 400

@app.route('/api/admin/user_search')
@login_required
def api_admin_user_search():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Toggle gate
    try:
        if get_setting('UM_SEARCH_USER','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    q = (request.args.get('q') or '').strip()
    db = get_db(); cur = db.cursor()
    if not q:
        cur.execute('SELECT username FROM users ORDER BY LOWER(username) ASC LIMIT 50')
        users = [r[0] for r in cur.fetchall()]
        return jsonify({'users': users})
    pat = f"%{q.lower()}%"
    cur.execute('SELECT username FROM users WHERE LOWER(username) LIKE ? ORDER BY LOWER(username) ASC LIMIT 50', (pat,))
    return jsonify({'users': [r[0] for r in cur.fetchall()]})

@app.route('/api/admin/timeout', methods=['POST'])
@login_required
def api_admin_timeout():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Toggle gate
    try:
        if get_setting('UM_TIMEOUT_USER','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    try:
        minutes = int(data.get('minutes') or 5)
    except Exception:
        minutes = 5
    if not user:
        return jsonify({'error':'bad params'}), 400
    user_timeouts[user] = time.time() + max(1, minutes) * 60
    try:
        log_admin_action(me, 'timeout', target=user, details={'minutes': int(minutes)})
    except Exception:
        pass
    # Notify target privately via DM
    try:
        db = get_db(); cur = db.cursor()
        msg = render_markdown(f"You were timed out for {minutes} minutes by {me}.")
        cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', user, msg, None, datetime.utcnow()))
        db.commit(); did = cur.lastrowid
        payload = { 'id': did, 'from_user': 'System', 'to_user': user, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
        socketio.emit('dm_new', payload, room=f'user:{user}')
    except Exception:
        pass
    # Notify the targeted user to locally block sending UI
    try:
        emit('timeout_set', { 'until': int(user_timeouts[user]) }, room=f'user:{user}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/admin/shadow', methods=['POST'])
@login_required
def api_admin_shadow():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('UM_SHADOW_BAN','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    action = (data.get('action') or '').lower()
    if not user or action not in ('add','remove'):
        return jsonify({'error':'bad params'}), 400
    # Do not allow shadow-banning superadmins
    try:
        if user in SUPERADMINS:
            return jsonify({'error':'cannot shadow-ban superadmin'}), 403
    except Exception:
        pass
    ok = False
    if action == 'add':
        ok = set_shadow_ban(user)
        if ok:
            try:
                db = get_db(); cur = db.cursor()
                msg = render_markdown(f"You were shadow banned by {me}.")
                cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', user, msg, None, datetime.utcnow()))
                db.commit(); did = cur.lastrowid
                payload = { 'id': did, 'from_user': 'System', 'to_user': user, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
                socketio.emit('dm_new', payload, room=f'user:{user}')
            except Exception:
                pass
            try:
                log_admin_action(me, 'shadow_add', target=user)
            except Exception:
                pass
    else:
        ok = clear_shadow_ban(user)
        if ok:
            try:
                log_admin_action(me, 'shadow_remove', target=user)
            except Exception:
                pass
        if ok:
            try:
                db = get_db(); cur = db.cursor()
                msg = render_markdown(f"Your shadow ban was removed by {me}.")
                cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', user, msg, None, datetime.utcnow()))
                db.commit(); did = cur.lastrowid
                payload = { 'id': did, 'from_user': 'System', 'to_user': user, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
                socketio.emit('dm_new', payload, room=f'user:{user}')
            except Exception:
                pass
    if not ok:
        return jsonify({'error':'failed'}), 500
    return jsonify({'ok': True})

@app.route('/api/admin/warn', methods=['POST'])
@login_required
def api_admin_warn():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Toggle gate
    try:
        if get_setting('UM_GLOBAL_WARNING','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    message = (data.get('message') or '').strip()
    if not user or not message:
        return jsonify({'error':'bad params'}), 400
    safe_text = render_markdown(message)
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', user, safe_text, None, datetime.utcnow()))
    db.commit(); did = cur.lastrowid
    payload = { 'id': did, 'from_user': 'System', 'to_user': user, 'text': safe_text, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
    socketio.emit('dm_new', payload, room=f'user:{user}')
    socketio.emit('system_message', store_system_message(f"Warning sent to {user} by {me}"))
    try:
        log_admin_action(me, 'warn', target=user, details={'message': message[:500]})
    except Exception:
        pass
    return jsonify({'ok': True})
    if action == 'add':
        if user in SUPERADMINS:
            return jsonify({'error':'cannot modify superadmin'}), 400
        ADMINS.add(user)
        socketio.emit('system_message', store_system_message(f"{user} was granted admin by {me}"))
        socketio.emit('admin_list', {'admins': sorted(list(ADMINS))})
        return jsonify({'ok': True, 'admins': sorted(list(ADMINS))})
    if action == 'remove':
        ADMINS.discard(user)
        socketio.emit('system_message', store_system_message(f"{user} admin role removed by {me}"))
        socketio.emit('admin_list', {'admins': sorted(list(ADMINS))})
        return jsonify({'ok': True, 'admins': sorted(list(ADMINS))})
    return jsonify({'error':'unknown action'}), 400

@app.route('/api/admin/ban', methods=['POST'])
@login_required
def api_admin_ban():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Toggle gate
    try:
        if get_setting('UM_BAN_USER','1')=='0' and (request.json or {}).get('type','user')=='user':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    what = (data.get('type') or '').lower()  # 'user' or 'ip'
    action = (data.get('action') or '').lower()  # 'ban' or 'unban'
    value = (data.get('value') or '').strip()
    if what == 'user':
        target = sanitize_username(value)
        if not target:
            return jsonify({'error':'bad params'}), 400
        if action == 'ban':
            if not _can_ban(me, target):
                return jsonify({'error':'not allowed'}), 403
            db = get_db(); cur = db.cursor()
            cur.execute('INSERT OR IGNORE INTO banned_users(username) VALUES(?)', (target,))
            db.commit()
            try:
                log_admin_action(me, 'ban_user', target=target)
            except Exception:
                pass
            # Notify target privately
            try:
                msg = render_markdown(f"You were banned by {me}.")
                cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', target, msg, None, datetime.utcnow()))
                db.commit(); did = cur.lastrowid
                payload = { 'id': did, 'from_user': 'System', 'to_user': target, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
                socketio.emit('dm_new', payload, room=f'user:{target}')
            except Exception:
                pass
            for sid, uname in list(connected_sockets.items()):
                if uname == target:
                    try: socketio.server.disconnect(sid)
                    except Exception: pass
            return jsonify({'ok': True})
        if action == 'unban':
            if not _can_unban(me, target):
                return jsonify({'error':'not allowed'}), 403
            db = get_db(); cur = db.cursor()
            cur.execute('DELETE FROM banned_users WHERE username=?', (target,))
            db.commit()
            try:
                log_admin_action(me, 'unban_user', target=target)
            except Exception:
                pass
            # Notify target privately
            try:
                msg = render_markdown(f"Your ban was removed by {me}.")
                cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', target, msg, None, datetime.utcnow()))
                db.commit(); did = cur.lastrowid
                payload = { 'id': did, 'from_user': 'System', 'to_user': target, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
                socketio.emit('dm_new', payload, room=f'user:{target}')
            except Exception:
                pass
            return jsonify({'ok': True})
        return jsonify({'error':'unknown action'}), 400
    elif what == 'ip':
        user = sanitize_username((data.get('username') or '').strip())
        ip = (value or '').strip()
        # If IP is not provided but username is, derive from online map
        if not ip and user:
            ip = user_ips.get(user) or ''
            if not ip:
                return jsonify({'error': f'no ip for user {user} (offline)'}), 400
        if action == 'ban':
            # Must map to a user to enforce hierarchy, unless overseer/superadmin scenario
            if user and not _can_ban(me, user):
                return jsonify({'error':'not allowed'}), 403
            if ip in ("127.0.0.1", "::1"):
                return jsonify({'error':'refuse loopback'}), 400
            # Protect admins from non-superadmins. Superadmins may ban any IP, including those used by superadmins.
            try:
                holders = [u for u, uip in user_ips.items() if uip == ip]
                if not is_superadmin(me):
                    if any(u in SUPERADMINS for u in holders):
                        return jsonify({'error':'ip in use by a superadmin'}), 400
                    if any(u in ADMINS for u in holders):
                        return jsonify({'error':'ip in use by an admin'}), 400
            except Exception:
                pass
            db = get_db(); cur = db.cursor()
            cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (ip,))
            db.commit(); banned_ips.add(ip)
            try:
                log_admin_action(me, 'ban_ip', target=user or '', details={'ip': ip})
            except Exception:
                pass
            socketio.emit('system_message', store_system_message(f"An IP was banned by {me}"))
            # Disconnect all sockets with that IP
            for sid, uname in list(connected_sockets.items()):
                try:
                    if user_ips.get(uname) == ip:
                        socketio.server.disconnect(sid)
                except Exception:
                    pass
            return jsonify({'ok': True})
        if action == 'unban':
            # If IP omitted but username provided, derive from online map
            if not ip and user:
                ip = user_ips.get(user) or ''
                if not ip:
                    return jsonify({'error': f'no ip for user {user} (offline)'}), 400
            db = get_db(); cur = db.cursor()
            cur.execute('DELETE FROM banned_ips WHERE ip_address=?', (ip,))
            db.commit(); banned_ips.discard(ip)
            try:
                log_admin_action(me, 'unban_ip', target=user or '', details={'ip': ip})
            except Exception:
                pass
            socketio.emit('system_message', store_system_message(f"An IP was unbanned by {me}"))
            return jsonify({'ok': True})
        return jsonify({'error':'unknown action'}), 400
    return jsonify({'error':'bad params'}), 400

@app.route('/api/admin/code', methods=['GET', 'POST'])
@login_required
def api_admin_code():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    if request.method == 'GET':
        try:
            with open(__file__, 'r', encoding='utf-8') as f:
                return jsonify({'content': f.read()})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    # POST -> save (optionally restart atomically in background)
    data = request.get_json(silent=True) or {}
    content = data.get('content')
    restart = bool(data.get('restart', True))
    if content is None:
        return jsonify({'error': 'no content'}), 400
    if len(content) > 5000000:
        return jsonify({'error': 'too large'}), 400
    # Background task to write atomically and restart, so this request can finish before
    def _write_and_maybe_restart(text: str, do_restart: bool):
        try:
            path = __file__
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(text)
            os.replace(tmp, path)  # atomic replace on same filesystem
            if do_restart:
                time.sleep(0.6)
                try:
                    os.execv(sys.executable, [sys.executable] + sys.argv)
                except Exception:
                    os._exit(3)
        except Exception:
            # best-effort; cannot report error after response
            pass
    try:
        threading.Thread(target=_write_and_maybe_restart, args=(content, restart), daemon=True).start()
        return jsonify({'ok': True, 'scheduled_restart': restart})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def render_markdown(text: str) -> str:
    """Render markdown and sanitize HTML. Allow links and basic formatting only."""
    text = text or ""
    try:
        md_html = markdown.markdown(text, extensions=["extra", "sane_lists"])  # may output <a>, <em>, <strong>, <code>
        # Sanitize: allow only safe inline tags with safe attrs
        allowed_tags = ["a", "em", "strong", "code", "br", "p", "ul", "ol", "li"]
        allowed_attrs = {"a": ["href", "title", "rel", "target"]}
        cleaned = bleach.clean(md_html, tags=allowed_tags, attributes=allowed_attrs, strip=True)
        # Ensure links are safe and open in new tab
        cleaned = cleaned.replace("<a ", "<a rel=\"noopener noreferrer\" target=\"_blank\" ")
        # Linkify plain URLs as anchors
        linked = bleach.linkify(cleaned)
        return linked
    except Exception:
        return bleach.clean(text, tags=[], attributes={}, strip=True)

# Routes: Authentication
@app.route("/", methods=["GET"])
def root():
    if "user_id" in session:
        return redirect(url_for("chat"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("chat"))
    
    # Emergency shutdown check
    try:
        allowed, reason = _emergency_check_gate(
            username=None, operation="register", superadmins=SUPERADMINS
        )
        if not allowed:
            return render_template_string(REGISTER_HTML, error=reason), 503
    except Exception:
        pass
    client_ip = get_client_ip()
    if is_ip_banned(client_ip):
        return render_template_string(REGISTER_HTML, error="Your IP address is banned"), 403
    
    # Block registration if device is banned
    try:
        cid = (request.cookies.get('client_id') or '').strip()
        if cid:
            db = get_db(); cur = db.cursor()
            cur.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid,))
            if cur.fetchone():
                return render_template_string(REGISTER_HTML, error="Your device is banned"), 403
            # If enabled, block/ban registration attempts with similar client_id to banned devices
            try:
                if get_setting('SEC_REG_BAN_SIMILAR_CID','0')=='1':
                    pref = cid[:8]
                    if pref:
                        # If prefix is whitelisted (from an admin device-unban), skip blocking
                        try:
                            cur.execute('CREATE TABLE IF NOT EXISTS user_device_whitelist (cid_prefix TEXT PRIMARY KEY, username TEXT, created_at TIMESTAMP)')
                            cur.execute('SELECT 1 FROM user_device_whitelist WHERE cid_prefix=? LIMIT 1', (pref,))
                            whitelisted = cur.fetchone() is not None
                        except Exception:
                            whitelisted = False
                        if not whitelisted:
                            cur.execute("SELECT client_id FROM device_bans WHERE client_id LIKE ? LIMIT 1", (pref+'%',))
                            if cur.fetchone():
                                # Auto-ban this device id and block registration
                                cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (cid, ''))
                                db.commit()
                                return render_template_string(REGISTER_HTML, error="Registration blocked"), 403
            except Exception:
                pass
    except Exception:
        pass

    if request.method == "POST":
        # Invite-only gate
        try:
            if (get_setting('INVITE_ONLY_MODE', '0') == '1'):
                return render_template_string(REGISTER_HTML, error="Registration is invite-only"), 403
        except Exception:
            pass
        username = sanitize_username((request.form.get("username") or "").strip())
        password = (request.form.get("password") or "")
        # very basic length/range checks to avoid empty or huge usernames
        if not username or len(username) > 20:
            return render_template_string(REGISTER_HTML, error="Invalid username (max 20 characters)"), 400
        
        if not username or not password:
            return render_template_string(REGISTER_HTML, error="Provide username and password")
        
        if username.lower() == "system":
            return render_template_string(REGISTER_HTML, error="Reserved username")
        
        db = get_db()
        cur = db.cursor()
        try:
            pw_hash = generate_password_hash(password)
            try:
                cur.execute("INSERT INTO users (username, password_hash, language) VALUES (?, ?, ?)",
                           (username, pw_hash, 'en'))
            except sqlite3.OperationalError:
                cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, pw_hash))
            db.commit()
            socketio.emit("user_list_refresh", {"new_user": username})
            # Use 303 See Other to force a GET to /login for some clients
            return redirect(url_for("login"), code=303)
        except sqlite3.IntegrityError:
            return render_template_string(REGISTER_HTML, error="Username taken")
    
    return render_template_string(REGISTER_HTML, error="")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("chat"))
    
    # Emergency shutdown check
    try:
        allowed, reason = _emergency_check_gate(
            username=None, operation="login", superadmins=SUPERADMINS
        )
        if not allowed:
            return render_template_string(LOGIN_HTML, error=reason), 503
    except Exception:
        pass
    client_ip = get_client_ip()
    if is_ip_banned(client_ip):
        return render_template_string(LOGIN_HTML, error="Your IP address is banned"), 403
    
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")
        
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, username, password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        
        if row and check_password_hash(row["password_hash"], password):
            # Device banned? hard block
            try:
                cid_cookie = (request.cookies.get('client_id') or '').strip()
                if cid_cookie:
                    cur2 = get_db().cursor(); cur2.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid_cookie,))
                    if cur2.fetchone():
                        return render_template_string(LOGIN_HTML, error="Your device is banned"), 403
            except Exception:
                pass
            if is_banned(username):
                # Strict associated ban: optionally ban public IP too
                try:
                    if get_setting('SEC_STRICT_ASSOCIATED_BAN','0')=='1':
                        priv, pub = detect_client_ips()
                        if pub and not _is_loopback_ip(pub):
                            cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (pub,))
                            get_db().commit()
                except Exception:
                    pass
                # Always ban device id if present
                try:
                    cid_cookie = (request.cookies.get('client_id') or '').strip()
                    if cid_cookie and get_setting('SEC_DEVICE_BAN_ON_LOGIN','1')=='1':
                        cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (cid_cookie, username))
                        get_db().commit()
                except Exception:
                    pass
                return render_template_string(LOGIN_HTML, error="You are banned"), 403
            # Detect IPs and enforce
            priv, pub = detect_client_ips()
            _update_user_ips(username, priv, pub)
            if _is_ip_blocked_for(username, priv, pub):
                return render_template_string(LOGIN_HTML, error="Access blocked by IP ban")
            session.clear()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            online_users[username] = time.time()
            try:
                cid = (request.cookies.get('client_id') or '').strip()
                info = user_ips.get(username) if isinstance(user_ips.get(username), dict) else {}
                if cid:
                    info = {'private': info.get('private'), 'public': info.get('public'), 'immune': info.get('immune', _user_immune(username)), 'client_id': cid}
                    user_ips[username] = info
                # If this user is banned, auto device-ban this client
                try:
                    if is_banned(username) and cid and get_setting('SEC_DEVICE_BAN_ON_LOGIN','1')=='1':
                        db = get_db(); cur = db.cursor()
                        cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (cid, username))
                        db.commit()
                except Exception:
                    pass
            except Exception:
                pass
            try:
                socketio.emit('user_list_refresh', { 'online': username })
            except Exception:
                pass
            return redirect(url_for("chat"))
        
        return render_template_string(LOGIN_HTML, error="Invalid username or password")
    
    return render_template_string(LOGIN_HTML, error="")

@app.route("/logout")
def logout():
    username = session.get("username")
    session.clear()
    if username in online_users:
        online_users.pop(username)
    try:
        socketio.emit('user_list_refresh', { 'offline': username })
    except Exception:
        pass
    return redirect(url_for("login"))

# Routes: Chat
@app.route("/chat")
@login_required
def chat():
    # fetch my profile theme/avatar
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT username, theme, avatar, bio, status, language, COALESCE(allow_dm_nonfriends,1) AS allow_dm_nonfriends FROM users WHERE id=?", (session.get("user_id"),))
    urow = cur.fetchone() or {}
    # Honor stealth mode for initial render to prevent admin badge flash
    try:
        stealth = (get_setting('ADMINS_STEALTH','0') == '1')
    except Exception:
        stealth = False
    return render_template_string(
        CHAT_HTML,
        username=session.get("username"),
        is_admin=is_admin(),
        admins=([] if stealth else sorted(list(ADMINS))),
        superadmins=sorted(list(SUPERADMINS)),
        my_theme=(urow["theme"] if isinstance(urow, sqlite3.Row) else None) or "light",
        my_avatar=(urow["avatar"] if isinstance(urow, sqlite3.Row) else None) or "",
        my_bio=(urow["bio"] if isinstance(urow, sqlite3.Row) else None) or "",
        my_status=(urow["status"] if isinstance(urow, sqlite3.Row) else None) or "",
        my_allow=(urow["allow_dm_nonfriends"] if isinstance(urow, sqlite3.Row) else 1),
        my_language=((urow["language"] if isinstance(urow, sqlite3.Row) else None) or 'en'),
        supported_languages=[{'code': code, 'label': label} for code, label in SUPPORTED_LANGUAGES],
        gdm_tid=request.args.get('tid') or '',
        voice_ch=request.args.get('voice') or '',
    )

@app.route('/voice/<channel>')
def voice_link(channel: str):
    try:
        # Redirect user to chat with voice channel preselected; auth handled by /chat
        ch = (channel or '').strip()
        return redirect(f"/chat?voice={ch}")
    except Exception:
        return redirect('/chat')

@app.route("/api/messages")
@login_required
def api_messages():
    db = get_db()
    cur = db.cursor()
    me = session.get('username')
    cur.execute("SELECT * FROM messages ORDER BY id ASC")
    messages = []
    for row in cur.fetchall():
        author = row["username"] if isinstance(row, sqlite3.Row) else row[2]
        try:
            if author and author != me and is_shadow_banned(author):
                continue
        except Exception:
            pass
        # Reply preview
        rto = None; ruser=None; rsnip=None
        try:
            rto = (row["reply_to"] if isinstance(row, sqlite3.Row) else None)
        except Exception:
            rto = None
        if rto:
            try:
                cur2 = db.cursor(); cur2.execute('SELECT username, text FROM messages WHERE id=?', (rto,))
                rr = cur2.fetchone()
                if rr:
                    ruser = rr[0] if not isinstance(rr, sqlite3.Row) else rr['username']
                    rhtml = rr[1] if not isinstance(rr, sqlite3.Row) else rr['text']
                    try:
                        plain = re.sub(r'<[^>]+>', '', rhtml or '')
                    except Exception:
                        plain = (rhtml or '')
                    rsnip = (plain or '')[:140]
            except Exception:
                pass
        messages.append({
            "id": row["id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "text": row["text"],
            "attachment": row["attachment"],
            "created_at": to_ny_time(row["created_at"]) if row["created_at"] else None,
            "reply_to": rto,
            "reply_username": ruser,
            "reply_snippet": rsnip
        })
    return jsonify(messages)

@app.route("/api/users_all")
@login_required
def api_users_all():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users ORDER BY LOWER(username) ASC")
    users = [r[0] for r in cur.fetchall()]
    return jsonify(users)

@app.route("/api/voice/channels")
@login_required
def api_voice_channels():
    try:
        chans = sorted([k for k,v in voice_channels.items() if v and len(v)>0])
        return jsonify({'ok': True, 'channels': chans})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e), 'channels': []}), 200

@app.route("/api/dm/peers")
@login_required
def api_dm_peers():
    me = session.get("username")
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT DISTINCT CASE WHEN from_user=? THEN to_user ELSE from_user END AS peer
        FROM direct_messages
        WHERE from_user=? OR to_user=?
        ORDER BY LOWER(peer) ASC
        """,
        (me, me, me),
    )
    peers = [r[0] for r in cur.fetchall()]
    return jsonify(peers)

@app.route("/api/dm/messages")
@login_required
def api_dm_messages():
    me = session.get("username")
    peer = (request.args.get("peer") or "").strip()
    if not peer:
        return jsonify([])
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT id, from_user, to_user, text, attachment, created_at, reply_to
        FROM direct_messages
        WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)
        ORDER BY id ASC
        """,
        (me, peer, peer, me),
    )
    rows = cur.fetchall()
    out = []
    for r in rows:
        # Hide messages authored by shadow-banned users (except my own)
        try:
            if r[1] and r[1] != me:
                try:
                    if is_shadow_banned(r[1]):
                        continue
                except Exception:
                    pass
        except Exception:
            pass
        # Reply preview
        rto = None; ruser=None; rsnip=None
        try:
            rto = r[6]
        except Exception:
            rto = None
        if rto:
            try:
                cur2 = db.cursor(); cur2.execute('SELECT from_user, text FROM direct_messages WHERE id=?', (rto,))
                rr = cur2.fetchone()
                if rr:
                    ruser = rr[0]
                    rhtml = rr[1]
                    try:
                        plain = re.sub(r'<[^>]+>', '', rhtml or '')
                    except Exception:
                        plain = (rhtml or '')
                    rsnip = (plain or '')[:140]
            except Exception:
                pass
        out.append(
            {
                "id": r[0],
                "from_user": r[1],
                "to_user": r[2],
                "text": r[3],
                "attachment": r[4],
                "created_at": to_ny_time(r[5]) if r[5] else None,
                "reply_to": rto,
                "reply_username": ruser,
                "reply_snippet": rsnip,
            }
        )
    return jsonify(out)

# Group DM APIs
@app.route('/api/gdm/threads', methods=['GET','POST'])
@login_required
def api_gdm_threads():
    me = session.get('username')
    try:
        _ensure_gdm_schema()
    except Exception:
        pass
    db = get_db(); cur = db.cursor()
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        name = (data.get('name') or '').strip() or f"Group {datetime.utcnow().strftime('%H%M%S')}"
        members = list(set([(m or '').strip() for m in (data.get('members') or []) if m and m.strip()]))
        if me not in members:
            members.append(me)
        if not members or len(members) < 2:
            return jsonify({'error':'need at least 2 members'}), 400
        cur.execute('INSERT INTO group_threads (name, created_by, created_at) VALUES (?, ?, ?)', (name, me, datetime.utcnow()))
        tid = cur.lastrowid
        for u in members:
            cur.execute('INSERT OR IGNORE INTO group_members (thread_id, username) VALUES (?,?)', (tid, u))
        db.commit()
        return jsonify({'id': tid, 'name': name})
    # GET: list my group threads
    try:
        cur.execute("""
            SELECT t.id, t.name, t.created_by, t.created_at, COALESCE(t.archived,0) as archived
            FROM group_threads t JOIN group_members m ON t.id=m.thread_id
            WHERE m.username=?
            ORDER BY t.id ASC
        """, (me,))
        rows = cur.fetchall() or []
        out = []
        for r in rows:
            try:
                out.append({'id': r[0], 'name': r[1], 'created_by': r[2], 'created_at': to_ny_time(r[3]) if r[3] else None, 'archived': (r[4] or 0)})
            except Exception:
                # Fallback if row is sqlite3.Row
                try:
                    out.append({'id': r['id'], 'name': r['name'], 'created_by': r['created_by'], 'created_at': to_ny_time(r['created_at']) if r['created_at'] else None, 'archived': r.get('archived', 0) if hasattr(r, 'get') else 0})
                except Exception:
                    pass
        return jsonify(out)
    except Exception:
        # Likely missing archived column; retry without it
        try:
            cur.execute("""
                SELECT t.id, t.name, t.created_by, t.created_at
                FROM group_threads t JOIN group_members m ON t.id=m.thread_id
                WHERE m.username=?
                ORDER BY t.id ASC
            """, (me,))
            rows = cur.fetchall() or []
            out = [{'id': r[0], 'name': r[1], 'created_by': r[2], 'created_at': to_ny_time(r[3]) if r[3] else None, 'archived': 0} for r in rows]
            return jsonify(out)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/gdm/messages')
@login_required
def api_gdm_messages():
    me = session.get('username')
    try:
        tid = int((request.args.get('tid') or '0'))
    except Exception:
        tid = 0
    if not tid:
        return jsonify([])
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return jsonify([])
    cur.execute('SELECT id, username, text, attachment, created_at, edited, reply_to FROM group_messages WHERE thread_id=? ORDER BY id ASC', (tid,))
    out=[]
    for r in cur.fetchall():
        try:
            author = r[1]
            if author and author != me:
                try:
                    if is_shadow_banned(author):
                        continue
                except Exception:
                    pass
        except Exception:
            pass
        rto=None; ruser=None; rsnip=None
        try:
            rto = r[6]
        except Exception:
            rto = None
        if rto:
            try:
                cur2 = db.cursor(); cur2.execute('SELECT username, text FROM group_messages WHERE id=?', (rto,))
                rr = cur2.fetchone()
                if rr:
                    ruser = rr[0] if not isinstance(rr, sqlite3.Row) else rr['username']
                    rhtml = rr[1] if not isinstance(rr, sqlite3.Row) else rr['text']
                    try:
                        plain = re.sub(r'<[^>]+>', '', rhtml or '')
                    except Exception:
                        plain = (rhtml or '')
                    rsnip = (plain or '')[:140]
            except Exception:
                pass
        out.append({'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None, 'edited': r[5] or 0, 'reply_to': rto, 'reply_username': ruser, 'reply_snippet': rsnip})
    return jsonify(out)

@app.route('/api/gdm/rename', methods=['POST'])
@login_required
def api_gdm_rename():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    name = (data.get('name') or '').strip()
    if not tid or not name:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    creator = row[0]
    if not (me == creator or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    cur.execute('UPDATE group_threads SET name=? WHERE id=?', (name, tid))
    db.commit()
    # notify all members to refresh
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    for u in members:
        socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    return jsonify({'ok': True})

# Group management endpoints (toggle-gated)
@app.route('/api/gdm/lock', methods=['POST'])
@login_required
def api_gdm_lock():
    me = session.get('username')
    try:
        if get_setting('GD_LOCK_GROUP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    cur.execute('UPDATE group_threads SET locked=1 WHERE id=?', (tid,))
    db.commit()
    try:
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        for u in [x[0] for x in cur.fetchall()]:
            socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/gdm/unlock', methods=['POST'])
@login_required
def api_gdm_unlock():
    me = session.get('username')
    try:
        if get_setting('GD_UNLOCK_GROUP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    cur.execute('UPDATE group_threads SET locked=0 WHERE id=?', (tid,))
    db.commit()
    try:
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        for u in [x[0] for x in cur.fetchall()]:
            socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/gdm/remove_member', methods=['POST'])
@login_required
def api_gdm_remove_member():
    me = session.get('username')
    try:
        if get_setting('GD_REMOVE_USER','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    user = sanitize_username((data.get('username') or '').strip())
    if not tid or not user:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    if user == owner:
        return jsonify({'error':'cannot remove owner'}), 400
    cur.execute('DELETE FROM group_members WHERE thread_id=? AND username=?', (tid, user))
    db.commit()
    try:
        socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{user}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/gdm/archive', methods=['POST'])
@login_required
def api_gdm_archive():
    me = session.get('username')
    try:
        if get_setting('GD_ARCHIVE_GROUP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    cur.execute('UPDATE group_threads SET archived=1 WHERE id=?', (tid,))
    db.commit()
    try:
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        for u in [x[0] for x in cur.fetchall()]:
            socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/gdm/delete', methods=['POST'])
@login_required
def api_gdm_delete_group():
    me = session.get('username')
    try:
        if get_setting('GD_DELETE_GROUP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        cur.execute('DELETE FROM group_messages WHERE thread_id=?', (tid,))
    except Exception:
        pass
    try:
        cur.execute('DELETE FROM group_members WHERE thread_id=?', (tid,))
    except Exception:
        pass
    cur.execute('DELETE FROM group_threads WHERE id=?', (tid,))
    db.commit()
    # If this was the last group and toggle enabled, reset group id sequences
    try:
        cur.execute('SELECT COUNT(1) FROM group_threads')
        left = (cur.fetchone() or [0])[0]
        if int(left or 0) == 0 and get_setting('RESET_ID_GROUP_THREADS','0')=='1':
            try:
                cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('group_threads','group_members','group_messages')")
                db.commit()
            except Exception:
                pass
    except Exception:
        pass
    # notify: users who had membership get a refresh (best-effort, using prior members is tricky after delete)
    try:
        socketio.emit('gdm_threads_refresh', {'deleted': tid})
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/gdm/force_leave', methods=['POST'])
@login_required
def api_gdm_force_leave():
    me = session.get('username')
    try:
        if get_setting('GD_FORCE_LEAVE_GROUP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    user = sanitize_username((data.get('username') or '').strip())
    if not tid or not user:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    if user == owner:
        return jsonify({'error':'cannot force owner'}), 400
    cur.execute('DELETE FROM group_members WHERE thread_id=? AND username=?', (tid, user))
    db.commit()
    try:
        socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{user}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/clear/all', methods=['POST'])
@login_required
def api_clear_all():
    me = session.get('username')
    if not me:
        return jsonify({'error': 'not logged in'}), 401
    db = get_db()
    cur = db.cursor()
    removed = {'public':0,'dm':0,'gdm':0}
    did_reset_public = False
    did_reset_gdm = False
    # Public: only superadmins can nuke all public messages
    if is_superadmin(me):
        try:
            cur.execute('DELETE FROM messages')
            removed['public'] = cur.rowcount if hasattr(cur, 'rowcount') else 0
            # Reset message IDs if toggle enabled
            try:
                if get_setting('RESET_PUBLIC_IDS','0')=='1':
                    try:
                        cur.execute("DELETE FROM sqlite_sequence WHERE name='messages'")
                        did_reset_public = True
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass
    # DMs: clear all DMs involving me
    try:
        cur.execute('DELETE FROM direct_messages WHERE from_user=? OR to_user=?', (me, me))
        removed['dm'] = cur.rowcount if hasattr(cur, 'rowcount') else 0
    except Exception:
        pass
    # Group messages: superadmin can nuke all, regular users only their authored messages
    try:
        if is_superadmin(me):
            cur.execute('DELETE FROM group_messages')
        else:
            cur.execute('DELETE FROM group_messages WHERE username=?', (me,))
        removed['gdm'] = cur.rowcount if hasattr(cur, 'rowcount') else 0
        # If SA cleared all, optionally reset GDM ids
        try:
            if is_superadmin(me) and get_setting('RESET_GDM_IDS','0')=='1':
                try:
                    cur.execute("DELETE FROM sqlite_sequence WHERE name='group_messages'")
                    did_reset_gdm = True
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        pass
    try:
        db.commit()
    except Exception:
        pass
    # Audit: record ID resets if any occurred
    try:
        if did_reset_public or did_reset_gdm:
            log_admin_action(me, 'reset_ids', details={'public': bool(did_reset_public), 'gdm': bool(did_reset_gdm), 'removed': removed})
    except Exception:
        pass
    # Notify this user client to clear UI
    try:
        emit('clear_all', {}, room=f'user:{me}')
    except Exception:
        pass
    return jsonify({'ok': True, 'removed': removed})

@app.route('/api/gdm/kick', methods=['POST'])
@login_required
def api_gdm_kick():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    user = sanitize_username((data.get('user') or '').strip())
    if not tid or not user:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    # Must be owner or superadmin
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    creator = row[0]
    if not (me == creator or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Remove membership
    cur.execute('DELETE FROM group_members WHERE thread_id=? AND username=?', (tid, user))
    db.commit()
    # Notify
    emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{user}')
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    for r2 in cur.fetchall():
        emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{r2[0]}')
    return jsonify({'ok': True})

@app.route('/api/gdm/add_member', methods=['POST'])
@login_required
def api_gdm_add_member():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    users = data.get('users') or []
    users = [ (u or '').strip() for u in users if u and u.strip() ]
    if not tid or not users:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    creator = row[0]
    if not (me == creator or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    for u in users:
        cur.execute('INSERT OR IGNORE INTO group_members (thread_id, username) VALUES (?,?)', (tid, u))
    db.commit()
    # notify all existing and new members
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    for u in members:
        socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    return jsonify({'ok': True})

@app.route('/api/gdm/delete', methods=['POST'])
@login_required
def api_gdm_delete():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    creator = row[0]
    if not (me == creator or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # collect members for notification
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    cur.execute('DELETE FROM group_messages WHERE thread_id=?', (tid,))
    cur.execute('DELETE FROM group_members WHERE thread_id=?', (tid,))
    cur.execute('DELETE FROM group_threads WHERE id=?', (tid,))
    db.commit()
    for u in set(members):
        socketio.emit('gdm_threads_refresh', {'deleted': tid}, room=f'user:{u}')
    return jsonify({'ok': True})

@app.route("/api/online")
@login_required
def api_online():
    cutoff = time.time() - 60
    return jsonify([u for u, t in online_users.items() if t > cutoff])

@app.route("/api/users_profiles")
@login_required
def api_users_profiles():
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT username, avatar, bio, status FROM users ORDER BY LOWER(username) ASC")
    now = time.time(); cutoff = now - 60; idle_cutoff = now - 20
    out=[]
    for r in cur.fetchall():
        u = r[0]
        avatar = r[1]
        bio = r[2] or ""
        pref_status = (r[3] or '').lower()
        last = online_users.get(u, 0)
        # Manual status override: always respected if set
        if pref_status in ('online','idle','dnd','offline'):
            presence = pref_status
        else:
            if last > cutoff:
                presence = 'online' if last >= idle_cutoff else 'idle'
            else:
                presence = 'offline'
        out.append({
            "username": u,
            "avatar": avatar,
            "avatar_url": (f"/uploads/{avatar}" if avatar else url_for('default_avatar')),
            "bio": bio,
            "status": pref_status or '',
            "presence": presence,
        })
    return jsonify(out)

@app.route('/default_avatar')
def default_avatar():
    return send_from_directory(APP_ROOT, DEFAULT_AVATAR)

@app.route('/default_sys_avatar')
def default_sys_avatar():
    return send_from_directory(APP_ROOT, DEFAULT_SYS_AVATAR)

@app.route('/api/gdm/members')
@login_required
def api_gdm_members():
    me = session.get('username')
    try:
        tid = int((request.args.get('tid') or '0'))
    except Exception:
        tid = 0
    if not tid:
        return jsonify([])
    db = get_db(); cur = db.cursor()
    # Only members can view the member list
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return jsonify([])
    cur.execute('SELECT username FROM group_members WHERE thread_id=? ORDER BY LOWER(username) ASC', (tid,))
    return jsonify([r[0] for r in cur.fetchall()])

# Group DM Invite API
@app.route('/api/gdm/invite/create', methods=['POST'])
@login_required
def api_gdm_invite_create():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int((data.get('tid') or 0))
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'invalid tid'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return jsonify({'error':'not a member'}), 403
    token = secrets.token_urlsafe(16)
    cur.execute('INSERT INTO group_invites(token, thread_id, created_by, created_at) VALUES(?,?,?,?)', (token, tid, me, to_ny_time(datetime.utcnow())))
    db.commit()
    link = url_for('api_gdm_invite_join', _external=True) + f"?token={token}"
    return jsonify({'ok':True,'token':token,'link':link})

@app.route('/api/gdm/invite/join', methods=['GET','POST'])
@login_required
def api_gdm_invite_join():
    me = session.get('username')
    token = (request.values.get('token') or '').strip()
    if not token:
        return jsonify({'error':'invalid'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT thread_id FROM group_invites WHERE token=?', (token,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    tid = row[0] if not isinstance(row, sqlite3.Row) else row['thread_id']
    cur.execute('INSERT OR IGNORE INTO group_members(thread_id, username) VALUES(?,?)', (tid, me))
    db.commit()
    # GET -> redirect back into app so user sees the group, POST -> JSON
    if request.method == 'GET':
        return redirect(url_for('chat', tid=tid))
    return jsonify({'ok':True,'thread_id':tid})

@app.route('/api/settings', methods=['POST'])
@login_required
def api_settings():
    me_id = session.get('user_id')
    me = session.get('username')
    db = get_db(); cur = db.cursor()
    # Load current row
    cur.execute('SELECT id, username, password_hash FROM users WHERE id=?', (me_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404
    data = request.get_json(silent=True) or {}
    new_username = sanitize_username((data.get('new_username') or '').strip())
    new_password = data.get('new_password') or ''
    theme = (data.get('theme') or '').strip().lower()
    bio = data.get('bio')
    # Only update status if the client explicitly sends a status field; otherwise keep existing DB value
    status_raw = data.get('status') if 'status' in data else None
    language = (data.get('language') or '').strip()
    changed = False
    
    # Username change with rollback protection
    if new_username and new_username.lower() != 'system' and new_username != (row['username'] if isinstance(row, sqlite3.Row) else row[1]):
        old_username = row['username'] if isinstance(row, sqlite3.Row) else row[1]
        
        # Validate username length (should already be sanitized, but double-check)
        if len(new_username) > 20:
            return jsonify({'error': 'username too long (max 20 characters)'}), 400
        
        # Check if username is taken
        try:
            cur.execute('SELECT 1 FROM users WHERE username=?', (new_username,))
            if cur.fetchone():
                return jsonify({'error': 'username taken'}), 400
        except Exception:
            pass
        
        # Store change history BEFORE making changes (for rollback)
        try:
            cur.execute('INSERT INTO username_change_history (user_id, old_username, new_username) VALUES (?, ?, ?)',
                       (me_id, old_username, new_username))
        except Exception:
            pass

        # Use timeout + normal SQLite transaction (avoid nested BEGIN)
        try:
            try:
                # Set a timeout for any locks (5 seconds)
                db.execute('PRAGMA busy_timeout = 5000')
            except Exception:
                pass

            try:
                # Update username in users table
                cur.execute('UPDATE users SET username=? WHERE id=?', (new_username, me_id))

                # Update username in all related tables
                cur.execute('UPDATE messages SET username=? WHERE username=?', (new_username, old_username))
                cur.execute('UPDATE direct_messages SET from_user=? WHERE from_user=?', (new_username, old_username))
                cur.execute('UPDATE direct_messages SET to_user=? WHERE to_user=?', (new_username, old_username))
                cur.execute('UPDATE group_members SET username=? WHERE username=?', (new_username, old_username))
                cur.execute('UPDATE group_threads SET created_by=? WHERE created_by=?', (new_username, old_username))

                # Commit transaction
                db.commit()
                changed = True

                # Update in-memory structures only after successful commit
                if old_username in online_users:
                    online_users[new_username] = online_users.pop(old_username)
                if old_username in ADMINS:
                    ADMINS.add(new_username); ADMINS.discard(old_username)
                if old_username in SUPERADMINS:
                    SUPERADMINS.add(new_username); SUPERADMINS.discard(old_username)
                session['username'] = new_username
                me = new_username

            except Exception as e:
                # Rollback on any error
                try:
                    db.rollback()
                except Exception:
                    pass
                # Attempt to restore old username
                try:
                    cur.execute('UPDATE users SET username=? WHERE id=?', (old_username, me_id))
                    db.commit()
                    # Mark history entry as rolled back
                    cur.execute('UPDATE username_change_history SET rolled_back=1 WHERE user_id=? AND new_username=? ORDER BY id DESC LIMIT 1',
                               (me_id, new_username))
                    db.commit()
                except Exception:
                    pass
                return jsonify({'error': f'username change failed: {str(e)}'}), 500

        except Exception as e:
            # If transaction fails entirely, try to rollback
            try:
                db.rollback()
            except Exception:
                pass
            # Attempt to restore old username
            try:
                cur.execute('UPDATE users SET username=? WHERE id=?', (old_username, me_id))
                db.commit()
                # Mark history entry as rolled back
                cur.execute('UPDATE username_change_history SET rolled_back=1 WHERE user_id=? AND new_username=? ORDER BY id DESC LIMIT 1',
                           (me_id, new_username))
                db.commit()
            except Exception:
                pass
            return jsonify({'error': f'username change failed: {str(e)}'}), 500
    if new_password:
        current_password = data.get('current_password') or ''
        pw_hash = row['password_hash'] if isinstance(row, sqlite3.Row) else row[2]
        if not current_password or not check_password_hash(pw_hash, current_password):
            return jsonify({'error': 'invalid current password'}), 403
        cur.execute('UPDATE users SET password_hash=? WHERE id=?', (generate_password_hash(new_password), me_id))
        changed = True
    if theme in ('light','dark'):
        cur.execute('UPDATE users SET theme=? WHERE id=?', (theme, me_id))
        changed = True
    if bio is not None:
        # Enforce max bio length of 300 characters
        try:
            bio = (bio or '')[:300]
        except Exception:
            bio = (bio or '')
        cur.execute('UPDATE users SET bio=? WHERE id=?', (bio, me_id))
        changed = True
    if status_raw is not None:
        status = (status_raw or '').strip().lower()
        if status in ('online','idle','dnd','offline',''):
            cur.execute('UPDATE users SET status=? WHERE id=?', (status or None, me_id))
            changed = True
    if language:
        if language not in SUPPORTED_LANGUAGE_CODES:
            language = None
        else:
            cur.execute('UPDATE users SET language=? WHERE id=?', (language, me_id))
            changed = True
    if changed:
        db.commit()
    return jsonify({'ok': True, 'username': session.get('username')})

@app.route('/api/upload/avatar', methods=['POST'])
@login_required
def api_upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'error':'file required'}), 400
    file = request.files['avatar']
    if not file.filename:
        return jsonify({'error':'empty filename'}), 400
    saved = safe_save_file(file)
    db = get_db(); cur = db.cursor()
    cur.execute('UPDATE users SET avatar=? WHERE id=?', (saved, session.get('user_id')))
    db.commit()
    return jsonify({'ok': True, 'avatar': saved, 'url': url_for('uploaded_file', filename=saved)})

@app.route('/api/delete/avatar', methods=['POST'])
@login_required
def api_delete_avatar():
    db = get_db(); cur = db.cursor()
    cur.execute('UPDATE users SET avatar=NULL WHERE id=?', (session.get('user_id'),))
    db.commit()
    return jsonify({'ok': True})

@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# Serve System avatar image from the same directory as this file
@app.route('/sys_pfp.png')
def sys_pfp_png():
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        return send_from_directory(base, 'sys_pfp.png')
    except Exception:
        abort(404)

# Moderation helpers: shadow bans
def _ensure_shadow_table():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS shadow_bans (
            username TEXT PRIMARY KEY
        )''')
        db.commit()
    except Exception:
        pass

def is_shadow_banned(user: str) -> bool:
    try:
        _ensure_shadow_table()
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM shadow_bans WHERE username=?', (user,))
        return cur.fetchone() is not None
    except Exception:
        return False

def set_shadow_ban(user: str):
    try:
        _ensure_shadow_table()
        db = get_db(); cur = db.cursor()
        cur.execute('INSERT OR IGNORE INTO shadow_bans(username) VALUES(?)', (user,))
        db.commit(); return True
    except Exception:
        return False

def clear_shadow_ban(user: str):
    try:
        _ensure_shadow_table()
        db = get_db(); cur = db.cursor()
        cur.execute('DELETE FROM shadow_bans WHERE username=?', (user,))
        db.commit(); return True
    except Exception:
        return False

@app.route("/preview/<path:filename>")
@login_required
def preview(filename):
    fpath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(fpath):
        abort(404)
    
    ext = filename.rsplit(".", 1)[-1].lower()
    if ext in PREVIEW_EXTS:
        return send_from_directory(UPLOAD_FOLDER, filename)
    
    if ext == ZIP_EXT:
        try:
            with zipfile.ZipFile(fpath, "r") as zf:
                members = zf.namelist()
        except:
            return "<h3>Bad ZIP file</h3>", 400
        
        links = ''.join(f'<li><a href="/preview/zipfile/{filename}/{m}" target="_blank">{m}</a></li>' for m in members)
        return f"<html><body><ul>{links}</ul></body></html>"
    
    return send_from_directory(UPLOAD_FOLDER, filename)

# Socket.IO events
@socketio.on("connect")
def on_connect():
    username = session.get("username")
    if username:
        client_ip = get_client_ip()
        if is_banned(username) or is_ip_banned(client_ip):
            disconnect()
            return
        
        online_users[username] = time.time()
        user_ips[username] = client_ip
        connected_sockets[request.sid] = username
        join_room("chat_room")
        # Join per-user room for DMs
        try:
            join_room(f"user:{username}")
        except Exception:
            pass
        emit("user_joined", {"username": username, "online_count": len(online_users)}, room="chat_room")
        emit("user_list_refresh", {"username": username})
        # Cleanup stale typing entries and broadcast current list
        _cleanup_typing()
        emit("typing", {"users": _current_typing_list(exclude=None)}, room=request.sid)

@socketio.on("disconnect")
def on_disconnect():
    username = connected_sockets.get(request.sid)
    if username:
        del connected_sockets[request.sid]
        if username in online_users:
            del online_users[username]
        # Remove typing state on disconnect
        if username in typing_users:
            typing_users.pop(username, None)
            emit("typing", {"users": _current_typing_list(exclude=None)})
        leave_room("chat_room")
        # Leave per-user DM room
        try:
            leave_room(f"user:{username}")
        except Exception:
            pass
        emit("user_left", {"username": username, "online_count": len(online_users)}, room="chat_room")

# Group DM sockets
@socketio.on('gdm_join')
def on_gdm_join(data):
    me = session.get('username')
    try:
        tid = int((data or {}).get('thread_id', 0))
    except Exception:
        tid = 0
    if not me or not tid:
        return
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return
    # Join is allowed even when locked/archived; posting is gated in send/edit/delete
    join_room(f'gdm:{tid}')

def on_gdm_send_v1(data):
    me = session.get('username')
    try:
        if _emergency_write_block(me):
            return
    except Exception:
        pass
    try:
        tid = int((data or {}).get('thread_id', 0))
    except Exception:
        pass
    # Platform gates
    try:
        if get_setting('MAINTENANCE_MODE','0')=='1':
            return
        if get_setting('GDM_ENABLED','1')=='0':
            return
    except Exception:
        pass

    # Comprehensive anti-spam checking
    text = (data or {}).get("text", "").strip()
    has_attachment = bool((data or {}).get("filename"))
    spam_ok, spam_msg, split_chunks = _spam_comprehensive_gate("gdm", me, text, has_attachment=has_attachment, get_setting_func=get_setting)
    if not spam_ok:
        try:
            emit("system_message", spam_msg, room=f"user:{me}")
        except Exception:
            pass
        return

    text = (data or {}).get('text', '').strip()
    if not me or not tid or not (text or (data or {}).get('filename')):
        return
    # update presence activity
    try:
        online_users[me] = time.time()
    except Exception:
        pass
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return
    # Enforce bans/timeouts
    try:
        cur.execute('SELECT 1 FROM group_bans WHERE thread_id=? AND username=?', (tid, me))
        if cur.fetchone():
            return
        cur.execute('SELECT until_ts FROM group_timeouts WHERE thread_id=? AND username=?', (tid, me))
        r = cur.fetchone()
        if r:
            until_ts = r[0] if not isinstance(r, sqlite3.Row) else r['until_ts']
            if until_ts and until_ts > int(time.time()):
                return
            # If user currently timed out, re-send the timeout gate
            try:
                until = user_timeouts.get(u) or 0
                if until and time.time() < float(until):
                    emit('timeout_set', { 'until': int(until) }, room=f'user:{u}')
            except Exception:
                pass
            else:
                cur.execute('DELETE FROM group_timeouts WHERE thread_id=? AND username=?', (tid, me))
                db.commit()
    except Exception:
        pass
    # Enforce locked/archived for posting: allow owner or superadmin only
    try:
        cur.execute('SELECT COALESCE(locked,0), COALESCE(archived,0), created_by FROM group_threads WHERE id=?', (tid,))
        rr = cur.fetchone(); locked=(rr[0] if rr else 0); archived=(rr[1] if rr else 0)
        owner = (rr[2] if rr else None) if not isinstance(rr, sqlite3.Row) else rr['created_by']
        if (locked or archived) and not (is_superadmin(me) or (owner and owner==me)):
            return
    except Exception:
        pass
    # Owner/Superadmin commands
    if text.startswith("/"):
        # Handle admin and superadmin commands
        parts = text[1:].split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:]
        # /help for admins and above
        if cmd == 'help' and (is_admin(me) or is_superadmin(me)):
            help_cmds = []
            try:
                if get_setting('MC_PURGE_CHANNEL','1')=='1':
                    help_cmds.append('/clearall')
                    help_cmds.extend(['/clearall','/clear <N>'])
            except Exception:
                help_cmds.extend(['/clearall','/clear <N>'])
            # Kick
            try:
                if get_setting('GD_REMOVE_USER','1')=='1':
                    help_cmds.append('/kick <user>')
            except Exception:
                help_cmds.append('/kick <user>')
            # Ban/Unban
            try:
                if get_setting('UM_BAN_USER','1')=='1':
                    help_cmds.extend(['/ban <user>','/unban <user>'])
            except Exception:
                help_cmds.extend(['/ban <user>','/unban <user>'])
            # Timeout
            try:
                if get_setting('UM_TIMEOUT_USER','1')=='1':
                    help_cmds.append('/timeout <user> [minutes]')
            except Exception:
                help_cmds.append('/timeout <user> [minutes]')
            # IP
            if is_superadmin(me):
                help_cmds.extend(['/ipban <user>','/ipbanip <ip>','/ipunban <user>'])
            emit('system_message', store_system_message('Group commands:\n' + "\n".join(help_cmds)))
            return
        if cmd == 'clearall':
            cur.execute('DELETE FROM group_messages WHERE thread_id=?', (tid,))
            db.commit()
            emit('gdm_cleared', {'thread_id': tid}, room=f'gdm:{tid}')
            return
        if cmd == 'ban' and args:
            user = sanitize_username(args[0])
            if user:
                try:
                    cur.execute('INSERT OR IGNORE INTO group_bans(thread_id, username) VALUES(?,?)', (tid, user))
                    cur.execute('DELETE FROM group_members WHERE thread_id=? AND username=?', (tid, user))
                    db.commit()
                    emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{user}')
                    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
                    for r2 in cur.fetchall():
                        emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{r2[0]}')
                except Exception:
                    pass
            return
        if cmd == 'timeout' and args:
            user = sanitize_username(args[0])
            mins = 5
            if len(args) >= 2:
                try:
                    mins = max(1, int(args[1]))
                except Exception:
                    mins = 5
            until = int(time.time()) + mins*60
            try:
                cur.execute('INSERT OR REPLACE INTO group_timeouts(thread_id, username, until_ts) VALUES(?,?,?)', (tid, user, until))
                db.commit()
            except Exception:
                pass
            return
    attachment = None
    if data.get('filename') and data.get('content'):
        attachment = safe_save_file_from_b64(data['filename'], data['content'])
        if attachment is None:
            try:
                emit('system_message', "Attachment failed to upload (invalid or too large)", room=f'user:{me}')
            except Exception:
                pass
    safe_text = render_markdown(text)
    try:
        rid = int((data or {}).get('reply_to') or 0)
    except Exception:
        rid = 0
    ruser=None; rsnippet=None
    if rid:
        try:
            cur.execute('SELECT username, text FROM group_messages WHERE id=? AND thread_id=?', (rid, tid))
            rr = cur.fetchone()
            if rr:
                ruser = rr[0] if not isinstance(rr, sqlite3.Row) else rr['username']
                rhtml = rr[1] if not isinstance(rr, sqlite3.Row) else rr['text']
                try:
                    plain = re.sub(r'<[^>]+>', '', rhtml or '')
                except Exception:
                    plain = (rhtml or '')
                rsnippet = (plain or '')[:140]
        except Exception:
            rid = 0
    cur.execute('INSERT INTO group_messages (thread_id, username, text, attachment, created_at, edited, reply_to) VALUES (?,?,?,?,?,0,?)', (tid, me, safe_text, attachment, datetime.utcnow(), (rid or None)))
    msg_id = cur.lastrowid
    get_db().commit()
    # Enforce message lifespan for group messages if enabled
    try:
        if get_setting('MC_MESSAGE_LIFESPAN','0')=='1':
            days_s = get_setting('MC_MESSAGE_LIFESPAN_DAYS','0') or '0'
            days = int(days_s or '0')
            if days > 0:
                cutoff = datetime.utcnow() - timedelta(days=days)
                cur.execute('DELETE FROM group_messages WHERE created_at < ?', (cutoff,))
                get_db().commit()
    except Exception:
        pass
    # Emit to all members (cross-view) via per-user rooms for unread counting
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    payload = {
        'id': msg_id,
        'thread_id': tid,
        'username': me,
        'text': safe_text,
        'attachment': attachment,
        'created_at': to_ny_time(datetime.utcnow()),
        'edited': 0,
        'reply_to': (rid or None),
        'reply_username': ruser,
        'reply_snippet': rsnippet,
    }
    # Shadow ban: only echo to sender; otherwise emit to all members
    try:
        if is_shadow_banned(me):
            socketio.emit('gdm_new', payload, room=f'user:{me}')
        else:
            for u in members:
                socketio.emit('gdm_new', payload, room=f'user:{u}')
    except Exception:
        for u in members:
            socketio.emit('gdm_new', payload, room=f'user:{u}')

@socketio.on('gdm_edit')
def on_gdm_edit(data):
    me = session.get('username')
    try:
        if _emergency_write_block(me):
            return
    except Exception:
        pass
    try:
        mid = int((data or {}).get('id', 0))
    except Exception:
        mid = 0
    new_text = (data or {}).get('text', '')
    if not me or not mid:
        return
    try:
        if _emergency_write_block(me):
            return
    except Exception:
        pass
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT thread_id, username, text FROM group_messages WHERE id=?', (mid,))
    row = cur.fetchone()
    if not row:
        return
    tid, author, old_html = row[0], row[1], row[2] or ''
    # Enforce locked/archived (allow owner or superadmin)
    try:
        cur.execute('SELECT COALESCE(locked,0), COALESCE(archived,0), created_by FROM group_threads WHERE id=?', (tid,))
        rr = cur.fetchone(); locked=(rr[0] if rr else 0); archived=(rr[1] if rr else 0)
        owner = (rr[2] if rr else None) if not isinstance(rr, sqlite3.Row) else rr['created_by']
        if (locked or archived) and not (is_superadmin(me) or (owner and owner==me)):
            return
    except Exception:
        pass
    if not (author == me or is_admin(me) or is_superadmin(me)):
        return
    # If admin editing others, respect MC_EDIT_MESSAGES toggle
    if author != me and (is_admin(me) or is_superadmin(me)):
        try:
            if get_setting('MC_EDIT_MESSAGES','1')=='0':
                return
        except Exception:
            pass
    safe_text = render_markdown(new_text or '')
    if (old_html or '') == (safe_text or ''):
        return
    cur.execute('UPDATE group_messages SET text=?, edited=1 WHERE id=?', (safe_text, mid))
    get_db().commit()
    emit('gdm_edit', {'id': mid, 'text': safe_text}, room=f'gdm:{tid}')

@socketio.on('gdm_delete')
def on_gdm_delete(data):
    me = session.get('username')
    try:
        mid = int((data or {}).get('id', 0))
    except Exception:
        mid = 0
    if not me or not mid:
        return
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT thread_id, username FROM group_messages WHERE id=?', (mid,))
    row = cur.fetchone()
    if not row:
        return
    tid, author = row[0], row[1]
    # Enforce locked/archived
    try:
        cur.execute('SELECT COALESCE(locked,0), COALESCE(archived,0) FROM group_threads WHERE id=?', (tid,))
        rr = cur.fetchone(); locked=(rr[0] if rr else 0); archived=(rr[1] if rr else 0)
        if (locked or archived) and not is_superadmin(me):
            return
    except Exception:
        pass
    if not (author == me or is_admin(me) or is_superadmin(me)):
        return
    cur.execute('DELETE FROM group_messages WHERE id=?', (mid,))
    get_db().commit()
    emit('gdm_delete', mid, room=f'gdm:{tid}')

@socketio.on("send_message")
def on_send_message(data):
    username = session.get("username")
    if not username:
        return
    # Emergency shutdown: block new public messages for non-superadmins
    try:
        if _emergency_write_block(username):
            return
    except Exception:
        pass
    # User must exist in DB; otherwise disconnect and ignore
    try:
        if not _session_user_valid():
            try: socketio.server.disconnect(request.sid)
            except Exception: pass
            return
    except Exception:
        pass

    # Enforce IP bans (private first then public)
    try:
        priv, pub = detect_client_ips()
        _update_user_ips(username, priv, pub)
        if _is_ip_blocked_for(username, priv, pub):
            try:
                emit("system_message", "Your IP is banned", room=f'user:{username}')
            except Exception:
                pass
            try:
                socketio.server.disconnect(request.sid)
            except Exception:
                pass
            return
    except Exception:
        pass
    
    if is_banned(username):
        try:
            emit("system_message", "You are banned and cannot send messages", room=f'user:{username}')
        except Exception:
            pass
        disconnect()
        return
    
    client_ip = get_client_ip()
    if is_ip_banned(client_ip):
        try:
            emit("system_message", "Your IP is banned", room=f'user:{username}')
        except Exception:
            pass
        disconnect()
        return
    
    online_users[username] = time.time()
    
    # Check timeout
    if username in user_timeouts and user_timeouts[username] > time.time():
        try:
            emit("system_message", "You are timed out", room=f'user:{username}')
        except Exception:
            pass
        return

    # Determine admin privilege once
    try:
        adminish = bool(is_superadmin(username) or _is_adminish(username))
    except Exception:
        adminish = False
    # Platform gates for public chat
    try:
        if get_setting('MAINTENANCE_MODE','0')=='1':
            return
        if get_setting('PUBLIC_ENABLED','1')=='0':
            return
        if get_setting('ANNOUNCEMENTS_ONLY','0')=='1' and not adminish:
            return

    except Exception:
        pass
    # Comprehensive anti-spam checking
    text = (data or {}).get("text", "").strip()
    has_attachment = bool((data or {}).get("filename"))
    spam_ok, spam_msg, split_chunks = _spam_comprehensive_gate("public", username, text, has_attachment=has_attachment, get_setting_func=get_setting)
    if not spam_ok:
        try:
            emit("system_message", spam_msg, room=f"user:{username}")
        except Exception:
            pass
        return

    text = (data.get("text") or "").strip()
    attachment = None
    
    if data.get("filename") and data.get("content"):
        attachment = safe_save_file_from_b64(data["filename"], data["content"])
        if attachment is None:
            try:
                emit("system_message", "Attachment failed to upload (invalid or too large)", room=f'user:{username}')
            except Exception:
                pass

    # Admin commands (admins and superadmins)
    if text.startswith('/') and adminish:
        parts = text[1:].split()
        cmd = parts[0].lower()
        args = parts[1:]
        db = get_db()
        cur = db.cursor()
        # Dynamic help (toggle-aware)
        if cmd == 'help':
            help_cmds = []
            # Clear/purge
            try:
                if get_setting('MC_PURGE_CHANNEL','1')=='1':
                    help_cmds.extend(['/clearall','/clear <N>'])
            except Exception:
                help_cmds.extend(['/clearall','/clear <N>'])
            # Ban/Unban
            try:
                if get_setting('UM_BAN_USER','1')=='1':
                    help_cmds.extend(['/ban <user>','/unban <user>'])
            except Exception:
                help_cmds.extend(['/ban <user>','/unban <user>'])
            # Timeout
            try:
                if get_setting('UM_TIMEOUT_USER','1')=='1':
                    help_cmds.extend(['/timeout <user> <minutes>','/timeoutremove <user>'])
            except Exception:
                help_cmds.extend(['/timeout <user> <minutes>','/timeoutremove <user>'])
            # IP/admin tools (SA)
            if is_superadmin(username):
                help_cmds.extend(['/ipban <user>','/ipbanip <ip> (ban raw IP)','/ipunban <ip>','/ipof <user>','/addadmin <user>','/rmadmin <user>'])
            emit("system_message", store_system_message("Commands:\n" + "\n".join(help_cmds)))
            return
        
        if cmd == 'clearall':
            # Toggle gate
            try:
                if get_setting('MC_PURGE_CHANNEL','1')=='0':
                    return
            except Exception:
                pass
            cur.execute("DELETE FROM messages")
            db.commit()
            socketio.emit("clear_all", room='chat_room')
            socketio.emit("system_message", store_system_message(f"All messages cleared by {username}"), room='chat_room')
            return
        
        elif cmd == 'clear' and args:
            # Toggle gate
            try:
                if get_setting('MC_PURGE_CHANNEL','1')=='0':
                    return
            except Exception:
                pass
            try:
                n = int(args[0])
                # Find IDs first for realtime UI update
                cur.execute("SELECT id FROM messages ORDER BY id DESC LIMIT ?", (n,))
                ids = [r[0] for r in cur.fetchall()]
                if ids:
                    cur.execute("DELETE FROM messages WHERE id IN ({})".format(
                        ",".join(["?"]*len(ids))
                    ), tuple(ids))
                db.commit()
                # Realtime remove
                if ids:
                    socketio.emit("messages_deleted", { 'ids': ids }, room='chat_room')
                socketio.emit("system_message", store_system_message(f"Last {n} messages cleared by {username}"), room='chat_room')
            except:
                pass
            return
        
        elif cmd == 'ban' and args:
            target = args[0]
            if not _can_ban(username, target):
                emit("system_message", store_system_message("You are not allowed to ban this user"))
                return
            # True ban: ban user, their latest device, and associated IPs (private/public) if known
            cur.execute("INSERT OR IGNORE INTO banned_users(username) VALUES (?)", (target,))
            # From online cache
            info = user_ips.get(target) if isinstance(user_ips.get(target), dict) else {}
            try:
                # Ban device if known
                cid = (info.get('client_id') or '').strip()
                if not cid:
                    try:
                        cur.execute('SELECT client_id FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (target,))
                        r = cur.fetchone(); cid = (r[0] if r else '') if not isinstance(r, sqlite3.Row) else (r['client_id'] if r else '')
                    except Exception:
                        cid = ''
                if cid:
                    cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (cid, target))
                # Ban IPs if known
                priv = (info.get('private') or '')
                pub = (info.get('public') or '')
                if not (priv or pub):
                    try:
                        cur.execute('SELECT private_ip, public_ip FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (target,))
                        r = cur.fetchone()
                        if r:
                            priv = r[0] if not isinstance(r, sqlite3.Row) else r['private_ip']
                            pub = r[1] if not isinstance(r, sqlite3.Row) else r['public_ip']
                    except Exception:
                        pass
                for ip in [priv, pub]:
                    if ip:
                        cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (ip,))
            except Exception:
                pass
            db.commit()
            emit("system_message", store_system_message(f"{target} was banned by {username}"))
            for sid, uname in list(connected_sockets.items()):
                if uname == target:
                    socketio.server.disconnect(sid)
            return
        
        elif cmd == 'unban' and args:
            target = args[0]
            if not _can_unban(username, target):
                emit("system_message", store_system_message("You are not allowed to unban this user"))
                return
            cur.execute("DELETE FROM banned_users WHERE username=?", (target,))
            db.commit()
            emit("system_message", store_system_message(f"{target} was unbanned by {username}"))
            return
        
        elif cmd == 'ipban' and args:
            target = args[0]
            mode = (args[1].lower() if len(args) > 1 else 'auto') if args else 'auto'
            info = user_ips.get(target) or {}
            if not isinstance(info, dict):
                info = {'private': None, 'public': info}
            priv = info.get('private')
            pub = info.get('public')
            if not (priv or pub):
                emit("system_message", store_system_message(f"Cannot find IPs for {target} (user not online)"))
                return
            # Auto selection: default public; if same public is shared by a mix of admins and non-admins, prefer private
            use_ip = pub
            if mode == 'private':
                use_ip = priv or pub
            elif mode == 'public':
                use_ip = pub or priv
            else:  # auto
                try:
                    if pub:
                        holders = [u for u, d in user_ips.items() if isinstance(d, dict) and d.get('public') == pub]
                        has_admin = any((u in ADMINS or u in SUPERADMINS) for u in holders)
                        has_user = any((u not in ADMINS and u not in SUPERADMINS) for u in holders)
                        if has_admin and has_user and priv:
                            use_ip = priv
                except Exception:
                    pass
            if not use_ip:
                emit("system_message", store_system_message("No suitable IP to ban"))
                return
            if use_ip in ("127.0.0.1", "::1"):
                emit("system_message", store_system_message("Refusing to ban loopback IP (localhost) for all users"))
                return
            if not _can_ban(username, target):
                emit("system_message", store_system_message("You are not allowed to IP-ban this user"))
                return
            # Allow superadmins to ban any IP, block non-superadmins from banning admin/superadmin IPs
            try:
                holders = []
                for u, d in user_ips.items():
                    if isinstance(d, dict) and (d.get('public') == use_ip or d.get('private') == use_ip):
                        holders.append(u)
                if not is_superadmin(username):
                    if any(u in SUPERADMINS for u in holders):
                        emit("system_message", store_system_message("Refusing to IP-ban: IP belongs to a superadmin online"))
                        return
                    if any(u in ADMINS for u in holders):
                        emit("system_message", store_system_message("Refusing to IP-ban: IP belongs to an admin online"))
                        return
            except Exception:
                pass
            # Apply ban
            cur.execute("INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)", (use_ip,))
            db.commit(); banned_ips.add(use_ip)
            emit("system_message", store_system_message(f"IP {use_ip} banned by {username}"))
            # Disconnect sessions matching either private or public
            for sid, uname in list(connected_sockets.items()):
                try:
                    d = user_ips.get(uname) if isinstance(user_ips.get(uname), dict) else {'public': user_ips.get(uname), 'private': None}
                    if d and (d.get('public') == use_ip or d.get('private') == use_ip):
                        socketio.server.disconnect(sid)
                except Exception:
                    pass
            return
        
        elif cmd == 'ipunban' and args:
            ip_address = args[0]
            cur.execute("DELETE FROM banned_ips WHERE ip_address= ?", (ip_address,))
            db.commit()
            try:
                banned_ips.discard(ip_address)
            except Exception:
                pass
            emit("system_message", store_system_message(f"An IP was unbanned by {username}"))
            return

        elif cmd == 'ipunbanuser' and args:
            target = sanitize_username(args[0])
            ip = user_ips.get(target)
            if not ip:
                emit("system_message", store_system_message(f"No IP found for {target} (user offline)"))
                return
            if ip in ("127.0.0.1", "::1"):
                emit("system_message", store_system_message("Refusing to unban loopback (no need)"))
                return
            cur.execute("DELETE FROM banned_ips WHERE ip_address=?", (ip,))
            db.commit()
            banned_ips.discard(ip)
            emit("system_message", store_system_message(f"IP of {target} was unbanned by {username}"))
            return

        elif cmd == 'addadmin' and args:
            # Superadmin only
            if not is_superadmin(username):
                emit("system_message", store_system_message("Only superadmins can manage admins"))
                return
            target = sanitize_username(args[0])
            if not target or target in SUPERADMINS:
                emit("system_message", store_system_message("Cannot add superadmin or empty user"))
                return
            # Persist to extra_admins and in-memory set
            try:
                db = get_db(); cur = db.cursor()
                cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
                cur.execute('INSERT OR REPLACE INTO extra_admins(username, created_at, created_by) VALUES(?,?,?)', (target, datetime.utcnow().isoformat(), username))
                db.commit()
            except Exception:
                pass
            ADMINS.add(target)
            try:
                merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
            except Exception:
                merged = sorted(list(ADMINS))
            emit("system_message", store_system_message(f"{target} was granted admin by {username}"))
            emit('admin_list', {'admins': merged})
            return

        elif cmd == 'rmadmin' and args:
            # Superadmin only
            if not is_superadmin(username):
                emit("system_message", store_system_message("Only superadmins can manage admins"))
                return
            target = sanitize_username(args[0])
            if not target:
                return
            # Remove from extra_admins and in-memory set
            try:
                db = get_db(); cur = db.cursor()
                cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
                cur.execute('DELETE FROM extra_admins WHERE username=?', (target,))
                db.commit()
            except Exception:
                pass
            if target in ADMINS:
                ADMINS.discard(target)
                emit("system_message", store_system_message(f"{target} admin role removed by {username}"))
            else:
                emit("system_message", store_system_message(f"{target} is not an admin"))
            try:
                merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
            except Exception:
                merged = sorted(list(ADMINS))
            emit('admin_list', {'admins': merged})
            return
        
        elif cmd == 'ipof' and args:
            # Show the current IP of a user (online users only)
            target = sanitize_username(args[0])
            info = user_ips.get(target) or {}
            if isinstance(info, dict):
                priv = info.get('private') or ''
                pub = info.get('public') or ''
                emit("system_message", store_system_message(f"IPs of {target} — private: {priv or 'n/a'}, public: {pub or 'n/a'}"))
            else:
                ip = info or ''
                if ip:
                    emit("system_message", store_system_message(f"IP of {target} is {ip}"))
                else:
                    emit("system_message", store_system_message(f"No IP found for {target} (user offline)"))
            return
        
        elif cmd == 'ipbanip' and args:
            # Ban a raw IP directly
            ip = args[0].strip()
            if not ip:
                return
            if ip in ("127.0.0.1", "::1"):
                emit("system_message", store_system_message("Refusing to ban loopback IP (localhost) for all users"))
                return
            # Protect superadmins; allow superadmin to ban admins
            try:
                holders = []
                for u, d in user_ips.items():
                    if isinstance(d, dict):
                        if d.get('public') == ip or d.get('private') == ip:
                            holders.append(u)
                if any(u in SUPERADMINS for u in holders) and not _can_ipban_superadmin_ips(username):
                    emit("system_message", store_system_message("Refusing to IP-ban: IP belongs to a superadmin online"))
                    return
                if not is_superadmin(username) and any(u in ADMINS for u in holders):
                    emit("system_message", store_system_message("Refusing to IP-ban: IP belongs to an admin online"))
                    return
            except Exception:
                pass
            db = get_db(); cur = db.cursor()
            cur.execute("INSERT OR IGNORE INTO banned_ips(ip_address) VALUES (?)", (ip,))
            db.commit(); banned_ips.add(ip)
            emit("system_message", store_system_message(f"An IP was banned by {username}"))
            # Disconnect all users with this IP
            for sid, uname in list(connected_sockets.items()):
                ud = user_ips.get(uname) or {}
                try:
                    if isinstance(ud, dict) and (ud.get('public') == ip or ud.get('private') == ip):
                        socketio.server.disconnect(sid)
                except Exception:
                    pass
            return

        elif cmd == 'setipbanoverseer' and args:
            # Superadmin-only: set the special overseer allowed to IP-ban superadmin IPs
            if not is_superadmin(username):
                emit("system_message", store_system_message("Only superadmins can set the IP-ban overseer"))
                return
            target = sanitize_username(args[0])
            if not target:
                emit("system_message", store_system_message("Provide a valid username"))
                return
            ok = _set_overseer_by_username(target)
            if ok:
                emit("system_message", store_system_message(f"IP-ban overseer is now {target}"))
            else:
                emit("system_message", store_system_message("Failed to set overseer (user not found?)"))
            return

        elif cmd == 'timeout' and len(args) >= 2:
            target = args[0]
            seconds = int(args[1])
            user_timeouts[target] = time.time() + seconds
            emit("system_message", store_system_message(f"{target} timed out for {seconds} seconds by {username}"))
            return
        
        elif cmd == 'untimeout' and args:
            target = args[0]
            if target in user_timeouts:
                user_timeouts.pop(target)
            emit("system_message", store_system_message(f"{target} timeout removed by {username}"))
            try:
                emit('timeout_removed', {}, room=f'user:{target}')
            except Exception:
                pass
            return
        
        elif cmd == 'cleartxt':
            # SUPERADMIN only: clear the text log file chat_messages.txt
            if is_superadmin(username):
                try:
                    with open(LOG_FILE, 'w', encoding='utf-8') as f:
                        pass
                except Exception:
                    pass
                emit("system_message", store_system_message(f"Message log cleared by {username}"))
            else:
                emit("system_message", store_system_message("You are not authorized to use /cleartxt"))
            return
        else:
            emit("system_message", store_system_message(f"Unknown command: {text}"))
            return

    # Normal message with Markdown
    if text or attachment:
        # Server-side debounce: ignore exact same content from same user within 500ms
        try:
            now = time.time()
            key = username or ''
            last = user_last_send.get(key)
            sig = (text or '').strip() + '|' + (attachment or '')
            if last and last[0] == sig and (now - last[1]) < 0.5:
                return
            user_last_send[key] = (sig, now)
        except Exception:
            pass
        db = get_db(); cur = db.cursor()
        safe_text = render_markdown(text)
        try:
            rid = int((data or {}).get('reply_to') or 0)
        except Exception:
            rid = 0
        ruser = None
        rsnippet = None
        if rid:
            try:
                cur.execute('SELECT username, text FROM messages WHERE id=?', (rid,))
                rr = cur.fetchone()
                if rr:
                    ruser = rr[0] if not isinstance(rr, sqlite3.Row) else rr['username']
                    rhtml = rr[1] if not isinstance(rr, sqlite3.Row) else rr['text']
                    try:
                        plain = re.sub(r'<[^>]+>', '', rhtml or '')
                    except Exception:
                        plain = (rhtml or '')
                    rsnippet = (plain or '')[:140]
            except Exception:
                rid = 0
        cur.execute("""
            INSERT INTO messages (user_id, username, text, attachment, created_at, reply_to) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session.get("user_id"), username, safe_text, attachment, datetime.utcnow(), (rid or None)))
        db.commit()
        msg_id = cur.lastrowid
        # Enforce message lifespan if enabled
        try:
            if get_setting('MC_MESSAGE_LIFESPAN','0')=='1':
                days_s = get_setting('MC_MESSAGE_LIFESPAN_DAYS','0') or '0'
                days = int(days_s or '0')
                if days > 0:
                    cutoff = datetime.utcnow() - timedelta(days=days)
                    cur.execute('DELETE FROM messages WHERE created_at < ?', (cutoff,))
                    db.commit()
        except Exception:
            pass
        try:
            ts = _format_web_timestamp(datetime.utcnow())
            line = f"[{ts}] NEW id={msg_id} user={username}: {_plain_text_from_html(safe_text)}"
            if attachment:
                line += f" [ATTACH: {attachment}]"
            _append_log_line(line)
        except Exception:
            pass
        
        message_data = {
            "id": msg_id,
            "user_id": session["user_id"],
            "username": username,
            "text": safe_text,
            "attachment": attachment,
            "created_at": to_ny_time(datetime.utcnow()),
            "reply_to": (rid or None),
            "reply_username": ruser,
            "reply_snippet": rsnippet
        }
        # Broadcast to all users in public chat (shadow-banned users only see their own)
        try:
            if is_shadow_banned(username):
                socketio.emit("new_message", message_data, room=f'user:{username}')
            else:
                socketio.emit("new_message", message_data, room='chat_room')
        except Exception:
            socketio.emit("new_message", message_data, room='chat_room')
        # Message sent -> user is not typing anymore
        if username in typing_users:
            typing_users.pop(username, None)
            socketio.emit("typing", {"users": _current_typing_list(exclude=None)})

@socketio.on("gdm_send")
def on_gdm_send(data):
    username = session.get("username")
    if not username:
        return
    # Reject if user missing from DB
    try:
        if not _session_user_valid():
            try: socketio.server.disconnect(request.sid)
            except Exception: pass
            return
    except Exception:
        pass
    return on_gdm_send_v1(data)

@socketio.on('connect')
def on_connect():
    try:
        # Reject sockets for users that no longer exist
        if not _session_user_valid():
            try:
                socketio.server.disconnect(request.sid)
            except Exception:
                pass
            return
        join_room('chat_room')
        u = session.get('username')
        if u:
            join_room(f'user:{u}')
            connected_sockets[request.sid] = u
            online_users[u] = time.time()
            # Update IPs and enforce bans
            priv, pub = detect_client_ips()
            _update_user_ips(u, priv, pub)
            if _is_ip_blocked_for(u, priv, pub):
                try:
                    emit("system_message", store_system_message("Your IP is banned"), room=f'user:{u}')
                except Exception:
                    pass
                try:
                    socketio.server.disconnect(request.sid)
                except Exception:
                    pass
                return
            try:
                socketio.emit('user_list_refresh', { 'online': u })
            except Exception:
                pass
    except Exception:
        pass

@socketio.on('disconnect')
def on_disconnect():
    try:
        sid = request.sid
        u = connected_sockets.pop(sid, None)
        if u:
            # If no more sockets for this user, mark offline
            if u not in connected_sockets.values():
                try:
                    online_users.pop(u, None)
                except Exception:
                    pass
                try:
                    socketio.emit('user_list_refresh', { 'offline': u })
                except Exception:
                    pass
    except Exception:
        pass

@socketio.on("delete_message")
def on_delete_message(mid):
    username = session.get("username")
    try:
        if _emergency_write_block(username):
            return
    except Exception:
        pass
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM messages WHERE id= ?", (mid,))
    row = cur.fetchone()
    
    if not row:
        return
    author = row[0] if not isinstance(row, sqlite3.Row) else row["username"]
    # Authors can always delete their own
    if author == username:
        cur.execute("DELETE FROM messages WHERE id= ?", (mid,))
        db.commit(); socketio.emit("delete_message", mid, room='chat_room'); return
    # Admins/superadmins deleting others must respect MC_DELETE_MESSAGES
    if is_admin(username) or is_superadmin(username):
        try:
            if get_setting('MC_DELETE_MESSAGES','1')=='0':
                return
        except Exception:
            pass
        cur.execute("DELETE FROM messages WHERE id= ?", (mid,))
        db.commit(); socketio.emit("delete_message", mid, room='chat_room')

@socketio.on("edit_message")
def on_edit_message(data):
    username = session.get("username")
    try:
        mid = int((data or {}).get("id", 0))
    except Exception:
        mid = 0
    new_text = (data or {}).get("text", "")
    if not username or not mid:
        return
    try:
        if _emergency_write_block(username):
            return
    except Exception:
        pass
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT username, text FROM messages WHERE id=?", (mid,))
    row = cur.fetchone()
    if not row:
        return
    author = row[0] if not isinstance(row, sqlite3.Row) else row["username"]
    old_html = row[1] if not isinstance(row, sqlite3.Row) else (row["text"] or "")
    # Permission: author can edit; superadmins can edit anyone; admins can edit non-admins
    can_admin_edit = (username in ADMINS) and (author not in ADMINS or username in SUPERADMINS)
    if not (author == username or (username in SUPERADMINS) or can_admin_edit):
        return
    # If admin editing others, respect MC_EDIT_MESSAGES toggle
    if author != username and (username in ADMINS or username in SUPERADMINS):
        try:
            if get_setting('MC_EDIT_MESSAGES','1')=='0':
                return
        except Exception:
            pass
    safe_text = render_markdown(new_text or "")
    if (old_html or "") == (safe_text or ""):
        return
    cur.execute("UPDATE messages SET text=? WHERE id=?", (safe_text, mid))
    db.commit()
    socketio.emit("edit_message", {"id": mid, "text": safe_text}, room='chat_room')

@socketio.on("dm_send")
def on_dm_send(data):
    username = session.get("username")
    if not username:
        return
    try:
        if _emergency_write_block(username):
            return
    except Exception:
        pass
    # Reject if user missing from DB
    try:
        if not _session_user_valid():
            try: socketio.server.disconnect(request.sid)
            except Exception: pass
            return
    except Exception:
        pass
    # Platform gates
    try:
        if get_setting('MAINTENANCE_MODE','0')=='1':
            return
        if get_setting('DM_ENABLED','1')=='0':
            return
    except Exception:
        pass

    # Comprehensive anti-spam checking
    text = (data or {}).get("text", "").strip()
    has_attachment = bool((data or {}).get("filename"))
    spam_ok, spam_msg, split_chunks = _spam_comprehensive_gate("dm", username, text, has_attachment=has_attachment, get_setting_func=get_setting)
    if not spam_ok:
        try:
            emit("system_message", spam_msg, room=f"user:{username}")
        except Exception:
            pass
        return

    to_user = (data or {}).get("to", "").strip()
    text = (data or {}).get("text", "").strip()
    if not to_user or not (text or (data or {}).get("filename")):
        return
    # Admin DM commands
    if text.startswith('/') and (is_admin(username) or is_superadmin(username)):
        parts = text[1:].split()
        cmd = parts[0].lower() if parts else ''
        if cmd == 'help':
            emit('dm_new', { 'id': int(time.time()*1000)%2147483647, 'from_user': 'System', 'to_user': username, 'text': render_markdown('DM commands:\n/clearall'), 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }, room=f'user:{username}')
            return
        if cmd == 'clearall' and is_superadmin(username):
            db = get_db(); cur = db.cursor()
            cur.execute('DELETE FROM direct_messages WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)', (username, to_user, to_user, username))
            db.commit()
            emit('dm_cleared', {'peer': to_user}, room=f'user:{username}')
            emit('dm_cleared', {'peer': username}, room=f'user:{to_user}')
            return
    # update presence activity
    try:
        online_users[username] = time.time()
    except Exception:
        pass
    attachment = None
    if data.get("filename") and data.get("content"):
        attachment = safe_save_file_from_b64(data["filename"], data["content"])
        if attachment is None:
            try:
                emit("system_message", "Attachment failed to upload (invalid or too large)", room=f'user:{username}')
            except Exception:
                pass
    safe_text = render_markdown(text)
    db = get_db(); cur = db.cursor()
    try:
        rid = int((data or {}).get('reply_to') or 0)
    except Exception:
        rid = 0
    ruser = None
    rsnippet = None
    if rid:
        try:
            cur.execute('SELECT from_user, text FROM direct_messages WHERE id=?', (rid,))
            rr = cur.fetchone()
            if rr:
                ruser = rr[0]
                rhtml = rr[1]
                try:
                    plain = re.sub(r'<[^>]+>', '', rhtml or '')
                except Exception:
                    plain = (rhtml or '')
                rsnippet = (plain or '')[:140]
        except Exception:
            rid = 0
    cur.execute(
        """
        INSERT INTO direct_messages (from_user, to_user, text, attachment, created_at, reply_to)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (username, to_user, safe_text, attachment, datetime.utcnow(), (rid or None)),
    )
    db.commit()
    did = cur.lastrowid
    payload = {
        "id": did,
        "from_user": username,
        "to_user": to_user,
        "text": safe_text,
        "attachment": attachment,
        "created_at": to_ny_time(datetime.utcnow()),
        "reply_to": (rid or None),
        "reply_username": ruser,
        "reply_snippet": rsnippet,
    }
    emit("dm_new", payload, room=f"user:{to_user}")
    emit("dm_new", payload, room=f"user:{username}")

@socketio.on('dm_typing')
def on_dm_typing(data):
    me = session.get('username')
    to_user = (data or {}).get('to', '').strip()
    if not me or not to_user:
        return
    emit('dm_typing', { 'from': me, 'to': to_user }, room=f'user:{to_user}')

@socketio.on('gdm_typing')
def on_gdm_typing(data):
    me = session.get('username')
    try:
        tid = int((data or {}).get('thread_id', 0))
    except Exception:
        tid = 0
    if not me or not tid:
        return
    # Emit to all members via per-user rooms (cross-view), excluding sender
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    for u in members:
        if u == me:
            continue
        emit('gdm_typing', { 'from': me, 'thread_id': tid }, room=f'user:{u}')

@socketio.on("dm_edit")
def on_dm_edit(data):
    username = session.get("username")
    try:
        mid = int((data or {}).get("id", 0))
    except Exception:
        mid = 0
    new_text = (data or {}).get("text", "")
    if not username or not mid:
        return
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT from_user, to_user, text FROM direct_messages WHERE id=?", (mid,))
    row = cur.fetchone()
    if not row:
        return
    author, to_user, old_html = row[0], row[1], row[2] or ""
    if not (author == username or is_admin(username) or is_superadmin(username)):
        return
    safe_text = render_markdown(new_text or "")
    if (old_html or "") == (safe_text or ""):
        return
    cur.execute("UPDATE direct_messages SET text=? WHERE id=?", (safe_text, mid))
    db.commit()
    payload = {"id": mid, "text": safe_text}
    emit("dm_edit", payload, room=f"user:{author}")
    emit("dm_edit", payload, room=f"user:{to_user}")

@socketio.on("dm_delete")
def on_dm_delete(data):
    username = session.get("username")
    try:
        mid = int((data or {}).get("id", 0))
    except Exception:
        mid = 0
    if not username or not mid:
        return
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT from_user, to_user FROM direct_messages WHERE id=?", (mid,))
    row = cur.fetchone()
    if not row:
        return
    author, to_user = row[0], row[1]
    if not (author == username or is_admin(username) or is_superadmin(username)):
        return
    cur.execute("DELETE FROM direct_messages WHERE id=?", (mid,))
    db.commit()
    emit("dm_delete", mid, room=f"user:{author}")
    emit("dm_delete", mid, room=f"user:{to_user}")

@socketio.on("typing")
def on_typing(data):
    username = session.get("username")
    if not username:
        return
    try:
        is_typing = bool((data or {}).get("typing", False))
    except Exception:
        is_typing = False
    now = time.time()
    if is_typing:
        typing_users[username] = now + 3.0  # expires in 3s unless refreshed
    else:
        typing_users.pop(username, None)
    _cleanup_typing()
    emit("typing", {"users": _current_typing_list(exclude=None)})

def _cleanup_typing():
    now = time.time()
    stale = [u for u, exp in typing_users.items() if exp <= now]
    for u in stale:
        typing_users.pop(u, None)

def _current_typing_list(exclude=None):
    _cleanup_typing()
    users = sorted(typing_users.keys())
    if exclude:
        users = [u for u in users if u != exclude]
    return users

# HTML Templates (unchanged)
BASE_CSS = """
:root {
    --bg: #ececec;
    --card: #f8f8f8;
    --muted: #666;
    --primary: #222;
    --primary-hover: #333;
    --border: #d1d5db;
    /* Buttons (light) */
    --btn-bg: #111827;
    --btn-hover: #0b1220;
    --btn-fg: #ffffff;
}

html, body {
    height: 100%;
    margin: 0;
    background: var(--bg);
    font-family: "Courier New", Courier, monospace;
    color: var(--primary);
}

/* Dark theme overrides */
.theme-dark {
    --bg: #0f172a;          /* slate-900 */
    --card: #111827;        /* gray-900 */
    --muted: #9ca3af;       /* gray-400 */
    --primary: #e5e7eb;     /* text */
    --primary-hover: #ffffff;
    --border: #2a2f3a;      /* dark border */
    /* Buttons (dark) */
    --btn-bg: #2563eb;      /* blue-600 */
    --btn-hover: #1e40af;   /* blue-800 */
    --btn-fg: #ffffff;
}

/* Dark: force white inline blocks to themed surfaces (context menus, cards, misc) */
.theme-dark [style*="background:#fff"],
.theme-dark [style*="background: #fff"],
.theme-dark [style*="background:white"],
.theme-dark [style*="background: white"],
.theme-dark [style*="border:1px solid #e5e7eb"],
.theme-dark [style*="border: 1px solid #e5e7eb"],
.theme-dark [style*="border:1px solid #d1d5db"],
.theme-dark [style*="border: 1px solid #d1d5db"],
.theme-dark [style*="border:1px solid #ddd"],
.theme-dark [style*="border: 1px solid #ddd"],
.theme-dark [style*="border-bottom:1px solid #efefef"],
.theme-dark [style*="border-bottom: 1px solid #efefef"],
.theme-dark [style*="background:#fafafa"],
.theme-dark [style*="background: #fafafa"],
.theme-dark [style*="background:#f9fafb"],
.theme-dark [style*="background: #f9fafb"],
.theme-dark [style*="background:#fffbe6"],
.theme-dark [style*="background: #fffbe6"] {
    background: var(--card) !important;
    color: var(--primary) !important;
    border-color: var(--border) !important;
}

/* Dark: de-white inline blocks inside Admin Dashboard */
.theme-dark #adminBox [style*="background:#fff"],
.theme-dark #adminBox [style*="background: #fff"],
.theme-dark #adminBox [style*="background:#f9fafb"],
.theme-dark #adminBox [style*="background: #f9fafb"],
.theme-dark #adminBox [style*="border:1px solid #e5e7eb"],
.theme-dark #adminBox [style*="border: 1px solid #e5e7eb"] {
    background: var(--card) !important;
    color: var(--primary) !important;
    border-color: var(--border) !important;
}
/* Dark: links inside Admin Dashboard */
.theme-dark #adminBox a { color: #93c5fd; text-decoration-color: #93c5fd; }

.container {
    max-width: none;
    width: 100%;
    height: 100vh;
    margin: 0;
    padding: 12px 18px;
    box-sizing: border-box;
    background: var(--card);
    border-radius: 8px;
    box-shadow: 0 6px 18px rgba(0,0,0,0.04);
}

header {
    margin-bottom: 18px;
}

h1 {
    font-size: 28px;
    margin: 0;
}

small {
    color: var(--muted);
}

.chat {
    height: 60vh;
    border: 1px dashed #ddd;
    padding: 12px;
    overflow-y: auto;
    background: white;
    scroll-behavior: smooth;
}

/* Dark theme chat surface */
.theme-dark .chat {
    background: #0b1220;
    border-color: #2a2f3a;
}

/* Button variants */
.btn { padding: 8px 12px; border-radius: 6px; border: 0; font-weight: 700; cursor: pointer; transition: background 0.2s, color 0.2s, border-color 0.2s; }
.btn-primary { background:#2563eb; color:#fff; }
.btn-primary:hover { background:#1e40af; }
.btn-secondary { background:#374151; color:#fff; }
.btn-secondary:hover { background:#1f2937; }
.btn-success { background:#059669; color:#fff; }
.btn-success:hover { background:#047857; }
.btn-warn { background:#d97706; color:#fff; }
.btn-warn:hover { background:#b45309; }
.btn-danger { background:#b91c1c; color:#fff; }
.btn-danger:hover { background:#991b1b; }
.btn-outline { background:transparent; color:var(--primary); border:1px solid #4b5563; }
.btn-outline:hover { background:#1f2937; color:#e5e7eb; }

/* Dark theme overlays and boxes */
.theme-dark #settingsBox,
.theme-dark #adminBox,
.theme-dark #pinsBox {
  background: var(--card) !important;
  color: var(--primary) !important;
  border-color: var(--border) !important;
}
.theme-dark #sqlOut { background:#0b1020; color:#d1d5db; }

.message {
    padding: 6px 8px;
    border-bottom: 1px dashed #efefef;
    animation: fadeIn 0.3s ease-in;
}

/* Dark: soften message and username whites */
.theme-dark .message { color: #cbd5e1; border-bottom-color: #1f2937; }
.theme-dark .username { color: #d1d5db; }

/* Dark: composer textarea explicit */
.theme-dark #textInput { background: var(--card) !important; color: var(--primary) !important; border-color: var(--border) !important; }

/* Dark: possible context menu container */
.theme-dark #contextMenu, .theme-dark .context-menu, .theme-dark [data-menu="context"] {
  background: var(--card) !important;
  color: var(--primary) !important;
  border: 1px solid var(--border) !important;
  box-shadow: 0 10px 30px rgba(0,0,0,0.45) !important;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.username {
    font-weight: 700;
}

.username.system {
    color: orange;
}

.username.admin {
    color: maroon;
}

.time {
    font-style: italic;
    color: var(--muted);
    font-size: 12px;
}

.attachment {
    font-style: italic;
    color: var(--muted);
    font-size: 13px;
    margin-top: 6px;
}

.form-row {
    display: flex;
    gap: 8px;
    margin-top: 12px;
}

input[type=text], input[type=password] {
    font-family: inherit;
    padding: 8px;
    border: 1px solid #ddd;
    border-radius: 6px;
    flex: 1;
}

/* Dark theme form elements */
.theme-dark input[type=text],
.theme-dark input[type=password],
.theme-dark .file-input {
    background: #0b1220;
    border-color: #2a2f3a;
    color: var(--primary);
}

/* Dark theme: inputs/selects/textareas globally */
.theme-dark input,
.theme-dark select,
.theme-dark textarea {
    background: var(--card) !important;
    border-color: var(--border) !important;
    color: var(--primary) !important;
}

/* Dark theme: panels and separators */
.theme-dark details { background: var(--card); border-color: var(--border); }
.theme-dark hr { border-top-color: var(--border); }

button {
    padding: 8px 12px;
    border-radius: 6px;
    border: 0;
    background: var(--btn-bg);
    color: var(--btn-fg);
    font-weight: 700;
    cursor: pointer;
    transition: background 0.2s;
}

button:hover {
    background: var(--btn-hover);
}

.error {
    color: #a00;
    margin-top: 8px;
}

.note {
    font-size: 14px;
    color: var(--muted);
}

/* Polished UI */
.ellipsis {
    display: inline-block;
    max-width: 40ch;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: bottom;
}
.popover {
    position: fixed;
    background: #fff;
    color: #111;
    border: 1px solid #ddd;
    border-radius: 8px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.15);
    padding: 10px 12px;
    z-index: 20000;
    width: 260px;
}
.theme-dark .popover {
    background: var(--card);
    color: var(--primary);
    border-color: #333;
}

.file-input {
    border: 1px solid #ddd;
    padding: 6px;
    border-radius: 6px;
}

.status-indicator {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #4CAF50;
    margin-right: 4px;
}

@media (max-width: 600px) {
    .container {
        margin: 0;
        padding: 8px;
    }
}
"""

LOGIN_HTML = """
<!doctype html>
<html data-default-language="{{ my_language }}" lang="{{ my_language }}">
<head>
    <meta charset="utf-8">
    <title>Chatter — Login</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span style="font-size:20px;font-weight:700">Chatter</span></h1>
            <div class="note">Please login to continue.</div>
        </header>
        <form method="post" autocomplete="off">
            <div style="display:flex;flex-direction:column;gap:8px;max-width:420px">
                <label><strong>Username</strong></label>
                <input name="username" required>
                <label><strong>Password</strong></label>
                <input type="password" name="password" required>
                <div style="display:flex;gap:8px;margin-top:6px">
                    <button type="submit">Log in</button>
                    <a href="/register" style="align-self:center;color:var(--muted);text-decoration:underline">Create account</a>
                </div>
            </div>
        </form>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
    </div>
</body>
</html>
"""

REGISTER_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Chatter — Register</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span style="font-size:20px;font-weight:700">Chatter</span></h1>
            <div class="note">Please create an account to continue.</div>
        </header>
        <form method="post" autocomplete="off">
            <div style="display:flex;flex-direction:column;gap:8px;max-width:420px">
                <label><strong>Username</strong></label>
                <input name="username" required>
                <label><strong>Password</strong></label>
                <input type="password" name="password" required>
                <div style="display:flex;gap:8px;margin-top:6px">
                    <button type="submit">Register</button>
                    <a href="/login" style="align-self:center;color:var(--muted);text-decoration:underline">Back to login</a>
                </div>
            </div>
        </form>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
    </div>
</body>
</html>
"""

CHAT_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Chatter</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>{{ base_css }}</style>
    <style>
      /* Discord-Inspired Mobile Design - Comfortable and Spacious */
      
      /* Small phones (up to 480px) - Discord-like comfortable layout */
      @media (max-width: 480px) {
        .app { 
          display: flex !important; 
          flex-direction: row !important; 
          gap: 0 !important; 
          height: 100vh; 
          overflow: hidden;
          background: var(--bg);
        }
        
        /* Left sidebar - Discord server list style */
        #leftbar { 
          width: 72px !important; 
          min-width: 72px !important; 
          max-width: 72px !important;
          padding: 12px 8px !important;
          overflow-y: auto;
          font-size: 12px;
          background: var(--sidebar-bg, #202225);
          border-right: 1px solid var(--border);
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        
        /* Right sidebar - Discord member list style */
        #rightbar { 
          width: 240px !important; 
          min-width: 200px !important; 
          max-width: 280px !important;
          padding: 16px 12px !important;
          overflow-y: auto;
          font-size: 14px;
          background: var(--sidebar-bg, #2f3136);
          border-left: 1px solid var(--border);
          line-height: 1.5;
        }
        
        /* Main chat area - Discord chat style */
        #main { 
          flex: 1 !important; 
          min-width: 0 !important;
          padding: 0 !important;
          display: flex;
          flex-direction: column;
          height: 100vh;
          overflow: hidden;
          background: var(--bg);
        }
        
        /* Chat header area */
        .chat-header {
          padding: 12px 16px;
          border-bottom: 1px solid var(--border);
          background: var(--bg);
          flex-shrink: 0;
        }
        
        /* Chat messages area - Discord message style */
        .chat { 
          flex: 1;
          overflow-y: auto;
          padding: 16px !important;
          font-size: 15px !important;
          line-height: 1.5 !important;
          background: var(--bg);
        }
        
        /* Message styling - Discord-like */
        .message { 
          font-size: 15px !important; 
          line-height: 1.5 !important; 
          padding: 8px 0 !important;
          margin: 0 !important;
          border-radius: 0;
          background: transparent;
          word-wrap: break-word;
        }
        
        .message:hover {
          background: rgba(79, 84, 92, 0.16) !important;
          margin: 0 -16px !important;
          padding: 8px 16px !important;
          border-radius: 0;
        }
        
        .username { 
          font-size: 16px !important; 
          font-weight: 600 !important;
          margin-bottom: 2px;
          display: inline-block;
        }
        
        /* Input area - Discord-like */
        .form-row { 
          flex-shrink: 0;
          padding: 16px !important;
          background: var(--bg);
          border-top: 1px solid var(--border);
        }
        
        /* Text input - Discord style */
        #textInput { 
          font-size: 15px !important; 
          padding: 12px 16px !important; 
          min-height: 44px !important;
          border-radius: 24px !important;
          border: 1px solid var(--border);
          background: var(--input-bg, #40444b);
          color: var(--text);
          width: 100%;
          box-sizing: border-box;
          resize: none;
          line-height: 1.4;
        }
        
        #textInput:focus {
          outline: none;
          border-color: var(--accent, #5865f2);
          box-shadow: 0 0 0 2px rgba(88, 101, 242, 0.3);
        }
        
        /* Send button - Discord style */
        #sendForm button { 
          padding: 12px 20px !important; 
          min-height: 44px !important; 
          font-size: 14px !important;
          font-weight: 600;
          border-radius: 22px !important;
          background: var(--accent, #5865f2) !important;
          border: none;
          color: white;
          cursor: pointer;
          margin-left: 8px;
          transition: background-color 0.2s ease;
        }
        
        #sendForm button:hover {
          background: var(--accent-hover, #4752c4) !important;
        }
        
        /* Left sidebar buttons - Discord server icons style */
        #leftbar button { 
          font-size: 11px !important; 
          padding: 8px 4px !important;
          min-height: 48px !important;
          width: 48px;
          border-radius: 50% !important;
          background: var(--button-bg, #36393f);
          border: none;
          color: var(--text);
          cursor: pointer;
          transition: all 0.2s ease;
          display: flex;
          align-items: center;
          justify-content: center;
          text-align: center;
          line-height: 1.2;
          word-break: break-word;
        }
        
        #leftbar button:hover {
          border-radius: 16px !important;
          background: var(--accent, #5865f2) !important;
          color: white;
        }
        
        /* Right sidebar styling - Discord member list */
        #rightbar button { 
          font-size: 13px !important; 
          padding: 8px 12px !important;
          min-height: 36px !important;
          width: 100%;
          border-radius: 4px !important;
          background: transparent;
          border: 1px solid var(--border);
          color: var(--text);
          cursor: pointer;
          margin-bottom: 4px;
          text-align: left;
          transition: background-color 0.2s ease;
        }
        
        #rightbar button:hover {
          background: rgba(79, 84, 92, 0.16) !important;
        }
        
        /* User avatars - larger and more prominent */
        img[style*="border-radius:50%"] {
          border: 2px solid var(--border) !important;
        }
        
        /* Status indicators - larger and more visible */
        span[style*="position:absolute"][style*="border-radius:50%"] {
          width: 12px !important;
          height: 12px !important;
          border: 3px solid var(--bg, #36393f) !important;
        }
        
        /* Hide mobile nav - not needed in full screen */
        #mobileNav { display: none !important; }
        body { padding-bottom: 0 !important; }
        
        /* Scrollbar styling - Discord-like */
        ::-webkit-scrollbar {
          width: 8px;
        }
        
        ::-webkit-scrollbar-track {
          background: transparent;
        }
        
        ::-webkit-scrollbar-thumb {
          background: rgba(79, 84, 92, 0.3);
          border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
          background: rgba(79, 84, 92, 0.5);
        }
      }
      
      /* Regular phones and small tablets (481px to 768px) - Enhanced Discord style */
      @media (min-width: 481px) and (max-width: 768px) {
        .app { 
          display: flex !important; 
          flex-direction: row !important; 
          gap: 0 !important; 
          height: 100vh; 
          overflow: hidden;
          background: var(--bg);
        }
        
        /* Left sidebar - wider on larger phones */
        #leftbar { 
          width: 240px !important; 
          min-width: 200px !important; 
          max-width: 280px !important;
          padding: 16px 12px !important;
          overflow-y: auto;
          font-size: 14px;
          background: var(--sidebar-bg, #2f3136);
          border-right: 1px solid var(--border);
          line-height: 1.5;
        }
        
        /* Right sidebar - comfortable width */
        #rightbar { 
          width: 240px !important; 
          min-width: 200px !important; 
          max-width: 280px !important;
          padding: 16px 12px !important;
          overflow-y: auto;
          font-size: 14px;
          background: var(--sidebar-bg, #2f3136);
          border-left: 1px solid var(--border);
          line-height: 1.5;
        }
        
        /* Main chat area */
        #main { 
          flex: 1 !important; 
          min-width: 0 !important;
          padding: 0 !important;
          display: flex;
          flex-direction: column;
          height: 100vh;
          overflow: hidden;
          background: var(--bg);
        }
        
        /* Chat messages */
        .chat { 
          flex: 1;
          overflow-y: auto;
          padding: 16px !important;
          font-size: 15px !important;
          line-height: 1.5 !important;
          background: var(--bg);
        }
        
        .message { 
          font-size: 15px !important; 
          line-height: 1.5 !important; 
          padding: 8px 0 !important;
          margin: 0 !important;
          word-wrap: break-word;
        }
        
        .message:hover {
          background: rgba(79, 84, 92, 0.16) !important;
          margin: 0 -16px !important;
          padding: 8px 16px !important;
        }
        
        .username { 
          font-size: 16px !important; 
          font-weight: 600 !important;
        }
        
        /* Input area */
        .form-row { 
          flex-shrink: 0;
          padding: 16px !important;
          background: var(--bg);
          border-top: 1px solid var(--border);
        }
        
        #textInput { 
          font-size: 15px !important; 
          padding: 12px 16px !important; 
          min-height: 44px !important;
          border-radius: 24px !important;
          border: 1px solid var(--border);
          background: var(--input-bg, #40444b);
          width: 100%;
          box-sizing: border-box;
        }
        
        #sendForm button { 
          padding: 12px 20px !important; 
          min-height: 44px !important; 
          font-size: 14px !important;
          font-weight: 600;
          border-radius: 22px !important;
          background: var(--accent, #5865f2) !important;
          border: none;
          color: white;
          margin-left: 8px;
        }
        
        /* Sidebar buttons */
        #leftbar button, #rightbar button { 
          font-size: 13px !important; 
          padding: 10px 12px !important;
          min-height: 40px !important;
          border-radius: 4px !important;
          background: transparent;
          border: 1px solid var(--border);
          color: var(--text);
          width: 100%;
          text-align: left;
          margin-bottom: 4px;
          cursor: pointer;
          transition: background-color 0.2s ease;
        }
        
        #leftbar button:hover, #rightbar button:hover {
          background: rgba(79, 84, 92, 0.16) !important;
        }
        
        /* Hide mobile nav */
        #mobileNav { display: none !important; }
        body { padding-bottom: 0 !important; }
      }
      
      /* Regular phones and small tablets (481px to 768px) - Full screen with better proportions */
      @media (min-width: 481px) and (max-width: 768px) {
        .app { 
          display: flex !important; 
          flex-direction: row !important; 
          gap: 4px !important; 
          height: 100vh; 
          overflow: hidden;
        }
        
        /* Better proportioned sidebars */
        #leftbar { 
          width: 30% !important; 
          min-width: 120px !important; 
          max-width: 180px !important;
          padding: 6px !important;
          overflow-y: auto;
          font-size: 12px;
        }
        #rightbar { 
          width: 25% !important; 
          min-width: 100px !important; 
          max-width: 150px !important;
          padding: 6px !important;
          overflow-y: auto;
          font-size: 12px;
        }
        
        /* Main chat area */
        #main { 
          flex: 1 !important; 
          min-width: 0 !important;
          padding: 4px !important;
          display: flex;
          flex-direction: column;
          height: 100vh;
          overflow: hidden;
        }
        
        .chat { 
          flex: 1;
          overflow-y: auto;
          padding: 6px !important;
          font-size: 14px;
        }
        
        .form-row { 
          flex-shrink: 0;
          padding: 6px !important;
        }
        
        #textInput { 
          font-size: 15px !important; 
          padding: 10px !important; 
          min-height: 40px !important;
        }
        
        #sendForm button { 
          padding: 10px 14px !important; 
          min-height: 40px !important;
        }
        
        /* Sidebar buttons */
        #leftbar button, #rightbar button { 
          font-size: 11px !important; 
          padding: 6px 8px !important;
          min-height: 36px !important;
        }
        
        /* Hide mobile nav */
        #mobileNav { display: none !important; }
        body { padding-bottom: 0 !important; }
      }
      
      /* Tablets and small laptops (769px to 1024px) - Standard full screen */
      @media (min-width: 769px) and (max-width: 1024px) {
        .app { 
          gap: 8px !important; 
          height: 100vh;
          overflow: hidden;
        }
        #leftbar { 
          width: 200px !important; 
          min-width: 200px !important;
          overflow-y: auto;
        }
        #rightbar { 
          width: 180px !important; 
          min-width: 180px !important;
          overflow-y: auto;
        }
        #main { 
          flex: 1; 
          padding: 6px !important;
          display: flex;
          flex-direction: column;
          height: 100vh;
          overflow: hidden;
        }
        .chat { 
          flex: 1;
          overflow-y: auto;
          padding: 8px !important;
        }
        .form-row { flex-shrink: 0; }
        #textInput { font-size: 15px !important; }
        
        /* No mobile nav on tablets */
        #mobileNav { display: none !important; }
        body { padding-bottom: 0 !important; }
      }
      
      /* Large tablets and laptops (1025px to 1440px) - Optimal full screen */
      @media (min-width: 1025px) and (max-width: 1440px) {
        .app { 
          gap: 12px !important; 
          max-width: none !important;
          height: 100vh;
          overflow: hidden;
        }
        #leftbar { 
          width: 240px !important; 
          min-width: 240px !important;
          overflow-y: auto;
        }
        #rightbar { 
          width: 220px !important; 
          min-width: 220px !important;
          overflow-y: auto;
        }
        #main { 
          flex: 1; 
          padding: 10px !important;
          display: flex;
          flex-direction: column;
          height: 100vh;
          overflow: hidden;
        }
        .chat { 
          flex: 1;
          overflow-y: auto;
          padding: 12px !important;
        }
        .form-row { flex-shrink: 0; }
      }
      
      /* Large screens (1441px+) - Maximum full screen */
      @media (min-width: 1441px) {
        .app { 
          gap: 16px !important; 
          max-width: none !important;
          height: 100vh;
          overflow: hidden;
        }
        #leftbar { 
          width: 280px !important; 
          min-width: 280px !important;
          overflow-y: auto;
        }
        #rightbar { 
          width: 260px !important; 
          min-width: 260px !important;
          overflow-y: auto;
        }
        #main { 
          flex: 1; 
          padding: 12px !important;
          display: flex;
          flex-direction: column;
          height: 100vh;
          overflow: hidden;
        }
        .chat { 
          flex: 1;
          overflow-y: auto;
          padding: 16px !important;
        }
        .form-row { flex-shrink: 0; }
      }
      
      /* Landscape orientation - maintain full screen */
      @media (max-width: 768px) and (orientation: landscape) {
        .app { height: 100vh !important; }
        .chat { padding: 4px !important; }
        .form-row { padding: 4px !important; }
        header { padding: 4px 6px !important; }
      }
      
      /* High DPI displays */
      @media (-webkit-min-device-pixel-ratio: 2), (min-resolution: 192dpi) {
        button, input { border-width: 0.5px; }
        .message { border-width: 0.5px; }
      }
      
      /* Ensure all elements stay within viewport */
      * { 
        box-sizing: border-box; 
      }
      
      /* Prevent horizontal overflow */
      body, html { 
        overflow-x: hidden; 
        height: 100vh;
        margin: 0;
        padding: 0;
      }
      
      /* Text wrapping to prevent overflow */
      .message, .username, button, input { 
        word-wrap: break-word; 
        overflow-wrap: break-word; 
        hyphens: auto;
      }

      @media (-webkit-min-device-pixel-ratio: 2), (min-resolution: 192dpi) {
        button, input { border-width: 0.5px; }
        .message { border-width: 0.5px; }
      }

      /* Composer layout */
      #sendForm .form-row { display:flex; gap:8px; align-items:flex-start; }
      #textInput { flex:1; width:100%; border:1px solid var(--border); border-radius:10px; resize:vertical; background:var(--card); color:var(--primary); padding:10px 12px; box-shadow:0 1px 0 rgba(0,0,0,0.02) inset; }
      #fileInput { align-self:flex-start; }
      #sendForm button[type="submit"] { align-self:flex-start; }
    </style>
</head>
<body class="{{ 'theme-dark' if my_theme=='dark' else '' }}">
        <div class="container app" style="display:flex; gap:0; align-items:flex-start;">
        <!-- Left: DM sidebar -->
        <aside id="leftbar" style="width:240px; min-width:240px; border-right:1px dashed #ddd; padding-right:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:6px">
                <span style="font-weight:700">Direct Messages</span>
                <div style="display:flex;gap:6px;align-items:center">
                    <button id="goPublicBtn" type="button" style="padding:4px 8px;font-size:12px;background:#374151"># Public</button>
                    <div style="position:relative;display:inline-block">
                      <button id="newMenuBtn" type="button" style="padding:4px 8px;font-size:12px">+ New ▾</button>
                      <div id="newMenu" style="display:none;position:absolute;right:0;top:100%;background:#0b1020;border:1px solid #374151;border-radius:8px;min-width:180px;z-index:50">
                        <a href="#" id="optNewDM" style="display:block;padding:8px 10px;color:#e5e7eb;text-decoration:none">New Direct Message</a>
                        <a href="#" id="optNewGroup" style="display:block;padding:8px 10px;color:#e5e7eb;text-decoration:none">New Group Chat</a>
                        <a href="#" id="optVoice" style="display:block;padding:8px 10px;color:#e5e7eb;text-decoration:none">Join/Create Voice Channel</a>
                      </div>
                    </div>
                </div>
            </div>
            <div style="margin-bottom:8px">
                <input id="dmSearch" type="text" placeholder="Find or start a conversation" style="width:100%;padding:6px" />
            </div>
            <div id="dmList" style="display:block"></div>
        </aside>
        <div id="leftResizer" style="width:6px;cursor:col-resize;align-self:stretch"></div>
        <!-- Main area -->
        <div id="main" style="flex:1; min-width:0; padding:0 8px;">
        <header>
            <h1>
                <span style="font-size:22px;font-weight:700">Chatter</span>
                <small>— chat{% if is_admin %} <span style="color:coral">(admin)</span>{% endif %}</small>
            </h1>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;flex-wrap:wrap;">
                <div class="note">
                    <span class="status-indicator"></span>
                    Logged in as <span class="username">{{ username }}</span>
                </div>
                <div>
                    <span id="onlineBtn" style="color:blue;cursor:pointer;text-decoration:underline">Online (<span id="onlineCount">0</span>)</span>
                </div>
                <div style="display:flex;gap:10px;align-items:center">
                    {% if username in superadmins %}
                    <button id="btnAdminDashHeader" type="button" title="Admin Dashboard" style="background:#374151;color:#fff">Admin Dashboard</button>
                    <button id="pinsBtn" type="button" title="View Pinned Messages" style="padding:6px 10px;background:#f59e0b;color:#fff;border:none;border-radius:4px;cursor:pointer">📌</button>
                    {% endif %}
                    <button id="settingsBtn" type="button">Settings</button>
                    {% if username not in superadmins %}
                    <button id="pinsBtn" type="button" title="View Pinned Messages" style="padding:6px 10px;background:#f59e0b;color:#fff;border:none;border-radius:4px;cursor:pointer">📌</button>
                    {% endif %}
                    <a href="/logout" style="color:var(--muted);text-decoration:underline">Log out</a>
                </div>
            </div>
        </header>

        <div id="modeBar" style="min-height:18px;color:#444;font-size:13px;margin:4px 0 6px 0"></div>
        <div id="chat" class="chat" aria-live="polite"></div>
        <div id="typingBar" style="min-height:18px;color:#666;font-size:13px;margin-top:6px"></div>
        <div id="globalTypingBar" style="min-height:18px;color:#888;font-size:13px;margin-top:2px"></div>

        <div style="margin-top:8px">
            <div id="replyBar" style="display:none;margin:6px 0;padding:8px;border:1px dashed #9ca3af;border-radius:6px;background:var(--card);color:var(--primary);font-size:13px">
                <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
                    <div>
                        <strong>Replying to <span id="replyUser"></span></strong>
                        <div id="replySnippet" style="color:var(--muted);margin-top:4px;max-width:660px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"></div>
                    </div>
                    <button id="cancelReplyBtn" type="button" class="btn btn-outline">✕</button>
                </div>
            </div>
            <form id="sendForm" enctype="multipart/form-data">
                <div class="form-row">
                    <textarea id="textInput" rows="2" placeholder="Type a message..." autocomplete="off" style="resize:vertical"></textarea>
                    <input id="fileInput" class="file-input" type="file">
                    <button type="submit">Send</button>
                </div>
            </form>
        </div>

    <!-- Pinned Messages Overlay -->
    <div id="pinsOverlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.35);z-index:10005;">
      <div style="position:relative;max-width:680px;margin:60px auto;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,0.25);">
        <div style="padding:12px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;color:var(--primary)">
          <strong>📌 Pinned Messages</strong>
          <button id="closePinsOverlay" type="button" style="padding:6px 10px">✕</button>
        </div>
        <div id="pinsList" style="padding:14px;max-height:70vh;overflow-y:auto;color:var(--primary)"></div>
      </div>
    </div>

    <!-- Admin Dashboard Overlay -->
    <div id="adminOverlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:10010;overflow:auto;">
      <div id="adminBox" style="position:relative;max-width:720px;margin:50px auto;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,0.25);">
        <div style="padding:14px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;color:var(--primary)">
          <strong>Admin Dashboard</strong>
          <button id="closeAdminOverlay" type="button" style="padding:6px 10px">✕</button>
        </div>
        <div style="padding:14px;display:flex;flex-direction:column;gap:16px;color:var(--primary)">
          <div id="idResetDropdown" style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card); display:none">
            <div style="font-weight:700;margin-bottom:8px">ID Reset Toggles</div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
              <label for="idResetSelect" style="min-width:140px">Visibility</label>
              <select id="idResetSelect" style="padding:6px 8px">
                <option value="hidden">Hidden</option>
                <option value="shown" selected>Shown</option>
              </select>
              <span class="note">Use this to show/hide the ID reset checkboxes.</span>
            </div>
          </div>
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)">
            <div style="font-weight:700;margin-bottom:8px">DM Tools</div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
              <label style="min-width:120px">Peer username</label>
              <input id="adminDmPeer" placeholder="username" style="flex:1;min-width:200px;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)" />
              <button id="adminDmSaveBtn" type="button" class="btn btn-primary">Save DM Logs</button>
              <button id="adminDmCloseAllBtn" type="button" class="btn btn-secondary">Close All My DMs</button>
            </div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
              <input id="adminDmTo" placeholder="send as System → username" style="flex:1;min-width:220px;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)" />
              <textarea id="adminDmText" rows="2" placeholder="message text" style="flex:2;min-width:260px;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)"></textarea>
              <button id="adminDmSendBtn" type="button" class="btn btn-primary">Send DM as System</button>
            </div>
          </div>
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)">
            <div style="font-weight:700;margin-bottom:8px">Group Controls</div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
              <input id="adminGdmTid" placeholder="thread id (tid)" style="width:200px;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)" />
              <button id="adminGdmLockBtn" type="button" class="btn btn-secondary">Lock</button>
              <button id="adminGdmUnlockBtn" type="button" class="btn btn-secondary">Unlock</button>
              <button id="adminGdmArchiveBtn" type="button" class="btn btn-secondary">Archive</button>
            </div>
          </div>
          <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;background:var(--card); display:none">
            <div style="font-weight:700;margin-bottom:8px">Admin Visibility</div>
            <label style="display:flex;align-items:center;gap:8px">
              <input id="toggleAdminsStealth" type="checkbox">
              <span>Stealth mode (hide admins from Users panel)</span>
            </label>
            <div id="stealthStatus" class="note" style="margin-top:6px;color:#6b7280"></div>
          </div>
          <div id="userMgmtCard" style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;background:var(--card)">
            <div style="font-weight:700;margin-bottom:8px">User Management</div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
              <input id="adminCreateUserName" placeholder="new username" style="flex:1;min-width:180px;padding:8px;border:1px solid #d1d5db;border-radius:6px;background:var(--card);color:var(--primary)" />
              <input id="adminCreateUserPass" type="password" placeholder="password" style="flex:1;min-width:180px;padding:8px;border:1px solid #d1d5db;border-radius:6px;background:var(--card);color:var(--primary)" />
              <label style="display:flex;align-items:center;gap:8px">
                <input id="adminCreateUserIsAdmin" type="checkbox" />
                <span>Make admin</span>
              </label>
              <button id="adminCreateUserBtn" type="button" class="btn btn-primary">Create User</button>
            </div>
            <div class="note" style="color:#6b7280">Superadmin only. Creating with "Make admin" adds this user as an extra admin.</div>
          </div>
          <details id="idResetDetails" style="border:1px solid var(--border);border-radius:10px;padding:0;background:var(--card)">
            <summary style="cursor:pointer;padding:12px;font-weight:700">ID Reset Behavior</summary>
            <div id="idResetBlock" style="padding:12px;border-top:1px solid var(--border);display:block">
              <div style="display:flex;flex-direction:column;gap:8px">
                <label style="display:flex;align-items:center;gap:8px">
                  <input id="toggleResetPublic" type="checkbox">
                  <span>Reset Public message IDs when clearing all public messages</span>
                </label>
                <label style="display:flex;align-items:center;gap:8px">
                  <input id="toggleResetDM" type="checkbox">
                  <span>Reset Direct Message IDs when clearing all DMs</span>
                </label>
                <label style="display:flex;align-items:center;gap:8px">
                  <input id="toggleResetGDM" type="checkbox">
                  <span>Reset Group Message IDs when clearing group messages</span>
                </label>
                <label style="display:flex;align-items:center;gap:8px">
                  <input id="toggleResetGroupThreads" type="checkbox">
                  <span>Reset Group/Member/Message thread IDs when the last group is deleted</span>
                </label>
              </div>
            </div>
          </details>
          <div id="adminDashMsg" style="min-height:18px;color:var(--primary)"></div>
        </div>
      </div>
    </div>

        <div style="margin-top:12px;color:var(--muted);font-size:13px">
            Chatter is not secure. Do not share anything confidential through chatter.
        </div>
        </div> <!-- end #main -->
        <!-- Right: Online panel -->
        <div id="rightResizer" style="width:6px;cursor:col-resize;align-self:stretch"></div>
        <aside id="rightbar" style="width:240px; min-width:240px; border-left:1px dashed #ddd; padding-left:12px; display:flex; flex-direction:column; max-height:100vh;">
            <div style="font-weight:700; margin-bottom:8px; flex:0 0 auto;">Users</div>
            <div id="rightOnlineList" style="font-size:14px; overflow-y:auto; flex:1 1 auto; padding-right:4px;"></div>
        </aside>
    </div>

    

    <!-- Mobile Navigation -->
    <nav id="mobileNav" style="display:none;">
        <button id="tabPublic" type="button"><i class="icon-chat"></i><small>Public</small></button>
        {% if username in superadmins %}
        <button id="btnAdminDash" type="button" title="Admin Dashboard" class="btn btn-secondary">Admin Dashboard</button>
        {% endif %}
        <button id="tabDMs" type="button"><i class="icon-users"></i><small>DMs</small></button>
        <button id="tabGDMs" type="button"><i class="icon-group"></i><small>Groups</small></button>
        <button id="tabSettings" type="button"><i class="icon-cog"></i><small>Settings</small></button>
    </nav>
    <div id="mobileBackdrop"></div>

    <!-- Inline Dialog and Toast -->
    <div id="chatDialog" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:10012;align-items:center;justify-content:center;">
      <div id="chatDialogBox" style="background:var(--card);border:1px solid var(--border);border-radius:12px;max-width:520px;width:92%;box-shadow:0 10px 40px rgba(0,0,0,0.3);">
        <div style="padding:12px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;color:var(--primary)">
          <strong id="chatDialogTitle">Dialog</strong>
          <button id="chatDialogClose" class="btn btn-outline" type="button">✕</button>
        </div>
        <form id="chatDialogForm" style="padding:14px;display:flex;flex-direction:column;gap:10px"></form>
        <div style="padding:12px 14px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end">
          <button id="chatDialogCancel" class="btn btn-outline" type="button">Cancel</button>
          <button id="chatDialogSubmit" class="btn btn-primary" type="submit">OK</button>
        </div>
      </div>
    </div>
    <div id="chatToast" style="display:none;position:fixed;left:50%;transform:translateX(-50%);bottom:16px;z-index:10013;background:var(--card);color:var(--primary);border:1px solid var(--border);padding:8px 12px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.25)"></div>

    <!-- Settings Modal -->
    <div id="settingsOverlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:9998;overflow:auto;">
      <div id="settingsBox" style="position:relative;max-width:520px;margin:60px auto;background:var(--card);border:1px solid #ccc;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,0.2);max-height:80vh;overflow:auto;">
        <div style="padding:12px 14px;border-bottom:1px solid var(--border);font-weight:700;display:flex;justify-content:space-between;align-items:center;">
          <span>Settings</span>
          <div style="display:flex;gap:8px;align-items:center">
            {% if username in superadmins %}
            <button id="btnAdminDashSettings" type="button" title="Admin Dashboard" class="btn btn-secondary">Admin Dashboard</button>
            {% endif %}
            <button id="closeSettings" type="button" class="btn btn-outline">✕</button>
          </div>
        </div>
        <div style="padding:14px;display:flex;flex-direction:column;gap:14px">
          <div>
            <label><strong>Username</strong></label>
            <div style="display:flex;gap:8px;align-items:center">
              <input id="setUsername" placeholder="New username" style="flex:1;padding:8px" value="{{ username }}">
              <button id="saveUsername" type="button" class="btn btn-primary">Save</button>
            </div>
          </div>
          <div>
            <label><strong>Change Password</strong></label>
            <div style="display:flex;flex-direction:column;gap:6px">
              <input id="setCurrentPw" type="password" placeholder="Current password" style="padding:8px">
              <input id="setNewPw" type="password" placeholder="New password" style="padding:8px">
              <button id="savePassword" type="button" class="btn btn-primary">Update Password</button>
            </div>
            <div class="note">Username can be changed without password. Password change requires current password.</div>
          </div>
          <div>
            <label><strong>Theme</strong></label>
            <div style="display:flex;gap:8px;align-items:center">
              <select id="setTheme" style="padding:8px">
                <option value="light" {{ 'selected' if my_theme=='light' else '' }}>Light</option>
                <option value="dark" {{ 'selected' if my_theme=='dark' else '' }}>Dark</option>
              </select>
              <button id="saveTheme" type="button" class="btn btn-primary">Apply</button>
              <button id="resetSidebarSizes" type="button" class="btn btn-outline" style="margin-left:auto">Reset Sidebar Sizes</button>
            </div>
          </div>
          <div>
            <label><strong>Language</strong></label>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <select id="setLanguage" style="padding:8px;min-width:160px">
                {% for lang in supported_languages %}
                <option value="{{ lang.code }}" {{ 'selected' if (my_language or 'en') == lang.code else '' }}>{{ lang.label }}</option>
                {% endfor %}
              </select>
              <button id="saveLanguage" type="button" class="btn btn-primary">Apply</button>
            </div>
            <div class="note" style="margin-top:6px;color:#6b7280">Automatically translates messages and interface content.</div>
          </div>
          <div>
            <label><strong>Profile</strong></label>
            <div style="display:flex;flex-direction:column;gap:6px">
              <textarea id="setBio" placeholder="Short bio" rows="3" style="padding:8px">{{ my_bio }}</textarea>
              <div style="display:flex;gap:8px;align-items:center">
                <select id="setStatus" style="padding:8px">
                  <option value="" {{ 'selected' if (my_status or '')=='' else '' }}>Default</option>
                  <option value="online" {{ 'selected' if my_status=='online' else '' }}>Online</option>
                  <option value="idle" {{ 'selected' if my_status=='idle' else '' }}>Idle</option>
                  <option value="dnd" {{ 'selected' if my_status=='dnd' else '' }}>Do Not Disturb</option>
                  <option value="offline" {{ 'selected' if my_status=='offline' else '' }}>Offline</option>
                </select>
                <button id="saveProfile" type="button" class="btn btn-primary">Save Profile</button>
              </div>
              <div class="note">Bio shows on hover and in DM header. Status affects your presence color.</div>
              <hr style="margin:10px 0;border:none;border-top:1px dashed #ccc">
              <div style="display:flex;gap:8px;flex-wrap:wrap">
                <button id="markAllReadBtn" type="button" class="btn btn-primary">✓ Mark All As Read</button>
                <button id="clearAllMsgs" type="button" class="btn btn-danger" style="display:none">🧹 Clear All Messages</button>
              </div>
            </div>
          </div>
          <div>
            <label><strong>Danger Zone</strong></label>
            <div class="note" style="margin:6px 0;color:#b91c1c">Deleting your account removes your messages, DMs, group messages, and profile. This cannot be undone.</div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input id="delAccPw" type="password" placeholder="Confirm password" style="padding:8px;min-width:200px">
              <button id="deleteAccountBtn" type="button" class="btn btn-danger">Delete my account</button>
            </div>
          </div>
          <div>
            <label><strong>Profile Picture</strong></label>
            <form id="avatarForm" enctype="multipart/form-data" style="display:flex;gap:8px;align-items:center">
              <input id="avatarFile" name="avatar" type="file" accept="image/*">
              <button type="submit" class="btn btn-primary">Upload</button>
              {% if my_avatar %}<img src="/uploads/{{ my_avatar }}" alt="avatar" style="width:28px;height:28px;border-radius:50%;border:1px solid var(--border)">{% endif %}
              <button id="deleteAvatarBtn" type="button" class="btn btn-danger" style="margin-left:auto">Delete</button>
            </form>
          </div>
        </div>
      </div>
    </div>

    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
    <script>
        const SUPPORTED_LANGUAGES = {{ supported_languages|tojson }};
        const ADMINS = {{ admins|tojson }};
        const SUPERADMINS = {{ superadmins|tojson }};
        const chatEl = document.getElementById('chat');
        const me = "{{ username }}";
        const isAdmin = {{ 'true' if is_admin else 'false' }};
        let contextMenu = null;
        let messagesLoaded = false;
        let typingTimer = null;
        let currentMode = 'public'; // 'public' | 'dm' | 'gdm'
        let currentPeer = null;
        let currentThreadId = null;
        let currentReply = null; // {type:'public'|'dm'|'gdm', id:number, username:string, snippet:string}
        const modeBar = document.getElementById('modeBar');

        const Language = (() => {
          const STORAGE_KEY = 'chat.language';
          const defaultLanguage = (document.documentElement?.dataset?.defaultLanguage || 'en').trim() || 'en';
          const allowed = Array.isArray(SUPPORTED_LANGUAGES)
            ? SUPPORTED_LANGUAGES.map(item => {
                if (!item) return null;
                if (typeof item === 'string') return item;
                if (typeof item.code === 'string') return item.code;
                if (typeof item.value === 'string') return item.value;
                return null;
              }).filter(Boolean)
            : [];
          const blockTags = new Set(['SCRIPT','STYLE','NOSCRIPT','CODE','PRE','TEXTAREA','OPTION']);
          const originals = new WeakMap();
          const cache = new Map();
          let current = defaultLanguage;

          function normalize(text) {
            return (text || '').replace(/\s+/g, ' ').trim();
          }

          async function fetchTranslation(text, lang) {
            const target = (lang || current || '').trim() || 'en';
            if (!text || !text.trim()) return text;
            if (target === 'en') return text;
            if (Array.isArray(allowed) && allowed.length && !allowed.includes(target)) {
              return text;
            }
            if ((text || '').length > 4500) {
              return text;
            }
            const key = `${target}::${text}`;
            if (cache.has(key)) {
              return cache.get(key);
            }
            const url = `https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=${encodeURIComponent(target)}&dt=t&q=${encodeURIComponent(text)}`;
            const ctrl = new AbortController();
            const timer = setTimeout(() => {
              try { ctrl.abort(); } catch(_e){}
            }, 1800);
            try {
              const res = await fetch(url, { method: 'GET', signal: ctrl.signal });
              if (!res.ok) {
                cache.set(key, text);
                return text;
              }
              let translated = text;
              try {
                const data = await res.json();
                if (Array.isArray(data) && Array.isArray(data[0])) {
                  translated = data[0].map(part => (Array.isArray(part) && part[0] != null) ? part[0] : '').join('');
                } else if (typeof data === 'string' && data) {
                  translated = data;
                }
              } catch (_err) {
                translated = text;
              }
              if (!translated) translated = text;
              cache.set(key, translated);
              return translated;
            } catch (_err) {
              cache.set(key, text);
              return text;
            } finally {
              clearTimeout(timer);
            }
          }

          async function translateNodes(nodes) {
            if (!nodes || !nodes.length) return;
            if ((current || '').trim() === 'en') {
              for (const node of nodes) {
                const original = originals.get(node);
                if (original != null) {
                  node.nodeValue = original;
                }
              }
              return;
            }
            const buckets = new Map();
            for (const node of nodes) {
              if (!node) continue;
              const parent = node.parentElement;
              if (!parent || blockTags.has(parent.tagName)) continue;
              const value = node.nodeValue;
              if (!value || !value.trim()) continue;
              if (!originals.has(node)) {
                originals.set(node, value);
              }
              const key = normalize(value);
              if (!key) continue;
              if (!buckets.has(key)) buckets.set(key, []);
              buckets.get(key).push(node);
            }
            for (const [key, nodeList] of buckets.entries()) {
              const translated = await fetchTranslation(key);
              if (!translated) continue;
              for (const node of nodeList) {
                const original = originals.get(node) ?? node.nodeValue ?? '';
                const leading = (original.match(/^\s*/) || [''])[0];
                const trailing = (original.match(/\s*$/) || [''])[0];
                node.nodeValue = `${leading}${translated}${trailing}`;
              }
            }
          }

          async function translateElement(root) {
            if (!root) return;
            const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
            const nodes = [];
            while (walker.nextNode()) {
              nodes.push(walker.currentNode);
            }
            await translateNodes(nodes);
          }

          async function applyDocument() {
            await translateElement(document.body);
          }

          function setLanguage(lang, opts) {
            const options = opts || {};
            const normalized = (lang || '').trim();
            const target = (allowed.length ? (allowed.includes(normalized) ? normalized : defaultLanguage) : (normalized || defaultLanguage)) || 'en';
            current = target;
            document.documentElement.setAttribute('lang', current);
            if (!options.silent) {
              try { localStorage.setItem(STORAGE_KEY, current); } catch (_err) {}
            }
            applyDocument();
          }

          function getLanguage() {
            return current;
          }

          async function init() {
            let initial = defaultLanguage;
            try {
              const stored = localStorage.getItem(STORAGE_KEY);
              if (stored && (!allowed.length || allowed.includes(stored))) {
                initial = stored;
              }
            } catch (_err) {}
            current = initial || 'en';
            document.documentElement.setAttribute('lang', current);
            await applyDocument();
            return current;
          }

          return {
            init,
            setLanguage,
            getLanguage,
            translateFragment: translateElement,
            translateText: fetchTranslation,
          };
        })();
        Language.init();
        // Inline editor helper
        function startInlineEdit(container, initialHTML, onSave){
          try{
            const originalHTML = initialHTML || '';
            const wrap = document.createElement('div');
            wrap.style.marginTop = '4px';
            const ta = document.createElement('textarea');
            ta.value = (container.innerText || '').replaceAll('\u00A0',' ');
            ta.style.width = '100%';
            ta.style.minHeight = '64px';
            ta.style.padding = '10px';
            ta.style.border = '1px solid #374151';
            ta.style.borderRadius = '8px';
            ta.style.background = 'var(--card)';
            ta.style.color = 'var(--primary)';
            ta.style.fontFamily = 'inherit';
            ta.style.fontSize = '14px';
            ta.placeholder = 'Edit message';
            const row = document.createElement('div');
            row.style.display = 'flex'; row.style.alignItems = 'center'; row.style.gap = '8px'; row.style.marginTop = '6px';
            const hint = document.createElement('div');
            hint.style.color = '#9ca3af'; hint.style.fontSize = '12px';
            hint.textContent = 'escape to cancel • enter to save • shift+enter for newline';
            const saveBtn = document.createElement('button');
            saveBtn.type = 'button'; saveBtn.className = 'btn btn-primary'; saveBtn.textContent = 'Save';
            row.appendChild(hint); row.appendChild(saveBtn);
            wrap.appendChild(ta); wrap.appendChild(row);
            const original = container.innerHTML;
            container.innerHTML = '';
            container.appendChild(wrap);
            ta.focus();
            ta.addEventListener('keydown', (ev)=>{
              if (ev.key === 'Enter' && !ev.shiftKey){ ev.preventDefault(); saveBtn.click(); }
              else if (ev.key === 'Escape'){ ev.preventDefault(); container.innerHTML = original; }
            });
            saveBtn.addEventListener('click', ()=>{
              try{
                const txt = (ta.value || '').trim();
                if (!txt) { container.innerHTML = original; return; }
                onSave(txt);
              } finally {
                container.innerHTML = originalHTML || container.innerHTML;
              }
            });
          }catch(e){}
        }
        const dmListEl = document.getElementById('dmList');
        const dmSearchEl = document.getElementById('dmSearch');
        const rightOnlineList = document.getElementById('rightOnlineList');
        // Group DM elements (create dynamically below in left bar)
        const leftbar = document.getElementById('leftbar');
        const gdmSection = document.createElement('div');
        gdmSection.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin:14px 0 6px 0">
              <span style="font-weight:700">Group Chats</span>
              <span style="display:flex;gap:6px;align-items:center">
                <button id="newGdmBtn" type="button" style="padding:4px 8px;font-size:12px">+ Group</button>
                <button id="newVoiceBtn" type="button" style="padding:4px 8px;font-size:12px">+ Voice</button>
              </span>
            </div>
            <div id="channelsList" style="display:block"></div>`;
        leftbar.appendChild(gdmSection);
        const gdmListEl = gdmSection.querySelector('#channelsList');
        let gdmThreadsCache = {}; // tid -> {id,name,created_by}
        let voiceChannelsCache = [];
        let profilesCache = { data: [], ts: 0 };

        // Load DMs list and render in left sidebar
        async function loadDMs(){
          try{
            const search = (dmSearchEl.value||'').toLowerCase().trim();
            const r = await fetch('/api/dm/peers', {credentials:'same-origin'});
            const peers = await r.json().catch(()=>[]);
            const closed = JSON.parse(localStorage.getItem('closedDMs')||'[]');
            const unread = JSON.parse(localStorage.getItem('unreadDM')||'{}');
            const list = (Array.isArray(peers)? peers: []).filter(u=>u && u!==me && !closed.includes(u));
            list.sort();
            const filtered = search? list.filter(u=>u.toLowerCase().includes(search)) : list;
            dmListEl.innerHTML = filtered.map(u=>{
              const cnt = unread[u]||0;
              const badge = cnt>0? ` <span style='background:#ef4444;color:#fff;border-radius:10px;padding:0 6px;font-size:11px'>${cnt}</span>` : '';
              return `<div><a href="#" data-dm="${u}">@ ${u}${badge}</a></div>`;
            }).join('') || '<div style="color:#999">No DMs</div>';
            dmListEl.querySelectorAll('a[data-dm]').forEach(a=>{
              a.onclick=(e)=>{ e.preventDefault(); openDM(a.getAttribute('data-dm')); if (isMobile()) closeOverlays(); };
            });
          }catch(e){ try{ dmListEl.innerHTML = '<div style="color:#999">Failed</div>'; }catch(_){} }
        }

        // Sidebar resizers (desktop only)
        (function setupSidebarResizers(){
          try{
            const lbar = document.getElementById('leftbar');
            const rbar = document.getElementById('rightbar');
            const lrz = document.getElementById('leftResizer');
            const rrz = document.getElementById('rightResizer');
            if (!lbar || !rbar || !lrz || !rrz) return;
            const minW = 160, maxW = 480;
            // Make handles easier to grab and full-height
            [lrz, rrz].forEach(h=>{ try{
              h.style.width = '10px';
              h.style.minHeight = '100%';
              h.style.background = 'transparent';
              h.style.cursor = 'col-resize';
              h.onmouseenter = ()=>{ h.style.background = 'rgba(0,0,0,0.05)'; };
              h.onmouseleave = ()=>{ h.style.background = 'transparent'; };
            }catch(e){}});
            // Load saved widths
            try{
              const lw = parseInt(localStorage.getItem('ui.leftWidth')||'0',10); if (lw) { lbar.style.width=lw+'px'; lbar.style.minWidth=lw+'px'; }
              const rw = parseInt(localStorage.getItem('ui.rightWidth')||'0',10); if (rw) { rbar.style.width=rw+'px'; rbar.style.minWidth=rw+'px'; }
            }catch(e){}
            // Drag helpers
            function dragResizer(startX, startW, onmove){
              const getX = (ev)=> (ev.touches && ev.touches.length ? ev.touches[0].clientX : ev.clientX);
              const mm = (ev)=>{ const dx = getX(ev) - startX; onmove(dx); ev.preventDefault(); };
              const mu = ()=>{
                document.removeEventListener('mousemove', mm);
                document.removeEventListener('mouseup', mu);
                document.removeEventListener('touchmove', mm);
                document.removeEventListener('touchend', mu);
              };
              document.addEventListener('mousemove', mm, {passive:false});
              document.addEventListener('mouseup', mu);
              document.addEventListener('touchmove', mm, {passive:false});
              document.addEventListener('touchend', mu);
            }
            // Left drag: change leftbar width
            function startLeft(ev){
              if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) return;
              const startX = (ev.touches && ev.touches.length ? ev.touches[0].clientX : ev.clientX);
              const startW = lbar.getBoundingClientRect().width;
              dragResizer(startX, startW, (dx)=>{
                let w = Math.min(maxW, Math.max(minW, startW + dx));
                lbar.style.width = w+'px'; lbar.style.minWidth = w+'px';
                try{ localStorage.setItem('ui.leftWidth', String(w)); }catch(e){}
              });
              ev.preventDefault();
            }
            lrz.addEventListener('mousedown', startLeft);
            lrz.addEventListener('touchstart', startLeft, {passive:false});
            // Right drag: change rightbar width (dragging from its left edge -> inverse sign)
            function startRight(ev){
              if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) return;
              const startX = (ev.touches && ev.touches.length ? ev.touches[0].clientX : ev.clientX);
              const startW = rbar.getBoundingClientRect().width;
              dragResizer(startX, startW, (dx)=>{
                let w = Math.min(maxW, Math.max(minW, startW - dx));
                rbar.style.width = w+'px'; rbar.style.minWidth = w+'px';
                try{ localStorage.setItem('ui.rightWidth', String(w)); }catch(e){}
              });
              ev.preventDefault();
            }
            rrz.addEventListener('mousedown', startRight);
            rrz.addEventListener('touchstart', startRight, {passive:false});
          }catch(e){}
        })();

        // Quick Voice button in Channels header
        try{
          const nb = document.getElementById('newVoiceBtn');
          if (nb) nb.onclick = ()=>{
            openDialog({
              title:'Join/Create Voice Channel',
              html:`<input name='ch' placeholder='channel-name' style='padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)'>`,
              onSubmit: async (fd, close)=>{ const ch=(fd.get('ch')||'').toString().trim(); if(!ch){ toast('Enter a channel','#dc2626'); return; } close(); openVoice(ch); }
            });
          };
        }catch(e){}

        const socket = io();
        const initialGdmTid = {{ (gdm_tid|tojson) if gdm_tid is not none else '""' }};
        const initialVoiceCh = {{ (voice_ch|tojson) if voice_ch is not none else '""' }};

        // Mobile helpers
        const isMobile = () => window.matchMedia && window.matchMedia('(max-width: 768px)').matches;
        function closeOverlays(){ document.body.classList.remove('show-leftbar','show-rightbar'); }
        function openLeftbar(){ document.body.classList.add('show-leftbar'); }
        function openRightbar(){ document.body.classList.add('show-rightbar'); }
        (function setupMobileNav(){
          try {
            const nav = document.getElementById('mobileNav');
            const backdrop = document.getElementById('mobileBackdrop');
            const apply = () => { nav.style.display = isMobile() ? 'flex' : 'none'; };
            apply();
            window.addEventListener('resize', apply);
            backdrop.onclick = closeOverlays;
            document.getElementById('tabPublic').onclick = () => { switchToPublic(); closeOverlays(); };
            document.getElementById('tabDMs').onclick = () => { if (!document.body.classList.contains('show-leftbar')) { openLeftbar(); try { document.getElementById('dmList').scrollIntoView({behavior:'smooth'}); } catch(e){} } else { closeOverlays(); } };
            document.getElementById('tabGDMs').onclick = () => { if (!document.body.classList.contains('show-leftbar')) { openLeftbar(); try { document.getElementById('channelsList').scrollIntoView({behavior:'smooth'}); } catch(e){} } else { closeOverlays(); } };
            document.getElementById('tabSettings').onclick = () => { closeOverlays(); document.getElementById('settingsOverlay').style.display='block'; };
          } catch(e) {}
        })();

        // Dialog/Toast helpers
        function toast(msg, color){
          try{
            const el=document.getElementById('chatToast');
            el.textContent=msg||'';
            try { Language.translateFragment(el); } catch(_){}
            el.style.display='block';
            el.style.color=color||'var(--primary)';
            clearTimeout(window.__toastTimer);
            window.__toastTimer=setTimeout(()=>{ el.style.display='none'; }, 1800);
          }catch(e){}
        }
        function openDialog(opts){
          try{
            const wrap=document.getElementById('chatDialog');
            const form=document.getElementById('chatDialogForm');
            document.getElementById('chatDialogTitle').textContent=opts.title||'Dialog';
            form.innerHTML = opts.html||'';
            wrap.style.display='flex';
            try { Language.translateFragment(wrap); } catch(_){}
            const close=()=>{ wrap.style.display='none'; };
            document.getElementById('chatDialogClose').onclick=close;
            document.getElementById('chatDialogCancel').onclick=close;
            const submitBtn=document.getElementById('chatDialogSubmit');
            submitBtn.onclick=(ev)=>{
              ev.preventDefault();
              try{ opts.onSubmit && opts.onSubmit(new FormData(form), close); }catch(e){}
            };
          }catch(e){}
        }

        // Voice Channels UI section
        const voiceState = {
          current: null,
          localStream: null,
          peers: {}, // username -> RTCPeerConnection
          muted: false
        };
        const voiceSection = document.createElement('div');
        voiceSection.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;margin:14px 0 6px 0">
            <span style="font-weight:700">Voice Channels</span>
            <span id="voiceStatus" style="font-size:12px;color:#9ca3af"></span>
          </div>
          <div id="voiceControls" style="display:none;gap:6px;margin-bottom:6px">
            <button id="voiceMuteBtn" type="button" style="padding:4px 8px;font-size:12px">Mute</button>
            <button id="voiceLeaveBtn" type="button" style="padding:4px 8px;font-size:12px;background:#7f1d1d;color:#fff">Leave</button>
            <div id="voicePeers" style="margin-left:auto;font-size:12px;color:#9ca3af"></div>
          </div>
          <div id="voiceList" style="display:none"></div>`;
        leftbar.appendChild(voiceSection);
        const voiceListEl = voiceSection.querySelector('#voiceList');
        const voiceControlsEl = voiceSection.querySelector('#voiceControls');
        const voiceStatusEl = voiceSection.querySelector('#voiceStatus');
        const voiceMuteBtn = voiceSection.querySelector('#voiceMuteBtn');
        const voiceLeaveBtn = voiceSection.querySelector('#voiceLeaveBtn');
        const voicePeersEl = voiceSection.querySelector('#voicePeers');

        function setVoiceStatus(t){ try{ voiceStatusEl.textContent = t||''; }catch(e){} }
        function renderVoiceList(channels){
          try{
            const chans = Array.isArray(channels)? channels: [];
            voiceChannelsCache = chans;
            renderChannels();
          }catch(e){}
        }
        async function refreshVoiceList(){
          try{ const r = await fetch('/api/voice/channels',{credentials:'same-origin'}); const j = await r.json().catch(()=>({})); renderVoiceList((j&&j.channels)||[]); }catch(e){}
        }

        // Combined channels renderer
        function renderChannels(){
          try{
            const list = [];
            // Group threads
            const closed = JSON.parse(localStorage.getItem('closedGDMs')||'[]');
            const threads = Object.values(gdmThreadsCache||{});
            threads.sort((a,b)=>String(a.name||a.id).localeCompare(String(b.name||b.id)));
            threads.forEach(t=>{
              const sid = String(t.id);
              if (closed.includes(sid)) return;
              list.push(`<div><a href="#" data-gdm="${t.id}"># ${t.name ? t.name : ('Group '+t.id)}</a></div>`);
            });
            // Voice channels
            const v = Array.isArray(voiceChannelsCache)? voiceChannelsCache: [];
            v.forEach(c=>{ list.push(`<div><a href="#" data-voice="${c}">🔊 ${c}</a></div>`); });
            gdmListEl.innerHTML = list.length ? list.join('') : '<div style="color:#999">No channels</div>';
            // Wire clicks
            gdmListEl.querySelectorAll('a[data-gdm]').forEach(a=>{ a.onclick=(e)=>{ e.preventDefault(); const tid=parseInt(a.getAttribute('data-gdm'),10); if(!isNaN(tid)) openGDM(tid); if (isMobile()) closeOverlays(); }; });
            gdmListEl.querySelectorAll('a[data-voice]').forEach(a=>{ a.onclick=(e)=>{ e.preventDefault(); openVoice(a.getAttribute('data-voice')); if (isMobile()) closeOverlays(); }; });
          }catch(e){}
        }

        // Load group threads and update cache
        async function loadGDMs(){
          try{
            const r = await fetch('/api/gdm/threads',{credentials:'same-origin'});
            const j = await r.json().catch(()=>({}));
            const arr = Array.isArray(j) ? j : (j.threads||j.data||[]);
            const map = {};
            (arr||[]).forEach(t=>{ if (t && (t.id!==undefined)) map[t.id] = t; });
            gdmThreadsCache = map;
            renderChannels();
          }catch(e){}
        }

        function pcConfig(){ return { iceServers: [{urls:'stun:stun.l.google.com:19302'}] }; }
        async function ensureLocalStream(){
          if (voiceState.localStream) return voiceState.localStream;
          const s = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
          voiceState.localStream = s;
          return s;
        }
        function addPeer(username){
          if (!username || username===me || voiceState.peers[username]) return voiceState.peers[username];
          const pc = new RTCPeerConnection(pcConfig());
          voiceState.localStream.getTracks().forEach(t=> pc.addTrack(t, voiceState.localStream));
          pc.onicecandidate = (ev)=>{ if (ev.candidate) socket.emit('voice_ice', { channel: voiceState.current, candidate: ev.candidate }); };
          pc.ontrack = (ev)=>{
            try{
              let au = document.querySelector(`audio[data-voice-peer="${username}"]`);
              if (!au){ au = document.createElement('audio'); au.setAttribute('data-voice-peer', username); au.autoplay = true; au.playsInline = true; document.body.appendChild(au); }
              if (au.srcObject !== ev.streams[0]) { au.srcObject = ev.streams[0]; try { au.play().catch(()=>{}); } catch(_){} }
            }catch(e){}
          };
          voiceState.peers[username] = pc;
          return pc;
        }
        async function createAndSendOffer(toUser){
          try{
            const pc = addPeer(toUser);
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            socket.emit('voice_offer', { channel: voiceState.current, sdp: offer });
          }catch(e){}
        }
        async function openVoice(channel){
          try{
            if (!channel) return;
            await ensureLocalStream();
            voiceState.current = channel;
            voiceControlsEl.style.display = 'flex';
            setVoiceStatus(`# ${channel}`);
            socket.emit('voice_join', { channel });
            refreshVoiceList();
          }catch(e){}
        }
        function leaveVoice(){
          try{
            const ch = voiceState.current; if (!ch) return;
            socket.emit('voice_leave', { channel: ch });
            Object.values(voiceState.peers||{}).forEach(pc=>{ try{ pc.close(); }catch(e){} });
            voiceState.peers = {};
            voiceState.current = null;
            voiceControlsEl.style.display = 'none';
            setVoiceStatus('');
            try{ voicePeersEl.textContent=''; }catch(e){}
            refreshVoiceList();
            switchToPublic();
          }catch(e){}
        }
        voiceLeaveBtn.onclick = leaveVoice;
        voiceMuteBtn.onclick = ()=>{
          try{
            if (!voiceState.localStream) return;
            voiceState.muted = !voiceState.muted;
            voiceState.localStream.getAudioTracks().forEach(t=> t.enabled = !voiceState.muted);
            voiceMuteBtn.textContent = voiceState.muted? 'Unmute' : 'Mute';
            if (voiceState.current) socket.emit('voice_mute', { channel: voiceState.current, muted: voiceState.muted });
          }catch(e){}
        };

        // Voice signaling handlers
        try{
          socket.on('voice_participants', (d)=>{
            try{
              if (!d || !d.channel) return;
              renderChannels();
              if (voiceState.current && d.channel === voiceState.current){
                const parts = Array.isArray(d.participants)? d.participants: [];
                const others = parts.filter(u=>u!==me);
                // Update display
                try{ voicePeersEl.textContent = 'In call: ' + parts.join(', '); }catch(e){}
                // Create peer connections; avoid glare by only the lexicographically smaller username offering
                others.forEach(u=>{ try{ if (!voiceState.peers[u]) { addPeer(u); if ((me||'') < (u||'')) createAndSendOffer(u); } }catch(e){} });
                // Close PCs for users no longer present
                Object.keys(voiceState.peers).forEach(u=>{ if (!parts.includes(u)) { try{ voiceState.peers[u].close(); }catch(e){} delete voiceState.peers[u]; } });
              }
            }catch(e){}
          });
        }catch(e){}

        try{
          socket.on('voice_offer', async (d)=>{
            try{
              if (!d || !d.channel || d.from===me) return;
              if (!voiceState.current || d.channel !== voiceState.current) return;
              await ensureLocalStream();
              const pc = addPeer(d.from);
              await pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
              const answer = await pc.createAnswer();
              await pc.setLocalDescription(answer);
              socket.emit('voice_answer', { channel: voiceState.current, sdp: answer });
            }catch(e){}
          });
          socket.on('voice_answer', async (d)=>{
            try{
              if (!d || !d.channel || d.from===me) return;
              if (!voiceState.current || d.channel !== voiceState.current) return;
              const pc = voiceState.peers[d.from];
              if (!pc) return;
              await pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
            }catch(e){}
          });
          socket.on('voice_ice', async (d)=>{
            try{
              if (!d || !d.channel || d.from===me) return;
              if (!voiceState.current || d.channel !== voiceState.current) return;
              const pc = voiceState.peers[d.from] || addPeer(d.from);
              if (d.candidate) {
                try { await pc.addIceCandidate(new RTCIceCandidate(d.candidate)); } catch(e){}
              }
            }catch(e){}
          });
        }catch(e){}

        // Admin Dashboard overlay open/close
        (function setupAdminDash(){
          const open = () => {
            try {
              document.getElementById('adminOverlay').style.display='block';
              const dd = document.getElementById('idResetDropdown');
              if (dd) dd.style.display = 'block';
              try { initResetIdToggles(); } catch(e){}
            } catch(e){}
          };
          const close = () => { try { document.getElementById('adminOverlay').style.display='none'; } catch(e){} };
          try {
            const b1 = document.getElementById('btnAdminDash');
            const b2 = document.getElementById('btnAdminDashHeader');
            const b3 = document.getElementById('btnAdminDashSettings');
            if (b1) b1.onclick = open;
            if (b2) b2.onclick = open;
            if (b3) b3.onclick = open;
            document.getElementById('closeAdminOverlay').onclick = close;
          } catch(e) {}
          const say = (t,c)=>{ const el=document.getElementById('adminDashMsg'); if(el){ el.textContent=t||''; el.style.color=c||'#374151'; } };
          // ID Reset dropdown wiring
          try {
            const sel = document.getElementById('idResetSelect');
            const block = document.getElementById('idResetBlock');
            const sel2 = document.getElementById('idResetSelect2');
            if (sel && block) {
              const apply = (v)=>{ block.style.display = (v==='shown') ? 'block' : 'none'; };
              sel.onchange = ()=> apply(sel.value);
              // default to shown once dashboard opens
              sel.value = 'shown'; apply('shown');
            }
            if (sel2 && block) {
              const apply2 = (v)=>{ block.style.display = (v==='shown') ? 'block' : 'none'; };
              sel2.onchange = ()=> apply2(sel2.value);
              // default based on current value of quick selector
              apply2(sel2.value||'shown');
            }
          } catch(e){}
          const post = async (url, body)=>{
            try {
              const res = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body||{})});
              let j={}; try{ j=await res.json(); }catch(_){}
              if(res.ok && (j.ok||res.status===200)) say('Done','#16a34a'); else say(j.error||'Failed','#dc2626');
            } catch(e) { say('Failed','#dc2626'); }
          };
          try {
            const btn = document.getElementById('adminCreateUserBtn');
            if (btn) btn.onclick = async ()=>{
              const u = (document.getElementById('adminCreateUserName')?.value||'').trim();
              const p = (document.getElementById('adminCreateUserPass')?.value||'').trim();
              const isA = !!document.getElementById('adminCreateUserIsAdmin')?.checked;
              if (!u || !p) { say('Enter username and password','#dc2626'); return; }
              try {
                const r = await fetch('/api/admin/create_user',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:u,password:p,is_admin:isA})});
                const j = await r.json().catch(()=>({}));
                if (!r.ok || !j.ok) { say(j.error||'Failed','#dc2626'); return; }
                say('User created','#16a34a');
                try{ document.getElementById('adminCreateUserName').value=''; document.getElementById('adminCreateUserPass').value=''; document.getElementById('adminCreateUserIsAdmin').checked=false; }catch(e){}
              } catch(e){ say('Failed','#dc2626'); }
            };
          } catch(e){}
          // Quick Create User button wiring
          try {
            const qbtn = document.getElementById('quickCreateUserBtn');
            if (qbtn) qbtn.onclick = async ()=>{
              const u = (document.getElementById('quickCreateUserName')?.value||'').trim();
              const p = (document.getElementById('quickCreateUserPass')?.value||'').trim();
              const isA = !!document.getElementById('quickCreateUserIsAdmin')?.checked;
              if (!u || !p) { say('Enter username and password','#dc2626'); return; }
              try {
                const r = await fetch('/api/admin/create_user',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:u,password:p,is_admin:isA})});
                const j = await r.json().catch(()=>({}));
                if (!r.ok || !j.ok) { say(j.error||'Failed','#dc2626'); return; }
                say('User created','#16a34a');
                try{ document.getElementById('quickCreateUserName').value=''; document.getElementById('quickCreateUserPass').value=''; document.getElementById('quickCreateUserIsAdmin').checked=false; }catch(e){}
              } catch(e){ say('Failed','#dc2626'); }
            };
          } catch(e){}
          // DM Logs
          try { document.getElementById('adminDmSaveBtn').onclick = ()=>{ const peer=(document.getElementById('adminDmPeer').value||'').trim(); if(!peer){ say('Enter peer','#dc2626'); return;} window.open('/api/admin/dm_logs?peer='+encodeURIComponent(peer),'_blank'); }; } catch(e){}
          // Close All DMs
          try { document.getElementById('adminDmCloseAllBtn').onclick = ()=> post('/api/admin/dm_close_all',{}); } catch(e){}
          // DM as System
          try { document.getElementById('adminDmSendBtn').onclick = ()=>{ const to=(document.getElementById('adminDmTo').value||'').trim(); const text=(document.getElementById('adminDmText').value||'').trim(); if(!to||!text){ say('Enter recipient and text','#dc2626'); return;} post('/api/admin/dm_as_system',{to, text}); }; } catch(e){}
          // Group controls
          const tidVal = ()=>{ const v=(document.getElementById('adminGdmTid').value||'').trim(); const n=parseInt(v,10); return isNaN(n)?0:n; };
          try { document.getElementById('adminGdmLockBtn').onclick = ()=>{ const tid=tidVal(); if(!tid){ say('Enter tid','#dc2626'); return;} post('/api/gdm/lock',{tid, thread_id: tid}); }; } catch(e){}
          try { document.getElementById('adminGdmUnlockBtn').onclick = ()=>{ const tid=tidVal(); if(!tid){ say('Enter tid','#dc2626'); return;} post('/api/gdm/unlock',{tid, thread_id: tid}); }; } catch(e){}
          try { document.getElementById('adminGdmArchiveBtn').onclick = ()=>{ const tid=tidVal(); if(!tid){ say('Enter tid','#dc2626'); return;} post('/api/gdm/archive',{tid, thread_id: tid}); }; } catch(e){}
        })();

        // Settings: Reset Sidebar Sizes
        (function setupResetSidebarSizes(){
          try{
            const btn = document.getElementById('resetSidebarSizes');
            if (!btn) return;
            btn.onclick = ()=>{
              try{
                localStorage.removeItem('ui.leftWidth');
                localStorage.removeItem('ui.rightWidth');
              }catch(e){}
              try{
                const lbar = document.getElementById('leftbar');
                const rbar = document.getElementById('rightbar');
                if (lbar){ lbar.style.width='240px'; lbar.style.minWidth='240px'; }
                if (rbar){ rbar.style.width='240px'; rbar.style.minWidth='240px'; }
              }catch(e){}
              try{ alert('Sidebar sizes reset to default.'); }catch(e){}
            };
          }catch(e){}
        })();

        // Ensure group list refreshes on changes
        try {
          socket.on('gdm_threads_refresh', (data)=>{
            try { loadGDMs(); } catch(e){}
          });
        } catch(e) {}
        // Reset admin cache on load to reduce any flicker between cached DOM and current state
        try { window.__adminsLastJson = []; } catch(e){}
        // Helper: get avatar url from cache
        const getAvatar = (u) => {
            try {
                if (u === 'System') return '/sys_pfp.png';
                const p = (profilesCache.data||[]).find(x=>x.username===u);
                const url = (p && p.avatar_url) || '';
                return url || '/default_avatar';
            } catch(e) { return '/default_avatar'; }
        };
        // Initialize ID Reset toggles: fetch current settings and wire saves
        async function initResetIdToggles(){
            try {
                const pub = document.getElementById('toggleResetPublic');
                const dm = document.getElementById('toggleResetDM');
                const gdm = document.getElementById('toggleResetGDM');
                const thr = document.getElementById('toggleResetGroupThreads');
                if (!pub || !dm || !gdm || !thr) return;
                const apply = (j)=>{
                    try { pub.checked = !!(j.reset_public || j.public || j.pub); } catch(e){}
                    try { dm.checked = !!(j.reset_dm || j.dm); } catch(e){}
                    try { gdm.checked = !!(j.reset_gdm || j.gdm); } catch(e){}
                    try { thr.checked = !!(j.reset_group_threads || j.group_threads || j.threads); } catch(e){}
                };
                // Load current values from either /api/admins/resets or /api/admins/resets/get
                let j = {};
                try {
                    let r = await fetch('/api/admins/resets', {credentials:'same-origin'});
                    j = await r.json().catch(()=>({}));
                    if (!r.ok || (!j.ok && (j.reset_public===undefined && j.public===undefined))) throw new Error('fallback');
                } catch(_){
                    try {
                        const r2 = await fetch('/api/admins/resets/get', {credentials:'same-origin'});
                        j = await r2.json().catch(()=>({}));
                    } catch(e){}
                }
                // Handle shapes {ok:true, settings:{...}} or direct flags
                const data = (j && j.settings) ? j.settings : j;
                apply(data||{});
                const save = async ()=>{
                    const body = {
                        reset_public: !!pub.checked,
                        reset_dm: !!dm.checked,
                        reset_gdm: !!gdm.checked,
                        reset_group_threads: !!thr.checked,
                    };
                    try {
                        let r = await fetch('/api/admins/resets', {method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)});
                        if (!r.ok) throw new Error('fallback');
                    } catch(_){
                        try { await fetch('/api/admins/resets/set', {method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)}); } catch(e){}
                    }
                };
                pub.onchange = save; dm.onchange = save; gdm.onchange = save; thr.onchange = save;
            } catch(e){}
        }
        // Helper: update document title with unread totals
        const updateTitleUnread = () => {
            try {
                const dm = JSON.parse(localStorage.getItem('unreadDM')||'{}');
                const gdm = JSON.parse(localStorage.getItem('unreadGDM')||'{}');
                let total = 0;
                for (const k in dm) total += dm[k]||0;
                for (const k in gdm) total += gdm[k]||0;
                document.title = total>0 ? `Chatter (${total})` : 'Chatter';
            } catch(e) { document.title = 'Chatter'; }
        };
        // HTML escape helper for safe username rendering
        const esc = (s) => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

        // Pinned public message helpers (global scope)
        let pinnedMessageEl = null;
        function renderPinnedPublic(msg){
          // Remove existing pinned message if any
          if (pinnedMessageEl && pinnedMessageEl.parentNode) {
            pinnedMessageEl.remove();
            pinnedMessageEl = null;
          }
          if (!msg || currentMode !== 'public') return;
          
          // Create pinned message element at top of chat
          pinnedMessageEl = document.createElement('div');
          pinnedMessageEl.id = 'pinnedMessageTop';
          pinnedMessageEl.style.cssText = 'background:#fffbe6;border:2px solid #f59e0b;border-radius:8px;padding:10px 12px;margin-bottom:12px;position:sticky;top:0;z-index:4';
          
          let text = (msg.text||'');
          try {
            text = text.replace(/^<p>/i, '').replace(/<\/p>$/i, '');
          } catch(_e) {}
          const username = (msg.username||'');
          const time = msg.created_at ? new Date(msg.created_at).toLocaleString() : '';
          const mAva = getAvatar(username);
          
          pinnedMessageEl.innerHTML = `
            <div style='display:flex;align-items:flex-start;gap:10px'>
              <div style='font-size:20px'>📌</div>
              <div style='flex:1;min-width:0'>
                <div style='display:flex;align-items:center;gap:8px;margin-bottom:4px'>
                  <img src='${mAva}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                  <span style='font-weight:700;color:#78350f'>${esc(username)}</span>
                  <span style='color:#92400e;font-size:12px'>${time}</span>
                </div>
                <div style='color:#78350f'>${esc(text)}</div>
              </div>
            </div>
          `;
          
          // Insert at the top of chatEl
          if (chatEl && chatEl.firstChild) {
            chatEl.insertBefore(pinnedMessageEl, chatEl.firstChild);
          } else if (chatEl) {
            chatEl.appendChild(pinnedMessageEl);
          }
        }
        async function ensurePinnedLoaded(){
          try {
            if (currentMode !== 'public') return;
            const r = await fetch('/api/pinned?type=public',{credentials:'same-origin'});
            const j = await r.json();
            if(r.ok && j && j.ok){ renderPinnedPublic(j.message); }
          } catch(e) {}
        }

        // Socket connection events
        socket.on('connect', function() {
            console.log('Connected to server');
            loadMessages();
            // Load pinned public message on connect
            try { ensurePinnedLoaded(); } catch(e){}
            try { loadDMs(); } catch(e){}
            try { loadGDMs(); } catch(e){}
            // ensure mobile nav visibility on connect
            try { const nav = document.getElementById('mobileNav'); nav.style.display = isMobile() ? 'flex' : 'none'; } catch(e) {}
            // If we arrived via invite link, auto-open the group chat
            try {
              if (initialGdmTid && String(initialGdmTid).trim() !== '') {
                const tidNum = parseInt(initialGdmTid, 10);
                if (!isNaN(tidNum) && tidNum > 0) {
                  openGDM(tidNum);
                }
              }
              // Auto-join voice channel via link
              try {
                if (initialVoiceCh && String(initialVoiceCh).trim() !== '') {
                  openVoice(String(initialVoiceCh).trim());
                }
              } catch(e){}
              // Seed voice list
              try { refreshVoiceList(); } catch(e){}
            } catch(e) {}
        });

        socket.on('disconnect', function() {
            console.log('Disconnected from server');
        });

        // Group threads list refresh notifications (rename/add/delete)
        socket.on('gdm_threads_refresh', (info) => {
            try { loadGDMs(); } catch(e) {}
            if (info && info.deleted && currentMode==='gdm' && currentThreadId===info.deleted) {
                switchToPublic();
            }
        });

        // Typing indicator updates
        const typingBar = document.getElementById('typingBar');
        const globalTypingBar = document.getElementById('globalTypingBar');
        window.typingUsers = new Set();
        socket.on('typing', payload => {
            try {
                const users = (payload && payload.users) || [];
                window.typingUsers = new Set(users);
                const others = users.filter(u => u !== me);
                typingBar.textContent = formatTyping(others);
                try { Language.translateFragment(typingBar); } catch(_){}
            } catch (e) {}
        });
        // Cross-view typing notifications
        socket.on('dm_typing', info => {
            try {
                // Only show if not currently in this DM
                if (info && info.from && info.to && ((currentMode !== 'dm') || currentPeer !== info.from)) {
                    globalTypingBar.textContent = `${info.from} is typing in your DM…`;
                    try { Language.translateFragment(globalTypingBar); } catch(_){}
                    setTimeout(() => { if (globalTypingBar.textContent.includes('your DM')) globalTypingBar.textContent=''; }, 3000);
                }
            } catch(e) {}
        });
        socket.on('gdm_typing', info => {
            try {
                if (info && info.thread_id && ((currentMode !== 'gdm') || currentThreadId !== info.thread_id)) {
                    const name = (gdmThreadsCache[info.thread_id] && gdmThreadsCache[info.thread_id].name) || `Group ${info.thread_id}`;
                    globalTypingBar.textContent = `${info.from} is typing in ${name}…`;
                    try { Language.translateFragment(globalTypingBar); } catch(_){}
                    setTimeout(() => { if (globalTypingBar.textContent.includes('is typing in')) globalTypingBar.textContent=''; }, 3000);
                }
            } catch(e) {}
        });

        function formatTyping(users) {
            if (!users || users.length === 0) return '';
            if (users.length === 1) return users[0] + ' is typing…';
            if (users.length === 2) return users[0] + ' and ' + users[1] + ' are typing…';
            return users[0] + ', ' + users[1] + ' and ' + (users.length - 2) + ' others are typing…';
        }

        // Load existing messages immediately when connected
        function loadMessages() {
            if (messagesLoaded) return;
            
            fetch('/api/messages')
                .then(res => res.json())
                .then(msgs => {
                    msgs.forEach(m => renderMessage(m));
                    messagesLoaded = true;
                    // Load pinned message after regular messages
                    ensurePinnedLoaded();
                    chatEl.scrollTop = chatEl.scrollHeight;
                })
                .catch(err => console.error('Error loading messages:', err));
        }

        // Online users functionality (no typing state shown here)
        const onlineBtn = document.getElementById('onlineBtn');
        const onlineCountEl = document.getElementById('onlineCount');
        onlineBtn.onclick = function() {
            fetch('/api/online')
                .then(res => res.json())
                .then(users => {
                    let popup = window.open("", "Online Users", "width=300,height=400");
                    let html = "<html><head><title>Online Users</title></head><body><h3>Online Users:</h3><ul>";
                    users.forEach(u => {
                        const label = `${u}${u===me?' (you)':''}`;
                        html += `<li style=\"color:${ADMINS.includes(u)?'maroon':'black'}\">${label}</li>`;
                    });
                    html += "</ul></body></html>";
                    popup.document.write(html);
                    popup.document.close();
                });
        };

        // Real-time message events (handled below with de-duplication)
        socket.on('dm_new', dm => {
            const peer = dm.from_user === me ? dm.to_user : dm.from_user;
            // refresh sidebar peers
            loadDMs();
            if (currentMode === 'dm' && currentPeer === peer) {
                renderDM(dm);
                chatEl.scrollTop = chatEl.scrollHeight;
            } else {
                // increment unread for peer
                try {
                    const map = JSON.parse(localStorage.getItem('unreadDM')||'{}');
                    map[peer] = (map[peer]||0) + 1;
                    localStorage.setItem('unreadDM', JSON.stringify(map));
                    loadDMs();
                } catch(e) {}
            }
            updateTitleUnread();
        });
        socket.on('dm_edit', payload => {
            const el = chatEl.querySelector(`.message[data-id='${payload.id}']`);
            if (!el) return;
            const body = el.querySelector('.msg-body');
            if (body) body.innerHTML = payload.text || '';
        });
        socket.on('dm_delete', id => {
            const el = chatEl.querySelector(`.message[data-id='${id}']`);
            if (el) el.remove();
        });

        // Group live events
        socket.on('gdm_new', m => {
            if (currentMode === 'gdm' && currentThreadId === m.thread_id) {
                renderGDM(m);
                chatEl.scrollTop = chatEl.scrollHeight;
            } else {
                try {
                    const map = JSON.parse(localStorage.getItem('unreadGDM')||'{}');
                    const key = String(m.thread_id);
                    map[key] = (map[key]||0) + 1;
                    localStorage.setItem('unreadGDM', JSON.stringify(map));
                    loadGDMs();
                } catch(e) {}
            }
            updateTitleUnread();
        });
        // Clear events
        socket.on('dm_cleared', info => {
            if (currentMode==='dm') { chatEl.innerHTML=''; }
            const map = JSON.parse(localStorage.getItem('unreadDM')||'{}');
            if (currentPeer && map[currentPeer]) { delete map[currentPeer]; localStorage.setItem('unreadDM', JSON.stringify(map)); }
            updateTitleUnread();
        });
        socket.on('gdm_cleared', info => {
            if (currentMode==='gdm' && info && info.thread_id===currentThreadId) { chatEl.innerHTML=''; }
            const map = JSON.parse(localStorage.getItem('unreadGDM')||'{}');
            const key = String(currentThreadId||'');
            if (key && map[key]) { delete map[key]; localStorage.setItem('unreadGDM', JSON.stringify(map)); }
            updateTitleUnread();
        });
        socket.on('gdm_edit', payload => {
            const el = chatEl.querySelector(`.message[data-id='${payload.id}']`);
            if (!el) return;
            const body = el.querySelector('.msg-body');
            if (body) body.innerHTML = payload.text || '';
        });
        socket.on('gdm_delete', id => {
            const el = chatEl.querySelector(`.message[data-id='${id}']`);
            if (el) el.remove();
        });

        socket.on('delete_message', id => {
            const el = chatEl.querySelector(`.message[data-id='${id}']`);
            if (el) el.remove();
        });

        // Realtime removal for /clear N
        socket.on('messages_deleted', payload => {
            try {
                const ids = (payload && payload.ids) || [];
                ids.forEach(id => {
                    const el = chatEl.querySelector(`.message[data-id='${id}']`);
                    if (el) el.remove();
                });
            } catch(e) {}
        });

        socket.on('edit_message', payload => {
            const id = payload && payload.id;
            if (!id) return;
            const el = chatEl.querySelector(`.message[data-id='${id}']`);
            if (!el) return;
            const body = el.querySelector('.msg-body');
            if (body) { body.innerHTML = payload.text || ''; }
        });

        const seenMsgIds = new Set();

        socket.on('clear_all', () => {
            chatEl.innerHTML = '';
            messagesLoaded = false;
            try { seenMsgIds.clear(); } catch(e) {}
        });

        socket.on('system_message', msg => {
            try {
                if (typeof msg === 'string') {
                    msg = {
                        id: Date.now() % 2147483647,
                        username: 'System',
                        text: msg,
                        attachment: null,
                        created_at: new Date().toISOString(),
                        avatar: '/sys_pfp.png'
                    };
                } else if (msg && typeof msg === 'object') {
                    if (!msg.username) msg.username = 'System';
                    if (!msg.created_at) msg.created_at = new Date().toISOString();
                }
            } catch (e) {}
            renderMessage(msg);
        });
        // Live public messages (no reload) with de-duplication by id and public-only gating
        socket.on('new_message', msg => {
            if (currentMode !== 'public') return;
            try {
                if (msg && msg.id !== undefined && msg.id !== null) {
                    if (seenMsgIds.has(msg.id)) return;
                    seenMsgIds.add(msg.id);
                }
            } catch(e) {}
            renderMessage(msg);
        });

        socket.on('user_joined', data => {
            updateOnlineCount();
        });

        socket.on('user_left', data => {
            updateOnlineCount();
        });

        socket.on('user_list_refresh', function(data) {
            // Refresh the user profiles in the right column
            refreshRightOnline();
            try { if (window.refreshAdmins) window.refreshAdmins(); } catch(e){}
        });

        socket.on('admin_list', function(data) {
            // Refresh the admin list
            const admins = data && data.admins;
            if (admins) {
                if (!window.ADMINS) window.ADMINS = [];
                window.ADMINS = admins;
            }
        });

        function updateOnlineCount() {
            fetch('/api/online')
                .then(res => res.json())
                .then(users => {
                    onlineCountEl.textContent = users.length;
                });
        }

        function presenceColor(presence) {
            switch ((presence||'').toLowerCase()) {
                case 'online': return '#4CAF50';
                case 'idle': return '#eab308';
                case 'dnd': return '#ef4444';
                default: return '#bbb';
            }
        }

        async function getProfiles(force=false) {
            const now = Date.now();
            if (!force && (now - profilesCache.ts) < 30000 && profilesCache.data && profilesCache.data.length) {
                return profilesCache.data;
            }
            const data = await fetch('/api/users_profiles').then(r=>r.json());
            profilesCache = { data, ts: Date.now() };
            return data;
        }

        async function refreshRightOnline() {
            try {
                const profiles = await getProfiles(true);
                let filtered = profiles || [];
                if (currentMode === 'dm' && currentPeer) {
                    const allow = new Set([me, currentPeer]);
                    filtered = filtered.filter(p => allow.has(p.username));
                } else if (currentMode === 'gdm' && currentThreadId) {
                    const members = await fetch(`/api/gdm/members?tid=${currentThreadId}`).then(r=>r.json()).catch(()=>[]);
                    const allow = new Set(members||[]);
                    filtered = filtered.filter(p => allow.has(p.username));
                }
                const online = [];
                const offline = [];
                for (const p of filtered) {
                    ((p.presence||'').toLowerCase() === 'offline' ? offline : online).push(p);
                }
                const renderUser = (p) => {
                    const u = p.username;
                    const label = u === me ? `${u} (you)` : u;
                    const color = presenceColor(p.presence);
                    const ava = p.avatar_url || '';
                    const bio = (p.bio||'');
                    const shortBio = bio.length > 100 ? (bio.slice(0, 100) + '...') : bio;
                    const tooltip = `${bio}`;
                    const isSA = (Array.isArray(SUPERADMINS) && SUPERADMINS.includes(u));
                    const isAdmin = isSA ? false : ((window.ADMIN_SET && window.ADMIN_SET.has) ? window.ADMIN_SET.has(u) : false);
                    const meta = (window.ADMIN_META && window.ADMIN_META[u]) || {};
                    const isExtra = !!meta.extra;
                    const badge = isSA
                        ? `<span style='color:#fff;background:#111827;border-radius:6px;padding:1px 4px;font-size:11px;margin-left:6px'>Owner</span>`
                        : (isAdmin
                            ? (isExtra
                                ? `<span style='color:#fff;background:#6b21a8;border-radius:6px;padding:1px 4px;font-size:11px;margin-left:6px'>ADMIN</span>`
                                : `<span style='color:#fff;background:#b91c1c;border-radius:6px;padding:1px 4px;font-size:11px;margin-left:6px'>ADMIN</span>`)
                            : '');
                    return `<div style='display:flex;align-items:center;gap:10px;margin:8px 0;font-size:15px' data-user='${esc(u)}' title='${esc(tooltip)}'>
                        <div style='position:relative'>
                          <img src='${ava}' alt='' style='width:28px;height:28px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                          <span style='position:absolute;right:-2px;bottom:-2px;display:inline-block;width:12px;height:12px;border-radius:50%;background:${color};border:2px solid #fff'></span>
                        </div>
                        <div style='display:flex;flex-direction:column;min-width:0'>
                          <span>${esc(label)}${badge}</span>
                          <span style='color:#777;white-space:normal;word-break:break-word;overflow-wrap:anywhere;margin-top:4px'>${esc(shortBio)}</span>
                        </div>
                    </div>`;
                };
                rightOnlineList.innerHTML = filtered.map(p => {
                    const u = p.username;
                    const label = u === me ? `${u} (you)` : u;
                    const color = presenceColor(p.presence);
                    const ava = p.avatar_url || '';
                    const statusText = (p.status||'').toUpperCase();
                    const bio = (p.bio||'');
                    const shortBio = bio.length > 100 ? (bio.slice(0, 100) + '...') : bio;
                    const tooltip = `${bio}`;
                    return `<div style='display:flex;align-items:center;gap:10px;margin:8px 0;font-size:15px' data-user='${esc(u)}' title='${esc(tooltip)}'>
                        <div style='position:relative'>
                          <img src='${ava}' alt='' style='width:28px;height:28px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                          <span style='position:absolute;right:-2px;bottom:-2px;display:inline-block;width:12px;height:12px;border-radius:50%;background:${color};border:2px solid #fff'></span>
                        </div>
                        <div style='display:flex;flex-direction:column;min-width:0'>
                          <span>${esc(label)}</span>
                          <span style='color:#888;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px'>${esc(shortBio)}</span>
                        </div>
                    </div>`;
                }).join('');
                rightOnlineList.innerHTML = `
                  <div style='font-weight:700;margin:6px 0'>Online — ${online.length}</div>
                  ${online.map(renderUser).join('') || "<div class='note'>No one online</div>"}
                  <div style='font-weight:700;margin:10px 0 6px'>Offline — ${offline.length}</div>
                  ${offline.map(renderUser).join('') || "<div class='note'>No one offline</div>"}
                `;

                // Pin update socket listener (uses global ensurePinnedLoaded and renderPinnedPublic)
                socket.on('pin_update', (payload)=>{
                  try {
                    if(!payload || payload.kind!=='public') return;
                    if(payload.action==='pin'){ renderPinnedPublic(payload.message||null); }
                    else if(payload.action==='unpin'){ 
                      // If unpinned, check if there's another pin
                      ensurePinnedLoaded();
                    }
                  } catch(e) {}
                });
                // Hover/click profile popover + context menu (with hover-intent) via delegated listeners
                ensureProfilePopover();
                rightOnlineList.onmouseover = (ev) => {
                    const el = ev.target && ev.target.closest('[data-user]');
                    if (!el || !rightOnlineList.contains(el)) return;
                    const u = el.getAttribute('data-user');
                    const p = (profiles||[]).find(x=>x.username===u) || {};
                    scheduleShowProfilePopover(el, p, 250);
                };
                rightOnlineList.onmouseout = (ev) => {
                    const el = ev.target && ev.target.closest('[data-user]');
                    if (!el) return;
                    const to = ev.relatedTarget;
                    if (to && (to.closest && (to.closest('[data-user]') === el || to.closest('.popover')))) return;
                    scheduleHideProfilePopover(180);
                };
                rightOnlineList.onclick = (ev) => {
                    const el = ev.target && ev.target.closest('[data-user]');
                    if (!el || !rightOnlineList.contains(el)) return;
                    const u = el.getAttribute('data-user');
                    const p = (profiles||[]).find(x=>x.username===u) || {};
                    scheduleShowProfilePopover(el, p, 0);
                };
                rightOnlineList.oncontextmenu = (ev) => {
                    const el = ev.target && ev.target.closest('[data-user]');
                    if (!el || !rightOnlineList.contains(el)) return;
                    ev.preventDefault();
                    const u = el.getAttribute('data-user');
                    if (!u || u === me) return;
                    showUserContextMenu(ev.pageX, ev.pageY, u);
                };
            } catch(e) {
                rightOnlineList.textContent = 'Failed to load';
            }
        }

        // Profile popover + context menu helpers
        function ensureProfilePopover() {
            if (window.__profilePopover) return;
            const pop = document.createElement('div');
            pop.className = 'popover';
            pop.style.display = 'none';
            pop.style.pointerEvents = 'auto';
            pop.addEventListener('mouseenter', () => {
                // Keep popover open while hovering it
                if (window.__popoverHideTimer) { clearTimeout(window.__popoverHideTimer); window.__popoverHideTimer = null; }
            });
            pop.addEventListener('mouseleave', () => {
                scheduleHideProfilePopover(150);
            });
            document.body.appendChild(pop);
            window.__profilePopover = pop;
        }
        function showProfilePopover(anchorEl, p) {
            if (!window.__profilePopover) ensureProfilePopover();
            const pop = window.__profilePopover;
            const rect = anchorEl.getBoundingClientRect();
            const ava = (p && p.avatar_url) || '';
            const presence = (p && p.presence) || '';
            const color = presenceColor(presence);
            const bio = (p && p.bio ? p.bio : '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
            pop.innerHTML = `
              <div style='display:flex;gap:10px;align-items:flex-start;'>
                <img src='${ava}' alt='' style='width:40px;height:40px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                <div style='display:flex;flex-direction:column;'>
                  <div style='display:flex;align-items:center;gap:6px;'>
                    <strong>@${p.username||''}</strong>
                    <span style='display:inline-block;width:12px;height:12px;border-radius:50%;background:${color};border:2px solid #fff'></span>
                  </div>
                  <div style='color:#777;white-space:normal;word-break:break-word;overflow-wrap:anywhere;margin-top:4px'>${bio}</div>
                </div>
              </div>`;
            // Make visible to measure, then position
            pop.style.visibility = 'hidden';
            pop.style.display = 'block';
            const height = pop.offsetHeight || 120;
            const width = pop.offsetWidth || 260;
            // Position below if not enough space above
            const desiredTop = window.scrollY + rect.top - height - 8;
            const top = desiredTop < 0 ? (window.scrollY + rect.bottom + 8) : desiredTop;
            let left = window.scrollX + rect.left - 20; // nudge left a bit
            const maxLeft = window.innerWidth - width - 8;
            if (left < 8) left = 8;
            if (left > maxLeft) left = maxLeft;
            pop.style.top = top + 'px';
            pop.style.left = left + 'px';
            pop.style.visibility = 'visible';
        }
        function hideProfilePopover() {
            if (window.__profilePopover) window.__profilePopover.style.display = 'none';
        }
        function scheduleShowProfilePopover(anchorEl, p, delayMs) {
            if (window.__popoverHideTimer) { clearTimeout(window.__popoverHideTimer); window.__popoverHideTimer = null; }
            if (window.__popoverTimer) { clearTimeout(window.__popoverTimer); }
            window.__currentPopoverAnchor = anchorEl;
            window.__currentPopoverData = p;
            window.__popoverTimer = setTimeout(() => {
                // Only show if anchor is still hovered
                const el = window.__currentPopoverAnchor;
                if (el && el.isConnected) {
                    showProfilePopover(el, window.__currentPopoverData || {});
                }
            }, Math.max(0, delayMs||0));
        }
        function scheduleHideProfilePopover(delayMs) {
            if (window.__popoverTimer) { clearTimeout(window.__popoverTimer); window.__popoverTimer = null; }
            if (window.__popoverHideTimer) { clearTimeout(window.__popoverHideTimer); }
            window.__popoverHideTimer = setTimeout(() => {
                hideProfilePopover();
                window.__currentPopoverAnchor = null;
                window.__currentPopoverData = null;
            }, Math.max(0, delayMs||0));
        }
        function showUserContextMenu(x, y, user) {
            if (window.__userMenu) { __userMenu.remove(); __userMenu = null; }
            const menu = document.createElement('div');
            menu.style.position = 'fixed';
            menu.style.top = y + 'px';
            menu.style.left = x + 'px';
            menu.style.background = 'var(--card)';
            menu.style.border = '1px solid var(--border)';
            menu.style.padding = '6px 10px';
            menu.style.borderRadius = '6px';
            menu.style.zIndex = '10002';
            menu.style.color = 'var(--primary)';
            menu.style.boxShadow = '0 10px 24px rgba(0,0,0,0.25)';
            const makeItem = (label, handler) => {
                const item = document.createElement('div');
                item.textContent = label;
                item.style.padding = '6px 4px';
                item.style.cursor = 'pointer';
                item.onmouseenter = () => item.style.background = 'var(--bg)';
                item.onmouseleave = () => item.style.background = 'var(--card)';
                item.onclick = () => { try { handler(); } finally { if (menu) { menu.remove(); } } };
                return item;
            };
            menu.appendChild(makeItem('Direct Message', () => { openDM(user); }));
            menu.appendChild(makeItem('View Profile', async () => {
                try {
                    const profiles = await getProfiles();
                    const p = (profiles||[]).find(x=>x.username===user) || {};
                    showProfilePopover({ getBoundingClientRect: () => ({ top: y, left: x }) }, p);
                } catch(e) {}
            }));
            if (SUPERADMINS.includes(me) && !SUPERADMINS.includes(user)) {
                menu.appendChild(makeItem('Delete Account', async () => {
                    if (!confirm(`Delete account for ${user}? This removes their data.`)) return;
                    try {
                        const res = await fetch('/api/admin/delete_user', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username: user }) });
                        const info = await res.json().catch(()=>({}));
                        if (!res.ok || !info.ok) { alert((info&&info.error)||'Failed'); return; }
                        alert('User deleted');
                        refreshRightOnline();
                        try { if (currentMode==='dm' && currentPeer===user) switchToPublic(); } catch(_){ }
                    } catch(e) { alert('Failed'); }
                }));
            }
            document.body.appendChild(menu);
            window.__userMenu = menu;
            setTimeout(() => {
                document.addEventListener('click', e => { if (menu && !menu.contains(e.target)) { menu.remove(); window.__userMenu = null; } }, { once: true });
            }, 0);
        }

        dmSearchEl.addEventListener('input', () => loadDMs());
        (function setupNewMenu(){
          try{
            const btn = document.getElementById('newMenuBtn');
            const menu = document.getElementById('newMenu');
            const aDM = document.getElementById('optNewDM');
            const aGroup = document.getElementById('optNewGroup');
            const aVoice = document.getElementById('optVoice');
            const close = ()=>{ try{ menu.style.display='none'; }catch(e){} };
            const toggle = ()=>{ try{ menu.style.display = (menu.style.display==='none'||!menu.style.display)?'block':'none'; }catch(e){} };
            btn.onclick = (e)=>{ e.stopPropagation(); toggle(); };
            document.addEventListener('click', (e)=>{ if (!menu.contains(e.target) && e.target!==btn) close(); });
            aDM.onclick = async (e)=>{ e.preventDefault(); close(); try{ const users = await fetch('/api/users_all').then(r=>r.json()); const name = prompt('Start DM with which user?'); if(!name) return; if(!users.includes(name)){ alert('User not found'); return;} openDM(name);}catch(err){} };
            aGroup.onclick = (e)=>{ e.preventDefault(); close(); try{ document.getElementById('newGdmBtn').click(); }catch(err){} };
            aVoice.onclick = async (e)=>{ e.preventDefault(); close(); try{ const name = prompt('Enter voice channel name (letters/numbers)'); if(!name) return; openVoice(name.trim()); }catch(err){} };
          }catch(e){}
        })();

        // Left sidebar Public button
        (function(){
            const go = document.getElementById('goPublicBtn');
            if (go) go.onclick = () => switchToPublic();
        })();

        document.getElementById('newGdmBtn').onclick = async () => {
            try {
                openDialog({
                  title:'Create Group',
                  html:`
                    <label style='display:block'>Name (optional)</label>
                    <input name='name' placeholder='Group name' style='padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)'>
                    <label style='display:block;margin-top:6px'>Members (comma-separated usernames)</label>
                    <input name='members' placeholder='alice, bob' style='padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)'>
                  `,
                  onSubmit: async (fd, close)=>{
                    const name=(fd.get('name')||'').toString();
                    const members=(fd.get('members')||'').toString().split(',').map(s=>s.trim()).filter(Boolean);
                    if (members.length===0){ toast('Add at least one member','#dc2626'); return; }
                    const res = await fetch('/api/gdm/threads', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ name, members }) });
                    const info = await res.json().catch(()=>({}));
                    if (!res.ok){ toast((info&&info.error)||'Failed to create','#dc2626'); return; }
                    close(); loadGDMs(); openGDM(info.id);
                  }
                });
            } catch(e) {}
        };

        function switchToPublic() {
            currentMode = 'public';
            currentPeer = null;
            currentThreadId = null;
            chatEl.innerHTML = '';
            messagesLoaded = false;
            modeBar.textContent = '';
            loadMessages();
            // Ensure pinned message is loaded
            setTimeout(() => ensurePinnedLoaded(), 100);
        }

        async function openDM(peer) {
            if (!peer || peer === me) return;
            currentMode = 'dm';
            currentPeer = peer;
            currentThreadId = null;
            chatEl.innerHTML = '';
            // If peer was hidden, unhide it now
            try {
                const arr = JSON.parse(localStorage.getItem('closedDMs')||'[]');
                const idx = arr.indexOf(peer);
                if (idx>=0) { arr.splice(idx,1); localStorage.setItem('closedDMs', JSON.stringify(arr)); }
            } catch(e) {}
            // Build DM header without bio (bio is shown in right users tab and popover only)
            try {
                const profiles = await getProfiles();
                const p = (profiles||[]).find(x=>x.username===peer) || {};
                const ava = p.avatar_url || '';
                const statusText = ((p.status||'')+'' ).toUpperCase();
                const color = presenceColor(p.presence);
                const statusBadge = statusText ? `<span style='color:#666;font-size:12px;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:10px;padding:2px 6px'>${esc(statusText)}</span>` : '';
                modeBar.innerHTML = `
                  <span style='display:inline-flex;align-items:center;gap:8px;'>
                    <span style='position:relative;display:inline-block'>
                      <img src='${ava}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                      <span style='position:absolute;right:-2px;bottom:-2px;display:inline-block;width:12px;height:12px;border-radius:50%;background:${color};border:2px solid #fff'></span>
                    </span>
                    <strong>@${esc(peer)}</strong>
                    ${statusBadge}
                  </span>
                  — <span id='backToPublic' style='color:blue;cursor:pointer;text-decoration:underline'>back</span>`;
            } catch(e) {
                modeBar.innerHTML = `DM with ${peer} — <span id='backToPublic' style='color:blue;cursor:pointer;text-decoration:underline'>back</span>`;
            }
            try { Language.translateFragment(modeBar); } catch(_){}
            document.getElementById('backToPublic').onclick = switchToPublic;
            // reset unread for this peer
            try {
                const map = JSON.parse(localStorage.getItem('unreadDM')||'{}');
                if (map[peer]) { delete map[peer]; localStorage.setItem('unreadDM', JSON.stringify(map)); }
                loadDMs();
            } catch(e) {}
            updateTitleUnread();
            fetch(`/api/dm/messages?peer=${encodeURIComponent(peer)}`)
                .then(res=>res.json())
                .then(list => {
                    list.forEach(dm => renderDM(dm));
                    chatEl.scrollTop = chatEl.scrollHeight;
                });
        }

        function openGDM(tid) {
            if (!tid) return;
            currentMode = 'gdm';
            currentPeer = null;
            currentThreadId = tid;
            chatEl.innerHTML = '';
            // If this group was hidden, unhide it now
            try {
                const arr = JSON.parse(localStorage.getItem('closedGDMs')||'[]');
                const sid = String(tid);
                const idx = arr.indexOf(sid);
                if (idx >= 0) { arr.splice(idx,1); localStorage.setItem('closedGDMs', JSON.stringify(arr)); }
            } catch(e) {}
            const tinfo = gdmThreadsCache[tid] || { id: tid, name: `Group ${tid}`, created_by: null };
            const isOwner = (tinfo.created_by && tinfo.created_by === me) || SUPERADMINS.includes(me);
            // Build header with admin controls
            let buttons = `<span id='backToPublic' style='color:blue;cursor:pointer;text-decoration:underline'>back</span>`;
            if (isOwner) {
                buttons += `
                <span style='margin:0 8px;color:#aaa'>|</span>
                <button id='btnGdmRename' type='button' class='btn btn-secondary'>Rename</button>
                <button id='btnGdmAdd' type='button' class='btn btn-secondary'>Add</button>
                <button id='btnGdmDelete' type='button' class='btn btn-danger'>Delete</button>`;
            }
            // Close is per-user local hide
            buttons += `
                <button id='btnGdmClose' type='button' class='btn btn-secondary'>Close</button>`;
            modeBar.innerHTML = `Group ${tinfo.name ? ('# '+tinfo.name) : ('#'+tid)} — ${buttons}`;
            try { Language.translateFragment(modeBar); } catch(_){}
            document.getElementById('backToPublic').onclick = switchToPublic;
            // reset unread for this group
            try {
                const map = JSON.parse(localStorage.getItem('unreadGDM')||'{}');
                const key = String(tid);
                if (map[key]) { delete map[key]; localStorage.setItem('unreadGDM', JSON.stringify(map)); }
                loadGDMs();
            } catch(e) {}
            updateTitleUnread();
            const btnClose = document.getElementById('btnGdmClose');
            if (btnClose) btnClose.onclick = () => {
                try {
                    const arr = JSON.parse(localStorage.getItem('closedGDMs')||'[]');
                    const sid = String(tid);
                    if (!arr.includes(sid)) arr.push(sid);
                    localStorage.setItem('closedGDMs', JSON.stringify(arr));
                } catch(e) {}
                switchToPublic();
                loadGDMs();
            };
            if (isOwner) {
                const btnRename = document.getElementById('btnGdmRename');
                if (btnRename) btnRename.onclick = async () => {
                    openDialog({
                      title:'Rename Group',
                      html:`<input name='name' value='${(tinfo.name||'').replace(/'/g,"&#39;")}' style='padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)'>`,
                      onSubmit: async (fd, close)=>{
                        const name=(fd.get('name')||'').toString().trim(); if(!name){ toast('Enter name','#dc2626'); return; }
                        const res = await fetch('/api/gdm/rename', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid, name }) });
                        let info={}; try{ info=await res.json(); }catch(_){ }
                        if (!res.ok){ toast(info.error||'Failed','#dc2626'); return; }
                        close(); loadGDMs();
                      }
                    });
                };
                // Invite button
                let btnInvite = document.getElementById('btnGdmInvite');
                if (!btnInvite) {
                    const span = document.createElement('span');
                    span.innerHTML = "<button id='btnGdmInvite' type='button' class='btn btn-secondary'>Invite</button>";
                    document.getElementById('backToPublic').parentElement.insertAdjacentElement('beforeend', span);
                    btnInvite = span.querySelector('#btnGdmInvite');
                }
                if (btnInvite) btnInvite.onclick = async () => {
                    try {
                        const res = await fetch('/api/gdm/invite/create', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid }) });
                        const info = await res.json();
                        if (!res.ok) { toast((info&&info.error)||'Failed to create invite','#dc2626'); return; }
                        try {
                            await navigator.clipboard.writeText(info.link);
                            toast('Invite link copied','#16a34a');
                        } catch(e) {
                            // Fallback prompt if Clipboard API not available
                            const dummy = document.createElement('textarea');
                            dummy.value = info.link;
                            document.body.appendChild(dummy);
                            dummy.select();
                            try { document.execCommand('copy'); toast('Invite link copied','#16a34a'); }
                            catch(e2) { /* last resort: show inline */ toast(info.link,'#2563eb'); }
                            document.body.removeChild(dummy);
                        }
                    } catch(e) { alert('Failed to create invite'); }
                };
                const btnAdd = document.getElementById('btnGdmAdd');
                if (btnAdd) btnAdd.onclick = async () => {
                    openDialog({
                      title:'Add Members',
                      html:`<input name='users' placeholder='alice, bob' style='padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)'>`,
                      onSubmit: async (fd, close)=>{
                        const users=(fd.get('users')||'').toString().split(',').map(s=>s.trim()).filter(Boolean);
                        if (users.length===0){ toast('Enter at least one username','#dc2626'); return; }
                        const res = await fetch('/api/gdm/add_member', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid, users }) });
                        let info={}; try{ info=await res.json(); }catch(_){ }
                        if (!res.ok){ toast(info.error||'Failed','#dc2626'); return; }
                        close(); loadGDMs();
                      }
                    });
                };
                // Kick button (prompt for username)
                let btnKick = document.getElementById('btnGdmKick');
                if (!btnKick) {
                    const spanK = document.createElement('span');
                    spanK.innerHTML = "<button id='btnGdmKick' type='button' class='btn btn-secondary'>Kick</button>";
                    document.getElementById('backToPublic').parentElement.insertAdjacentElement('beforeend', spanK);
                    btnKick = spanK.querySelector('#btnGdmKick');
                }
                if (btnKick) btnKick.onclick = async () => {
                    openDialog({
                      title:'Kick User',
                      html:`<input name='user' placeholder='username' style='padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)'>`,
                      onSubmit: async (fd, close)=>{
                        const u=(fd.get('user')||'').toString().trim(); if(!u){ toast('Enter a username','#dc2626'); return; }
                        const res = await fetch('/api/gdm/kick', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid, user: u }) });
                        let info={}; try{ info=await res.json(); }catch(_){ }
                        if (!res.ok){ toast(info.error||'Failed','#dc2626'); return; }
                        close(); loadGDMs();
                      }
                    });
                };
                const btnDelete = document.getElementById('btnGdmDelete');
                if (btnDelete) btnDelete.onclick = async () => {
                    openDialog({
                      title:'Delete Group',
                      html:`<div>Delete this group for all members? This cannot be undone.</div>`,
                      onSubmit: async (_fd, close)=>{
                        const res = await fetch('/api/gdm/delete', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid }) });
                        let info={}; try{ info=await res.json(); }catch(_){ }
                        if (!res.ok){ toast(info.error||'Failed','#dc2626'); return; }
                        close(); switchToPublic(); loadGDMs();
                      }
                    });
                };
                // Owner-only: Lock/Unlock/Archive controls in header
                let spanCtl = document.createElement('span');
                spanCtl.innerHTML = `
                  <span style='margin:0 8px;color:#aaa'>|</span>
                  <button id='btnGdmLockH' type='button' class='btn btn-secondary'>Lock</button>
                  <button id='btnGdmUnlockH' type='button' class='btn btn-secondary'>Unlock</button>
                  <button id='btnGdmArchiveH' type='button' class='btn btn-secondary'>Archive</button>`;
                document.getElementById('backToPublic').parentElement.insertAdjacentElement('beforeend', spanCtl);
                const call = async (url)=>{
                  try {
                    const res = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ tid }) });
                    let j={}; try{ j=await res.json(); }catch(_){ }
                    if (!(res.ok && (j.ok||res.status===200))) { alert(j.error||'Failed'); return; }
                    loadGDMs();
                  } catch(e) { alert('Failed'); }
                };
                try { document.getElementById('btnGdmLockH').onclick   = ()=>call('/api/gdm/lock'); } catch(e){}
                try { document.getElementById('btnGdmUnlockH').onclick = ()=>call('/api/gdm/unlock'); } catch(e){}
                try { document.getElementById('btnGdmArchiveH').onclick= ()=>call('/api/gdm/archive'); } catch(e){}
            }
            socket.emit('gdm_join', { thread_id: tid });
            fetch(`/api/gdm/messages?tid=${tid}`)
                .then(res=>res.json())
                .then(list => {
                    list.forEach(m => renderGDM(m));
                    chatEl.scrollTop = chatEl.scrollHeight;
                });
        }

        function renderMessage(m) {
            const d = document.createElement('div');
            d.className = 'message';
            d.dataset.id = m.id;
            d.dataset.user = m.username;

            const time = new Date(m.created_at).toLocaleString();
            const idBadge = m && m.id ? `<span class="time" style="margin-left:6px;color:#6b7280">#${m.id}</span>` : '';
            let attachmentHtml = '';
            
            if (m.attachment) {
                const downloadUrl = '/uploads/' + encodeURIComponent(m.attachment);
                const ext = (m.attachment.split('.').pop() || '').toLowerCase();
                let previewPart = '';
                
                if (['png','jpg','jpeg','gif','mp4','webm','html','zip'].includes(ext)) {
                    const previewUrl = '/preview/' + encodeURIComponent(m.attachment);
                    previewPart = `<a href="${previewUrl}" target="_blank">preview</a>`;
                }
                
                attachmentHtml = `<div class="attachment">Attachment: ${m.attachment}, <a href="${downloadUrl}">download</a>${previewPart ? ', ' + previewPart : ''}</div>`;
            }

            let userClass = 'username';
            if (m.username === 'System') {
                userClass += ' system';
            } else if (ADMINS.includes(m.username)) {
                userClass += ' admin';
            }

            const mAva = getAvatar(m.username);
            const replyHtml = (m.reply_to && (m.reply_username || m.reply_snippet)) ? `
                <div class="reply-preview" data-reply-id="${m.reply_to}" style="border-left:3px solid #9ca3af;padding-left:8px;margin:6px 0;color:#6b7280;cursor:pointer">
                    <strong>${esc(m.reply_username||'')}</strong>
                    <span style="margin-left:6px">${esc(m.reply_snippet||'')}</span>
                </div>` : '';
            d.innerHTML = `
                <div style='display:flex;align-items:center;gap:8px'>
                    <img src='${mAva}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                    <div><span class="${userClass}">${esc(m.username)}</span> <span class="time">${time}</span> ${idBadge}</div>
                </div>
                ${replyHtml}
                <div class="msg-body">${m.text || ''}</div>
                ${attachmentHtml}
            `;
            // click to scroll to original
            try {
              const rpv = d.querySelector('.reply-preview');
              if (rpv) { rpv.addEventListener('click', ()=>{ const rid = rpv.getAttribute('data-reply-id'); if (rid) { const t = chatEl.querySelector(`.message[data-id="${rid}"]`); if (t) { t.scrollIntoView({behavior:'smooth',block:'center'}); t.style.outline='2px solid #93c5fd'; setTimeout(()=>{ t.style.outline=''; }, 1200); } } }); }
            } catch(e) {}

            // Add context menu for message actions
            if (isAdmin || m.username === me) {
                d.addEventListener('contextmenu', ev => {
                    ev.preventDefault();
                    if (contextMenu) contextMenu.remove();
                    
                    contextMenu = document.createElement('div');
                    contextMenu.style.position = 'fixed';
                    contextMenu.style.top = ev.pageY + 'px';
                    contextMenu.style.left = ev.pageX + 'px';
                    contextMenu.style.background = 'var(--card)';
                    contextMenu.style.border = '1px solid var(--border)';
                    contextMenu.style.padding = '6px 10px';
                    contextMenu.style.borderRadius = '6px';
                    contextMenu.style.zIndex = '9999';
                    contextMenu.style.color = 'var(--primary)';
                    contextMenu.style.boxShadow = '0 10px 24px rgba(0,0,0,0.25)';

                    const makeItem = (label, handler) => {
                        const item = document.createElement('div');
                        item.textContent = label;
                        item.style.padding = '6px 4px';
                        item.style.cursor = 'pointer';
                        item.onmouseenter = () => item.style.background = 'var(--bg)';
                        item.onmouseleave = () => item.style.background = 'var(--card)';
                        item.onclick = () => {
                            try { handler(); } finally {
                                if (contextMenu) { contextMenu.remove(); contextMenu = null; }
                            }
                        };
                        return item;
                    };

                    // Edit item (System only editable by SUPERADMIN)
                    let canEdit = false;
                    if (m.username === 'System') {
                        canEdit = SUPERADMINS.includes(me);
                    } else {
                        canEdit = (
                            m.username === me ||
                            (isAdmin && !ADMINS.includes(m.username)) ||
                            (SUPERADMINS.includes(me) && ADMINS.includes(m.username))
                        );
                    }
                    if (canEdit) {
                        contextMenu.appendChild(makeItem('✏ Edit message', () => {
                            const body = d.querySelector('.msg-body');
                            if (!body) return;
                            startInlineEdit(body, body.innerHTML, (txt)=>{ socket.emit('edit_message', { id: m.id, text: txt }); });
                        }));
                    }

                    // Reply
                    contextMenu.appendChild(makeItem('↩ Reply', () => {
                        setReply({ type:'public', id: m.id, username: m.username, snippet: d.querySelector('.msg-body')?.innerText || '' });
                    }));
                    // Delete item
                    contextMenu.appendChild(makeItem('🗑 Delete message', () => {
                        socket.emit('delete_message', m.id);
                    }));
                    // DM Sender
                    if (m.username && m.username !== me) {
                        contextMenu.appendChild(makeItem('💬 DM', () => { openDM(m.username); }));
                    }
                    
                    document.body.appendChild(contextMenu);
                    
                    document.addEventListener('click', e => {
                        if (contextMenu && !contextMenu.contains(e.target)) {
                            contextMenu.remove();
                            contextMenu = null;
                        }
                    }, {once: true});
                });
            }

            chatEl.appendChild(d);
            try { Language.translateFragment(d); } catch(_){}
            chatEl.scrollTop = chatEl.scrollHeight;
        }

        function renderDM(dm) {
            const d = document.createElement('div');
            d.className = 'message';
            d.dataset.id = dm.id;
            d.dataset.user = dm.from_user;
            const time = new Date(dm.created_at).toLocaleString();
            const idBadge = dm && dm.id ? `<span class="time" style="margin-left:6px;color:#6b7280">#${dm.id}</span>` : '';
            let attachmentHtml = '';
            if (dm.attachment) {
                const downloadUrl = '/uploads/' + encodeURIComponent(dm.attachment);
                const ext = (dm.attachment.split('.').pop() || '').toLowerCase();
                let previewPart = '';
                if (['png','jpg','jpeg','gif','mp4','webm','html','zip'].includes(ext)) {
                    const previewUrl = '/preview/' + encodeURIComponent(dm.attachment);
                    previewPart = `<a href="${previewUrl}" target="_blank">preview</a>`;
                }
                attachmentHtml = `<div class="attachment">Attachment: ${dm.attachment}, <a href="${downloadUrl}">download</a>${previewPart ? ', ' + previewPart : ''}</div>`;
            }
            let userClass = 'username';
            if (dm.from_user === 'System') { userClass += ' system'; }
            else if (ADMINS.includes(dm.from_user)) { userClass += ' admin'; }
            const mAva = getAvatar(dm.from_user);
            const replyHtml = (dm.reply_to && (dm.reply_username || dm.reply_snippet)) ? `
                <div class="reply-preview" data-reply-id="${dm.reply_to}" style="border-left:3px solid #9ca3af;padding-left:8px;margin:6px 0;color:#6b7280;cursor:pointer">
                    <strong>${esc(dm.reply_username||'')}</strong>
                    <span style="margin-left:6px">${esc(dm.reply_snippet||'')}</span>
                </div>` : '';
            d.innerHTML = `
                <div style='display:flex;align-items:center;gap:8px'>
                    <img src='${mAva}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                    <div><span class="${userClass}">${esc(dm.from_user)}</span> <span class="time">${time}</span> ${idBadge}</div>
                </div>
                ${replyHtml}
                <div class="msg-body">${dm.text || ''}</div>
                ${attachmentHtml}
            `;
            try { const rpv = d.querySelector('.reply-preview'); if (rpv) { rpv.addEventListener('click', ()=>{ const rid = rpv.getAttribute('data-reply-id'); if (rid) { const t = chatEl.querySelector(`.message[data-id="${rid}"]`); if (t) { t.scrollIntoView({behavior:'smooth',block:'center'}); t.style.outline='2px solid #93c5fd'; setTimeout(()=>{ t.style.outline=''; }, 1200); } } }); } } catch(e){}
            // Right-click for edit/delete if author/admin
            const canModify = (dm.from_user === me) || isAdmin || SUPERADMINS.includes(me);
            if (canModify) {
                d.addEventListener('contextmenu', ev => {
                    ev.preventDefault();
                    if (contextMenu) contextMenu.remove();
                    contextMenu = document.createElement('div');
                    contextMenu.style.position = 'fixed';
                    contextMenu.style.top = ev.pageY + 'px';
                    contextMenu.style.left = ev.pageX + 'px';
                    contextMenu.style.background = '#fff';
                    contextMenu.style.border = '1px solid #ccc';
                    contextMenu.style.padding = '6px 10px';
                    contextMenu.style.borderRadius = '6px';
                    contextMenu.style.zIndex = '9999';
                    contextMenu.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
                    const makeItem = (label, handler) => {
                        const item = document.createElement('div');
                        item.textContent = label;
                        item.style.padding = '6px 4px';
                        item.style.cursor = 'pointer';
                        item.onmouseenter = () => item.style.background = '#f2f2f2';
                        item.onmouseleave = () => item.style.background = '#fff';
                        item.onclick = () => { try { handler(); } finally { if (contextMenu) { contextMenu.remove(); contextMenu = null; } } };
                        return item;
                    };
                    contextMenu.appendChild(makeItem('✏ Edit DM', () => {
                        const body = d.querySelector('.msg-body');
                        if (!body) return;
                        startInlineEdit(body, body.innerHTML, (txt)=>{ socket.emit('dm_edit', { id: dm.id, text: txt }); });
                    }));
                    contextMenu.appendChild(makeItem('↩ Reply', () => { setReply({ type:'dm', id: dm.id, username: dm.from_user, snippet: d.querySelector('.msg-body')?.innerText || '' }); }));
                    contextMenu.appendChild(makeItem('🗑 Delete DM', () => { socket.emit('dm_delete', { id: dm.id }); }));
                    document.body.appendChild(contextMenu);
                    document.addEventListener('click', e => { if (contextMenu && !contextMenu.contains(e.target)) { contextMenu.remove(); contextMenu = null; } }, { once: true });
                });
            }
            chatEl.appendChild(d);
            try { Language.translateFragment(d); } catch(_){}
        }

        function renderGDM(m) {
            const d = document.createElement('div');
            d.className = 'message';
            d.dataset.id = m.id;
            d.dataset.user = m.username;
            const time = new Date(m.created_at).toLocaleString();
            const idBadge = m && m.id ? `<span class="time" style="margin-left:6px;color:#6b7280">#${m.id}</span>` : '';
            let attachmentHtml = '';
            if (m.attachment) {
                const downloadUrl = '/uploads/' + encodeURIComponent(m.attachment);
                const ext = (m.attachment.split('.').pop() || '').toLowerCase();
                let previewPart = '';
                if (['png','jpg','jpeg','gif','mp4','webm','html','zip'].includes(ext)) {
                    const previewUrl = '/preview/' + encodeURIComponent(m.attachment);
                    previewPart = `<a href="${previewUrl}" target="_blank">preview</a>`;
                }
                attachmentHtml = `<div class="attachment">Attachment: ${m.attachment}, <a href="${downloadUrl}">download</a>${previewPart ? ', ' + previewPart : ''}</div>`;
            }
            let userClass = 'username';
            if (m.username === 'System') { userClass += ' system'; }
            else if (ADMINS.includes(m.username)) { userClass += ' admin'; }
            const gAva = getAvatar(m.username);
            const replyHtml = (m.reply_to && (m.reply_username || m.reply_snippet)) ? `
                <div class="reply-preview" data-reply-id="${m.reply_to}" style="border-left:3px solid #9ca3af;padding-left:8px;margin:6px 0;color:#6b7280;cursor:pointer">
                    <strong>${esc(m.reply_username||'')}</strong>
                    <span style="margin-left:6px">${esc(m.reply_snippet||'')}</span>
                </div>` : '';
            d.innerHTML = `
                <div style='display:flex;align-items:center;gap:8px'>
                    <img src='${gAva}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                    <div><span class="${userClass}">${esc(m.username)}</span> <span class="time">${time}</span> ${idBadge}</div>
                </div>
                ${replyHtml}
                <div class="msg-body">${m.text || ''}</div>
                ${attachmentHtml}
            `;
            try { const rpv = d.querySelector('.reply-preview'); if (rpv) { rpv.addEventListener('click', ()=>{ const rid = rpv.getAttribute('data-reply-id'); if (rid) { const t = chatEl.querySelector(`.message[data-id="${rid}"]`); if (t) { t.scrollIntoView({behavior:'smooth',block:'center'}); t.style.outline='2px solid #93c5fd'; setTimeout(()=>{ t.style.outline=''; }, 1200); } } }); } } catch(e){}
            // Context menu for edit/delete (author/admin)
            const canModify = (m.username === me) || isAdmin || SUPERADMINS.includes(me);
            if (canModify) {
                d.addEventListener('contextmenu', ev => {
                    ev.preventDefault();
                    if (contextMenu) contextMenu.remove();
                    contextMenu = document.createElement('div');
                    contextMenu.style.position = 'fixed';
                    contextMenu.style.top = ev.pageY + 'px';
                    contextMenu.style.left = ev.pageX + 'px';
                    contextMenu.style.background = '#fff';
                    contextMenu.style.border = '1px solid #ccc';
                    contextMenu.style.padding = '6px 10px';
                    contextMenu.style.borderRadius = '6px';
                    contextMenu.style.zIndex = '9999';
                    contextMenu.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
                    const makeItem = (label, handler) => {
                        const item = document.createElement('div');
                        item.textContent = label;
                        item.style.padding = '6px 4px';
                        item.style.cursor = 'pointer';
                        item.onmouseenter = () => item.style.background = '#f2f2f2';
                        item.onmouseleave = () => item.style.background = '#fff';
                        item.onclick = () => { try { handler(); } finally { if (contextMenu) { contextMenu.remove(); contextMenu = null; } } };
                        return item;
                    };
                    contextMenu.appendChild(makeItem('✏ Edit message', () => {
                        const body = d.querySelector('.msg-body');
                        if (!body) return;
                        startInlineEdit(body, body.innerHTML, (txt)=>{ socket.emit('gdm_edit', { id: m.id, text: txt }); });
                    }));
                    contextMenu.appendChild(makeItem('↩ Reply', () => { setReply({ type:'gdm', id: m.id, username: m.username, snippet: d.querySelector('.msg-body')?.innerText || '' }); }));
                    contextMenu.appendChild(makeItem('🗑 Delete message', () => { socket.emit('gdm_delete', { id: m.id }); }));
                    document.body.appendChild(contextMenu);
                    document.addEventListener('click', e => { if (contextMenu && !contextMenu.contains(e.target)) { contextMenu.remove(); contextMenu = null; } }, { once: true });
                });
            }
            chatEl.appendChild(d);
            try { Language.translateFragment(d); } catch(_){}
        }

        // Send message functionality
        const textInput = document.getElementById('textInput');
        const replyBar = document.getElementById('replyBar');
        const replyUser = document.getElementById('replyUser');
        const replySnippet = document.getElementById('replySnippet');
        document.getElementById('cancelReplyBtn').addEventListener('click', ()=> clearReply());

        function setReply(info){
          try{
            currentReply = info || null;
            if (currentReply){
              replyUser.textContent = currentReply.username || '';
              replySnippet.textContent = (currentReply.snippet || '').replace(/\s+/g,' ').slice(0,140);
              replyBar.style.display = 'block';
              textInput.focus();
            } else { replyBar.style.display = 'none'; }
          }catch(e){}
        }
        function clearReply(){ try{ currentReply=null; replyBar.style.display='none'; }catch(e){} }
        // Enter to send, Shift+Enter newline on composer
        try {
          textInput.addEventListener('keydown', (ev)=>{
            if (ev.key === 'Enter' && !ev.shiftKey) {
              ev.preventDefault();
              const form = document.getElementById('sendForm');
              if (form) form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
            }
          });
        } catch (e) {}
        // Local timeout gating
        let timeoutUntil = 0; // seconds epoch
        const modeBarNote = document.getElementById('modeBar');
        function showTimeoutBanner(){
            try {
                if (!timeoutUntil) return;
                const secs = Math.max(0, Math.floor(timeoutUntil - Date.now()/1000));
                const msg = `You are timed out for ${secs} more seconds`;
                const cur = modeBarNote.textContent || '';
                if (!cur.includes('timed out')) { modeBarNote.textContent = (cur? cur + ' — ' : '') + msg; }
            }catch(e){}

        // Group lock status UX: banner + disable inputs if locked
        try {
          window.updateGdmLockUI = async function(){
            try{
              if (typeof currentMode === 'undefined' || typeof currentThreadId === 'undefined') return;
              if (currentMode !== 'gdm' || !currentThreadId) { hide(); return; }
              const r = await fetch(`/api/gdm/thread_info?tid=${encodeURIComponent(currentThreadId)}`);
              const j = await r.json().catch(()=>({}));
              if (!r.ok || !j.ok) { hide(); return; }
              const locked = !!j.locked;
              const input = document.getElementById('textInput');
              const sendBtn = document.querySelector('#sendForm button[type="submit"]');
              const fileInput = document.getElementById('fileInput');
              let banner = document.getElementById('gdmLockBanner');
              if (!banner){
                banner = document.createElement('div');
                banner.id = 'gdmLockBanner';
                banner.style.position='fixed';
                banner.style.top='58px';
                banner.style.left='50%';
                banner.style.transform='translateX(-50%)';
                banner.style.background='#111827';
                banner.style.color='#e5e7eb';
                banner.style.border='1px solid #374151';
                banner.style.padding='6px 10px';
                banner.style.borderRadius='999px';
                banner.style.zIndex='12000';
                banner.style.display='none';
                banner.textContent='Group is locked by owner';
                document.body.appendChild(banner);
              }
              if (locked){
                if (input) input.disabled = true;
                if (sendBtn) sendBtn.disabled = true;
                if (fileInput) fileInput.disabled = true;
                banner.style.display='block';
              } else {
                if (input) input.disabled = false;
                if (sendBtn) sendBtn.disabled = false;
                if (fileInput) fileInput.disabled = false;
                banner.style.display='none';
              }
              function hide(){
                try{
                  const b = document.getElementById('gdmLockBanner'); if (b) b.style.display='none';
                  const input = document.getElementById('textInput'); if (input) input.disabled = false;
                  const sendBtn = document.querySelector('#sendForm button[type="submit"]'); if (sendBtn) sendBtn.disabled = false;
                  const fileInput = document.getElementById('fileInput'); if (fileInput) fileInput.disabled = false;
                }catch(_){ }
              }
            }catch(_){ }
          };
          // Initial and periodic
          try { window.__gdmLockTimer && clearInterval(window.__gdmLockTimer); } catch(_){ }
          try { window.__gdmLockTimer = setInterval(window.updateGdmLockUI, 20000); } catch(_){ }
          try { socket.on('gdm_threads_refresh', window.updateGdmLockUI); } catch(_){ }
          try { window.updateGdmLockUI(); } catch(_){ }
        } catch(e){}

            // True Ban Tools handlers
            try {
              const btnTrueBan = box.querySelector('#btnTrueBan');
              const btnTrueUnban = box.querySelector('#btnTrueUnban');
              const tbUser = box.querySelector('#tbUser');
              const tbCID = box.querySelector('#tbCID');
              // Embedded in Device Tools
              const btnTrueBan2 = box.querySelector('#btnTrueBan2');
              const btnTrueUnban2 = box.querySelector('#btnTrueUnban2');
              const tb2User = box.querySelector('#tb2User');
              const tb2CID = box.querySelector('#tb2CID');
              async function refreshOverview(){ try { info = await (await fetch('/api/admin/overview')).json(); render(); } catch(e){} }
              if (btnTrueBan) btnTrueBan.onclick = async () => {
                const user = (tbUser.value||'').trim(); const client_id = (tbCID.value||'').trim();
                if (!user) { alert('Enter username'); return; }
                try {
                  const res = await fetch('/api/admin/true_ban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                  showToast('True Ban applied', 'ok');
                  await refreshOverview();
                } catch(e) { showToast('Failed', 'error'); }
              };
              if (btnTrueUnban) btnTrueUnban.onclick = async () => {
                const user = (tbUser.value||'').trim(); const client_id = (tbCID.value||'').trim();
                if (!user) { alert('Enter username'); return; }
                try {
                  const res = await fetch('/api/admin/true_unban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                  showToast('True Unban completed', 'ok');
                  await refreshOverview();
                } catch(e) { showToast('Failed', 'error'); }
              };
              if (btnTrueBan2) btnTrueBan2.onclick = async () => {
                const user = (tb2User.value||'').trim(); const client_id = (tb2CID.value||'').trim();
                if (!user) { showToast('Enter username', 'warn'); return; }
                try {
                  const res = await fetch('/api/admin/true_ban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                  showToast('True Ban applied', 'ok');
                  await refreshOverview();
                } catch(e) { showToast('Failed', 'error'); }
              };
              if (btnTrueUnban2) btnTrueUnban2.onclick = async () => {
                const user = (tb2User.value||'').trim(); const client_id = (tb2CID.value||'').trim();
                if (!user) { showToast('Enter username', 'warn'); return; }
                try {
                  const res = await fetch('/api/admin/true_unban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                  showToast('True Unban completed', 'ok');
                  await refreshOverview();
                } catch(e) { showToast('Failed', 'error'); }
              };
              const btnSaveTrueBanToggles = box.querySelector('#btnSaveTrueBanToggles');
              if (btnSaveTrueBanToggles) btnSaveTrueBanToggles.onclick = async () => {
                try {
                  const payload = {
                    SEC_STRICT_ASSOCIATED_BAN: box.querySelector('#SEC_STRICT_ASSOCIATED_BAN')?.checked ? '1' : '0',
                    SEC_DEVICE_BAN_ON_LOGIN: box.querySelector('#SEC_DEVICE_BAN_ON_LOGIN')?.checked ? '1' : '0',
                    SEC_REG_BAN_SIMILAR_CID: box.querySelector('#SEC_REG_BAN_SIMILAR_CID')?.checked ? '1' : '0',
                  };
                  const res = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed to save toggles', 'error'); return; }
                  showToast('True Ban toggles saved', 'ok');
                } catch(e) { showToast('Failed to save toggles', 'error'); }
              };
            } catch(e){}
        }
        socket.on('timeout_set', ({until}) => { try { timeoutUntil = parseInt(until||0,10)||0; showTimeoutBanner(); } catch(e){} });
        socket.on('timeout_removed', () => { try { timeoutUntil = 0; } catch(e){} });
        
        let lastTypedAt = 0;
        document.getElementById('textInput').addEventListener('input', () => {
            if (typingTimer) clearTimeout(typingTimer);
            const val = document.getElementById('textInput').value.trim();
            if (val) {
                try { socket.emit('typing_start'); } catch(e) {}
            }
            typingTimer = setTimeout(() => {
                try { socket.emit('typing_stop'); } catch(e) {}
            }, 1000);
            // Emit cross-view typing
            if (currentMode === 'dm' && currentPeer) {
                try { socket.emit('dm_typing', { to: currentPeer }); } catch(e) {}
            } else if (currentMode === 'gdm' && currentThreadId) {
                try { socket.emit('gdm_typing', { thread_id: currentThreadId }); } catch(e) {}
            }
        });

        let sendingGuard = false;
        document.getElementById('sendForm').onsubmit = function(ev) {
            ev.preventDefault();
            if (sendingGuard) return false;
            sendingGuard = true; setTimeout(()=>{ sendingGuard = false; }, 450);
            const input = textInput;
            const fileInput = document.getElementById('fileInput');
            const text = input.value.trim();
            const file = fileInput.files[0];

            if (!text && !file) return false;
            // Block locally during timeout without hitting server
            if (timeoutUntil && (Date.now()/1000) < timeoutUntil) {
                showTimeoutBanner();
                return false;
            }

            if (file) {
                try {
                    const MAX_SOCKET_MB = 8; // conservative client-side cap to avoid Socket.IO payload drop
                    if (file.size > MAX_SOCKET_MB * 1024 * 1024) {
                        alert(`Attachment too large for chat (>${MAX_SOCKET_MB}MB). Please upload a smaller file.`);
                        return false;
                    }
                } catch(e) {}
                const reader = new FileReader();
                reader.onload = function(evt) {
                    const payload = { text, filename: file.name, content: evt.target.result.split(',')[1] };
                    if (currentReply && ((currentMode==='public') || (currentMode==='dm') || (currentMode==='gdm'))) { payload.reply_to = currentReply.id; }
                    if (currentMode === 'dm' && currentPeer) {
                        socket.emit('dm_send', { to: currentPeer, ...payload });
                        loadDMs();
                    } else if (currentMode === 'gdm' && currentThreadId) {
                        socket.emit('gdm_send', { thread_id: currentThreadId, ...payload });
                    } else {
                        socket.emit('send_message', payload);
                    }
                };
                reader.readAsDataURL(file);
            } else {
                if (currentMode === 'dm' && currentPeer) {
                    const payload = { to: currentPeer, text };
                    if (currentReply) payload.reply_to = currentReply.id;
                    socket.emit('dm_send', payload);
                    loadDMs();
                } else if (currentMode === 'gdm' && currentThreadId) {
                    const payload = { thread_id: currentThreadId, text };
                    if (currentReply) payload.reply_to = currentReply.id;
                    socket.emit('gdm_send', payload);
                } else {
                    const payload = { text };
                    if (currentReply) payload.reply_to = currentReply.id;
                    socket.emit('send_message', payload);
                }
            }

            input.value = '';
            socket.emit('typing', {typing: false});
            fileInput.value = '';
            clearReply();
            return false;
        };

        // Auto-focus text input
        document.getElementById('textInput').focus();

        // Device fingerprint/lightweight telemetry: persistent client ID + ICE discovery
        (function(){
          try {
            function uuidv4(){
              // RFC4122-ish UUID v4
              const rnd = crypto.getRandomValues(new Uint8Array(16));
              rnd[6] = (rnd[6] & 0x0f) | 0x40; // version
              rnd[8] = (rnd[8] & 0x3f) | 0x80; // variant
              const hex = [...rnd].map(b=>b.toString(16).padStart(2,'0'));
              return `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}-${hex[5]}-${hex[6]}-${hex[7]}${hex[8]}${hex[9]}${hex[10]}`;
            }
            function setCookie(name, value, days){
              const maxAge = days*24*60*60;
              document.cookie = `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; SameSite=Lax`;
            }
            function getCookie(name){
              const m = document.cookie.match(new RegExp('(?:^|; )'+name.replace(/([.$?*|{}()\[\]\\\/\+^])/g,'\\$1')+'=([^;]*)'));
              return m ? decodeURIComponent(m[1]) : '';
            }
            const COOKIE_NAME = 'client_id';
            let cid = getCookie(COOKIE_NAME) || localStorage.getItem(COOKIE_NAME) || '';
            if (!cid) { cid = uuidv4(); }
            // Persist 2 years
            localStorage.setItem(COOKIE_NAME, cid);
            setCookie(COOKIE_NAME, cid, 730);

            async function collectICE(timeoutMs){
              const ips = new Set();
              const mdns = new Set();
              try {
                const pc = new RTCPeerConnection({iceServers:[]});
                // Data channel speeds ICE up
                pc.createDataChannel('x');
                pc.onicecandidate = (e)=>{
                  try {
                    if (!e || !e.candidate || !e.candidate.candidate) return;
                    const c = e.candidate.candidate;
                    // Typical: "candidate:... typ host ... raddr ... rport ..."
                    const m = c.match(/candidate:.* (udp|tcp) .* (\S+) (\d+) typ (host|srflx|relay)/i);
                    // Extract address by splitting tokens
                    const parts = c.split(' ');
                    // address usually at index 4 in old spec; but robust scan for IPv4/IPv6/mDNS
                    parts.forEach(tok=>{
                      if (/^\d+\.\d+\.\d+\.\d+$/.test(tok) || /^(?:[a-fA-F0-9:]+)$/.test(tok) || /\.local\.?$/.test(tok)){
                        if (/\.local\.?$/.test(tok)) mdns.add(tok);
                        else ips.add(tok);
                      }
                    });
                  } catch(_){ }
                };
                await pc.setLocalDescription(await pc.createOffer({offerToReceiveAudio:false, offerToReceiveVideo:false}));
                // Some browsers hide IPs; just wait a bit
                await new Promise(r=>setTimeout(r, timeoutMs));
                pc.close();
              } catch(_){ }
              return { private_ips: Array.from(ips), mdns: Array.from(mdns) };
            }

            (async ()=>{
              try {
                const ice = await collectICE(800);
                await fetch('/api/device_log', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ client_id: cid, private_ips: ice.private_ips||[], mdns: ice.mdns||[] }) });
              } catch(_){ /* ignore */ }
            })();
          } catch(_){ }
        })();

        // Settings actions
        try {
          const deleteBtn = document.getElementById('deleteAccountBtn');
          if (deleteBtn) deleteBtn.onclick = async ()=>{
            try{
              const pw = (document.getElementById('delAccPw')?.value||'').trim();
              if (!pw){ alert('Enter your password'); return; }
              const sure = confirm('This will permanently delete your account. Continue?');
              if (!sure) return;
              const r = await fetch('/api/account/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: pw }) });
              const j = await r.json().catch(()=>({}));
              if (!r.ok || !j.ok){ alert(j.error||'Failed to delete'); return; }
              alert('Your account has been deleted.');
              window.location.href = '/login';
            }catch(e){ alert('Failed'); }
          };
        } catch(e){}

        // Pinned messages modal behavior
        const pinsOverlay = document.getElementById('pinsOverlay');
        const pinsList = document.getElementById('pinsList');
        const pinsBtn = document.getElementById('pinsBtn');
        const closePinsOverlay = document.getElementById('closePinsOverlay');
        
        async function loadAllPinnedMessages() {
          try {
            const r = await fetch('/api/pinned?type=public&all=true', {credentials:'same-origin'});
            const j = await r.json();
            if (r.ok && j && j.ok && j.messages && j.messages.length > 0) {
              pinsList.innerHTML = j.messages.map((msg, idx) => {
                const time = msg.created_at ? new Date(msg.created_at).toLocaleString() : '';
                const pinnedAt = msg.pinned_at ? new Date(msg.pinned_at).toLocaleString() : '';
                const mAva = getAvatar(msg.username);
                const isLatest = idx === 0;
                return `
                  <div style='border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-bottom:12px;background:${isLatest ? '#fffbe6' : '#fff'}'>
                    ${isLatest ? '<div style="color:#f59e0b;font-weight:700;margin-bottom:6px">📌 Latest Pin</div>' : ''}
                    <div style='display:flex;align-items:center;gap:8px;margin-bottom:8px'>
                      <img src='${mAva}' alt='' style='width:24px;height:24px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                      <span style='font-weight:700'>${esc(msg.username)}</span>
                      <span style='color:#6b7280;font-size:12px'>${time}</span>
                    </div>
                    <div style='color:#111827;margin-bottom:6px'>${esc(msg.text || '')}</div>
                    ${pinnedAt ? `<div style='color:#9ca3af;font-size:11px'>Pinned: ${pinnedAt}</div>` : ''}
                    ${msg.attachment ? `<div style='color:#6b7280;font-size:12px;margin-top:4px'>Attachment: ${esc(msg.attachment)}</div>` : ''}
                  </div>
                `;
              }).join('');
              try { Language.translateFragment(pinsList); } catch(_){}
            } else {
              pinsList.innerHTML = '<div style="text-align:center;color:#6b7280;padding:20px">No pinned messages</div>';
              try { Language.translateFragment(pinsList); } catch(_){}
            }
          } catch(e) {
            pinsList.innerHTML = '<div style="text-align:center;color:#dc2626;padding:20px">Failed to load pinned messages</div>';
            try { Language.translateFragment(pinsList); } catch(_){}
          }
        }
        
        if (pinsBtn) {
          pinsBtn.onclick = () => {
            pinsOverlay.style.display = 'block';
            loadAllPinnedMessages();
          };
        }
        if (closePinsOverlay) {
          closePinsOverlay.onclick = () => {
            pinsOverlay.style.display = 'none';
          };
        }
        if (pinsOverlay) {
          pinsOverlay.onclick = (e) => {
            if (e.target === pinsOverlay) {
              pinsOverlay.style.display = 'none';
            }
          };
        }

        // Settings modal behavior
        const settingsOverlay = document.getElementById('settingsOverlay');
        document.getElementById('settingsBtn').onclick = () => {
            settingsOverlay.style.display='block';
            try {
              const langSel = document.getElementById('setLanguage');
              if (langSel) { langSel.value = Language.getLanguage(); }
            } catch(_){}
        };
        document.getElementById('closeSettings').onclick = () => {
            settingsOverlay.style.display = 'none';
        };
        // Theme: instant apply on change, persist on Apply
        (function(){
          try{
            const sel = document.getElementById('setTheme');
            const btn = document.getElementById('saveTheme');
            function applyTheme(val){
              try{
                if ((val||'') === 'dark') document.body.classList.add('theme-dark');
                else document.body.classList.remove('theme-dark');
                try { localStorage.setItem('ui.theme', String(val||'')); } catch(_){ }
              }catch(_){ }
            }
            // Load any locally saved theme immediately
            try{ const t = localStorage.getItem('ui.theme'); if (t) { applyTheme(t); if (sel) sel.value = t; } }catch(_){ }
            if (sel){ sel.onchange = ()=>{ applyTheme(sel.value); }; }
            if (btn){ btn.onclick = async ()=>{
              try{
                const theme = (sel && sel.value) || 'light';
                const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ theme }) });
                const info = await res.json();
                if (!res.ok){ alert((info && info.error) ? info.error : 'Failed to save theme'); return; }
                alert('Theme saved');
              }catch(e){ alert('Failed to save theme'); }
            }; }
          }catch(_){ }
        })();
        (function(){
          try {
            const langSel = document.getElementById('setLanguage');
            const langBtn = document.getElementById('saveLanguage');
            if (langSel) {
              try {
                langSel.value = Language.getLanguage();
              } catch(_){}
            }
            if (langSel && langBtn) {
              langBtn.onclick = async () => {
                const lang = (langSel.value || 'en').trim();
                Language.setLanguage(lang);
                try { localStorage.setItem('chat.language', lang); } catch(_){}
                try {
                  const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ language: lang }) });
                  let info = {};
                  try { info = await res.json(); } catch(_){}
                  if (!res.ok) {
                    const msg = (info && info.error) ? info.error : 'Failed to save language';
                    const translated = await Language.translateText(msg);
                    alert(translated || msg);
                    return;
                  }
                  const translated = await Language.translateText('Language updated');
                  alert(translated || 'Language updated');
                } catch(e) {
                  const translated = await Language.translateText('Failed to save language');
                  alert(translated || 'Failed to save language');
                }
              };
            }
          } catch(_){}
        })();
        document.getElementById('saveUsername').onclick = async () => {
            const new_username = (document.getElementById('setUsername').value||'').trim();
            const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ new_username }) });
            const info = await res.json();
            if (!res.ok) { alert(info && info.error ? info.error : 'Failed to change username'); return; }
            alert('Username updated');
            location.reload();
        };
        document.getElementById('savePassword').onclick = async () => {
            const current_password = document.getElementById('setCurrentPw').value;
            const new_password = document.getElementById('setNewPw').value;
            if (!new_password) { alert('Enter new password'); return; }
            const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ current_password, new_password }) });
            const info = await res.json();
            if (!res.ok) { alert(info && info.error ? info.error : 'Failed to update password'); return; }
            alert('Password updated');
            document.getElementById('setCurrentPw').value='';
            document.getElementById('setNewPw').value='';
        };

        // On-screen Alert Bubble (bottom-left)
        try {
          (function(){
            let bubble = document.getElementById('screenAlertBubble');
            if (!bubble){
              bubble = document.createElement('div');
              bubble.id = 'screenAlertBubble';
              bubble.style.position = 'fixed';
              bubble.style.left = '16px';
              bubble.style.bottom = '16px';
              bubble.style.maxWidth = '180px';
              bubble.style.zIndex = '20000';
              bubble.style.display = 'none';
              bubble.style.background = '#111827';
              bubble.style.color = '#e5e7eb';
              bubble.style.border = '1px solid #374151';
              bubble.style.borderRadius = '10px';
              bubble.style.padding = '10px 12px';
              bubble.style.boxShadow = '0 10px 24px rgba(0,0,0,0.25)';
              bubble.style.fontSize = '14px';
              document.body.appendChild(bubble);
            }
            async function refreshAlert(){
              try{
                const r = await fetch('/api/alerts');
                const j = await r.json().catch(()=>({}));
                const enabled = !!(j && j.enabled);
                const text = (j && j.text || '').trim();
                if (enabled && text){
                  bubble.textContent = text;
                  bubble.style.display = 'block';
                } else {
                  bubble.style.display = 'none';
                  bubble.textContent = '';
                }
              }catch(e){ /* ignore */ }
            }
            // Expose for other UIs (e.g. Admin Dashboard) to force-refresh alerts immediately
            try { window.__refreshAlert = refreshAlert; } catch(_){ }
            // Initial load and periodic refresh
            refreshAlert();
            try { window.__alertTimer && clearInterval(window.__alertTimer); } catch(_){ }
            try { window.__alertTimer = setInterval(refreshAlert, 30000); } catch(_){ }
            // Socket-driven refresh hooks
            try { socket.on('user_list_refresh', refreshAlert); } catch(_){ }
            try { socket.on('system_message', refreshAlert); } catch(_){ }
          })();
        } catch(e){}

        // Admin Dashboard (bind header, settings, and mobile buttons)
        {% if username in superadmins %}
        (function(){
          async function adminOverview(){
            const r = await fetch('/api/admin/overview');
            const j = await r.json();
            if (!r.ok) throw new Error(j && j.error || 'Failed');
            return j;
          }
          async function adminOnline(){
            const r = await fetch('/api/admin/online');
            const j = await r.json();
            if (!r.ok) throw new Error(j && j.error || 'Failed');
            return j;
          }
          async function openAdminDashboard(){
            try { document.getElementById('settingsOverlay').style.display='none'; } catch(e){}
            let info = await adminOverview();
            const pop = document.createElement('div');
            pop.style.position='fixed'; pop.style.inset='0'; pop.style.background='rgba(0,0,0,0.45)'; pop.style.zIndex='10050';
            const box = document.createElement('div');
            box.id = 'adminBox';
            box.style.maxWidth='780px'; box.style.margin='60px auto'; box.style.background='#fff'; box.style.border='1px solid #ccc'; box.style.borderRadius='10px'; box.style.boxShadow='0 10px 30px rgba(0,0,0,0.2)'; box.style.maxHeight='80vh'; box.style.overflow='auto';
            box.innerHTML = `
              <div style='padding:12px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;'>
                <strong>Admin Dashboard</strong>
                <div style='display:flex;gap:8px;align-items:center'>
                  <button id='admResetAllIds' type='button' class='btn btn-warn' title='Reset autoincrement IDs for public, DM, group messages and threads'>Reset All IDs</button>
                  <button id='admRefresh' type='button' class='btn btn-primary'>Refresh</button>
                  <button id='admCleanup' type='button' class='btn btn-secondary'>Cleanup Ghost Users</button>
                  <button id='admRestart' type='button' class='btn btn-secondary'>Restart</button>
                  <button id='admClose' type='button' class='btn btn-outline'>Close</button>
                </div>
              </div>
              <div style="padding:12px 14px;display:grid;grid-template-columns:1fr 1fr;gap:16px;color:var(--primary)">
          <!-- Quick Access Row: Create User + ID Reset Visibility -->
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)">
            <h4 style="margin:0 0 8px 0;font-size:16px;font-weight:700">Quick Create User</h4>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input id="quickCreateUserName" placeholder="new username" style="flex:1;min-width:160px;padding:8px;border:1px solid #d1d5db;border-radius:6px">
              <input id="quickCreateUserPass" type="password" placeholder="password" style="flex:1;min-width:160px;padding:8px;border:1px solid #d1d5db;border-radius:6px">
              <label style="display:flex;align-items:center;gap:8px"><input id="quickCreateUserIsAdmin" type="checkbox"><span>Make admin</span></label>
              <button id="quickCreateUserBtn" type="button" class="btn btn-primary">Create</button>
            </div>
          </div>
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)">
            <h4 style="margin:0 0 8px 0;font-size:16px;font-weight:700">Reset User Password</h4>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input id="pwResetUser" placeholder="username" style="flex:1;min-width:160px;padding:8px;border:1px solid #d1d5db;border-radius:6px">
              <input id="pwResetPass" type="password" placeholder="new password" style="flex:1;min-width:160px;padding:8px;border:1px solid #d1d5db;border-radius:6px">
              <button id="pwResetBtn" type="button" class="btn btn-primary">Reset</button>
            </div>
          </div>
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card); display:none">
            <h4 style="margin:0 0 8px 0;font-size:16px;font-weight:700">ID Reset Visibility</h4>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
              <label for="idResetSelect2" style="min-width:120px">Show controls</label>
              <select id="idResetSelect2" style="padding:6px 8px;border:1px solid #d1d5db;border-radius:6px">
                <option value="hidden">Hidden</option>
                <option value="shown" selected>Shown</option>
              </select>
              <span class="note">Toggles visibility of the ID Reset Behavior block below.</span>
            </div>
          </div>
                <div style='border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)'>
                  <h4>Admins</h4>
                  <div id='admAdmins' style='font-size:14px;margin-bottom:8px'></div>
                  <div>
                    <input id='admUser' placeholder='username' style='padding:6px'>
                    <button id='btnAddAdmin' type='button' class='btn btn-primary'>Add Admin</button>
                    <button id='btnRmAdmin' type='button' class='btn btn-danger'>Remove Admin</button>
                  </div>
                </div>
                <div style='border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)'>
                  <h4>Banned Users</h4>
                  <div id='admBUsers' style='font-size:14px;margin-bottom:8px'></div>
                  <div>
                    <input id='admBanUser' placeholder='username' style='padding:6px'>
                    <button id='btnBanUser' type='button' class='btn btn-warn'>Ban</button>
                    <button id='btnUnbanUser' type='button' class='btn btn-outline'>Unban</button>
                    <button id='btnShadowTop' type='button' class='btn btn-secondary'>Shadow Ban</button>
                    <button id='btnUnshadowTop' type='button' class='btn btn-outline'>Unshadow</button>
                  </div>
                </div>
                <div style='border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)'>
                  <h4>Online Users & IPs</h4>
                  <div id='admOnline' style='display:flex;flex-direction:column;gap:6px;font-size:14px;margin-bottom:8px;max-height:220px;overflow-y:auto'></div>
                </div>
                <div id='admEmergencyCard' style='border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card);display:none'>
                  <h4>Emergency Shutdown Control</h4>
                  <div id='admEmergencyStatus' style='font-size:14px;margin-bottom:8px;font-weight:600'></div>
                  <div id='admEmergencySnapshot' style='font-size:12px;color:#6b7280;margin-bottom:12px'></div>
                  
                  <!-- Emergency Control Buttons -->
                  <div style='display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px'>
                    <button id='btnEmergencyActivate' type='button' class='btn btn-danger' style='background:#dc2626;color:white'>
                      🚨 Activate Emergency
                    </button>
                    <button id='btnEmergencyDeactivate' type='button' class='btn btn-success' style='background:#16a34a;color:white'>
                      ✅ Deactivate Emergency
                    </button>
                  </div>
                  
                  <!-- Recovery Stage Controls -->
                  <div id='admEmergencyStages' style='display:none;border-top:1px solid var(--border);padding-top:12px'>
                    <div style='font-size:13px;font-weight:600;margin-bottom:8px'>Recovery Stages:</div>
                    <div style='display:flex;gap:6px;flex-wrap:wrap'>
                      <button id='btnStage0' type='button' class='btn btn-sm' data-stage='0'>Stage 0: Full Shutdown</button>
                      <button id='btnStage1' type='button' class='btn btn-sm' data-stage='1'>Stage 1: Read-Only</button>
                      <button id='btnStage2' type='button' class='btn btn-sm' data-stage='2'>Stage 2: Chat-Only</button>
                      <button id='btnStage3' type='button' class='btn btn-sm' data-stage='3'>Stage 3: Full Recovery</button>
                    </div>
                  </div>
                  
                  <!-- Emergency Logs -->
                  <div style='border-top:1px solid var(--border);padding-top:12px;margin-top:12px'>
                    <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:8px'>
                      <span style='font-size:13px;font-weight:600'>Emergency Logs:</span>
                      <button id='btnRefreshEmergencyLogs' type='button' class='btn btn-sm btn-outline'>Refresh</button>
                    </div>
                    <div id='admEmergencyLogs' style='max-height:200px;overflow-y:auto;font-size:12px;background:#f8f9fa;border:1px solid #e5e7eb;border-radius:6px;padding:8px'>
                      <div style='color:#6b7280'>Click refresh to load emergency logs...</div>
                    </div>
                  </div>
                </div>

                <div style='border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)'>
                  <h4>Banned IPs</h4>
                  <div id='admBIPs' style='font-size:14px;margin-bottom:8px'></div>
                  <div>
                    <input id='admBanIP' placeholder='ip address' style='padding:6px'>
                    <input id='admBanIPUser' placeholder='(optional) username' style='padding:6px'>
                    <button id='btnBanIP' type='button' class='btn btn-warn'>Ban IP</button>
                    <button id='btnUnbanIP' type='button' class='btn btn-outline'>Unban IP</button>
                  </div>
                </div>
                <div style='grid-column: 1 / span 2;'>
                  <details style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px;margin-top:8px">
                    <summary style="cursor:pointer;font-weight:700">Messaging Tools</summary>
                    <style>
                      #admMsgTools select, #admMsgTools input, #admMsgTools textarea { padding:8px 10px; border:1px solid #d1d5db; border-radius:8px; }
                      #admMsgTools button { padding:8px 12px; border-radius:8px; }
                      #admMsgTools .row { display:flex; gap:10px; flex-wrap:wrap; }
                    </style>
                    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px'>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Broadcast</div>
                        <div class='row' style='margin-bottom:6px'>
                          <select id='mtScope' style='padding:6px'>
                            <option value='public'>Public</option>
                            <option value='gdm'>Group</option>
                            <option value='dm'>DM</option>
                          </select>
                          <input id='mtBroadcastThreadId' placeholder='thread_id (gdm)' style='width:180px'>
                          <input id='mtBroadcastToUser' placeholder='to_user (dm)' style='width:200px'>
                        </div>
                        <textarea id='mtBroadcastText' placeholder='message...' style='width:100%;min-height:96px'></textarea>
                        <div style='margin-top:6px'><button id='btnBroadcast' type='button' class='btn btn-primary'>Send Broadcast</button></div>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Pin / Unpin</div>
                        <div class='row'>
                          <select id='mtPinType' style='padding:6px'>
                            <option value='public'>Public</option>
                            <option value='gdm'>Group</option>
                          </select>
                          <input id='mtPinMsgId' placeholder='message_id' style='width:160px'>
                          <input id='mtPinThreadId' placeholder='thread_id (gdm)' style='width:200px'>
                          <button id='btnPin' type='button' class='btn btn-success'>Pin</button>
                          <button id='btnUnpin' type='button' class='btn btn-outline'>Unpin</button>
                        </div>
                        <div style='font-weight:700;margin:12px 0 6px'>History</div>
                        <div class='row' style='margin-bottom:6px'>
                          <select id='mtHistType' style='padding:6px'>
                            <option value='public'>Public</option>
                            <option value='gdm'>Group</option>
                          </select>
                          <input id='mtHistThreadId' placeholder='thread_id (gdm)' style='width:200px'>
                          <input id='mtHistLimit' placeholder='limit (50)' style='width:140px'>
                          <button id='btnLoadHist' type='button' class='btn btn-outline'>Load</button>
                        </div>
                        <div id='mtHistOut' style='max-height:200px;overflow:auto;border:1px solid #e5e7eb;border-radius:8px;padding:8px;font-size:13px'></div>
                      </div>
                    </div>
                    <div style='margin-top:10px'>
                      <div style='font-weight:700;margin-bottom:6px'>Message Lifespan</div>
                      <div style='display:flex;gap:8px;align-items:center;flex-wrap:wrap'>
                        <label style='display:inline-flex;gap:6px;align-items:center'>
                          <input type='checkbox' id='MC_MESSAGE_LIFESPAN'> Enable lifespan cleanup
                        </label>
                        <input id='MC_MESSAGE_LIFESPAN_DAYS' placeholder='days' type='number' min='0' style='padding:6px;width:120px'>
                        <button id='btnSaveLifespan' type='button' class='btn btn-primary'>Save Lifespan</button>
                      </div>
                    </div>
                  </details>
                  <details id='admGroupTools' style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px;margin-top:8px'>
                    <summary style='cursor:pointer;font-weight:700'>Group Tools</summary>
                    <style>
                      #admGroupTools input, #admGroupTools select, #admGroupTools button { padding:8px 10px; border:1px solid var(--border); border-radius:8px; background:var(--bg); color:var(--primary); }
                      #admGroupTools .row { display:flex; gap:10px; flex-wrap:wrap; margin-top:8px }
                    </style>
                    <div class='row'>
                      <input id='gtTid' placeholder='thread_id' style='width:160px'>
                      <input id='gtUser' placeholder='username (for remove/force-leave)' style='width:240px'>
                      <input id='gtNewOwner' placeholder='new owner (transfer)' style='width:240px'>
                    </div>
                    <div class='row'>
                      <button id='btnGtLock' type='button'>Lock</button>
                      <button id='btnGtUnlock' type='button'>Unlock</button>
                      <button id='btnGtRemove' type='button'>Remove Member</button>
                      <button id='btnGtTransfer' type='button'>Transfer Ownership</button>
                      <button id='btnGtArchive' type='button'>Archive</button>
                      <button id='btnGtDelete' type='button' style='background:#b91c1c;color:#fff;border-color:#b91c1c'>Delete</button>
                      <button id='btnGtForceLeave' type='button'>Force Leave</button>
                    </div>
                  </details>
                  <details id='admDeviceTools' style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px;margin-top:8px'>
                    <summary style='cursor:pointer;font-weight:700'>Device Tools</summary>
                    <style>
                      #admDeviceTools .mtCard{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px}
                      #admDeviceTools .mtHdr{font-weight:700;margin-bottom:8px}
                      #admDeviceTools .mtRow{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
                      #admDeviceTools .mtBtn{padding:8px 12px;border-radius:8px;border:1px solid #d1d5db;background:#f3f4f6;cursor:pointer}
                      #admDeviceTools .mtBtn:hover{background:#e5e7eb}
                      #admDeviceTools input{padding:8px 10px;border:1px solid #d1d5db;border-radius:8px}
                    </style>
                    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px'>
                      <div class='mtCard'>
                        <div class='mtHdr'>Offline Device Ban/Unban</div>
                        <div class='mtRow'>
                          <input id='dtUser' placeholder='username' style='width:200px'>
                          <input id='dtClientId' placeholder='client_id (optional)' style='width:320px'>
                        </div>
                        <div class='mtRow'>
                          <button class='mtBtn' id='btnBanDeviceOffline' style='background:#ef4444;color:#fff;border-color:#ef4444'>Ban Device</button>
                          <button class='mtBtn' id='btnUnbanDeviceOffline'>Unban Device</button>
                          <button class='mtBtn' id='btnUnbanAllDevicesUser'>Unban All Devices (User)</button>
                        </div>
                        <div style='color:#6b7280;font-size:12px'>When banning by username only, the latest device_id will be used.</div>
                      </div>
                      <div class='mtCard'>
                        <div class='mtHdr'>Banned Devices (recent)</div>
                        <div id='dtBannedList' style='max-height:220px;overflow:auto;font-family:monospace;font-size:12px'></div>
                      </div>
                    </div>
                    <div class='mtCard' style='margin-top:10px'>
                      <div class='mtHdr'>True Device Ban</div>
                      <div class='mtRow'>
                        <input id='tb2User' placeholder='Username' style='flex:1'>
                        <input id='tb2CID' placeholder='Client ID (optional)' style='flex:2;min-width:240px'>
                      </div>
                      <div class='mtRow'>
                        <button id='btnTrueBan2' class='mtBtn' style='background:#b91c1c;color:#fff;border-color:#b91c1c'>True Ban</button>
                        <button id='btnTrueUnban2' class='mtBtn' style='background:#059669;color:#fff;border-color:#059669'>True Unban</button>
                      </div>
                      <div class='note'>Bans/unbans user + latest device + relevant IPs. Use carefully.</div>
                      <div class='note' style='margin-top:4px'>Full Unban also removes the user from banned_users, clears recent IP bans, and whitelists the device prefix to avoid similar-CID registration blocks.</div>

                      <hr style='margin:10px 0;border:none;border-top:1px dashed #e5e7eb'>
                      <div class='mtHdr'>True Ban Toggles</div>
                      <div class='mtRow' style='flex-direction:column;align-items:flex-start'>
                        <label id='lbl_SEC_STRICT' style='color:#b91c1c;font-weight:700'><input type='checkbox' id='SEC_STRICT_ASSOCIATED_BAN'> TRUE BAN PUBLIC IP</label>
                        <label><input type='checkbox' id='SEC_DEVICE_BAN_ON_LOGIN'> Device ban on login to banned account</label>
                        <label><input type='checkbox' id='SEC_REG_BAN_SIMILAR_CID'> Block registration if client-id is similar to banned device</label>
                        <button id='btnSaveTrueBanToggles' class='mtBtn' style='margin-top:6px;background:#2563eb;color:#fff;border-color:#2563eb'>Save True Ban Toggles</button>
                      </div>
                    </div>
                  </details>
                  <details id='admUserMgmt' style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px'>
                    <summary style='cursor:pointer;font-weight:700'>User Management</summary>
                    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px'>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Search</div>
                        <input id='umSearch' placeholder='type to search users' style='padding:6px;width:100%'>
                        <div id='umResults' style='margin-top:6px;max-height:160px;overflow:auto;border:1px solid #e5e7eb;border-radius:6px;padding:6px;font-size:13px'></div>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Actions</div>
                        <input id='umUser' placeholder='username' style='padding:6px;width:100%'>
                        <div style='display:flex;gap:8px;margin-top:6px;flex-wrap:wrap'>
                          <button id='btnUMBan' type='button' style='background:#b45309;color:#fff'>Ban</button>
                          <button id='btnUMUnban' type='button'>Unban</button>
                          <button id='btnUMShadow' type='button'>Shadow Ban</button>
                          <button id='btnUMUnshadow' type='button'>Unshadow</button>
                        </div>
                        <div style='display:flex;gap:8px;margin-top:8px;align-items:center;flex-wrap:wrap'>
                          <label>Minutes <input id='umMinutes' type='number' min='1' value='5' style='padding:6px;width:80px'></label>
                          <button id='btnUMTimeout' type='button'>Timeout</button>
                        </div>
                        <div style='margin-top:8px'>
                          <div style='font-weight:700;margin-bottom:4px'>Global Warning</div>
                          <textarea id='umWarnMsg' rows='3' placeholder='message to send as System DM' style='width:100%;padding:6px'></textarea>
                          <button id='btnUMWarn' type='button' style='margin-top:6px'>Send Warning</button>
                        </div>
                      </div>
                    </div>
                  </details>
                </div>
                <div style='grid-column: 1 / span 2;'>
                  <h4>Server Code (superadmin)</h4>
                  <div style='display:flex;flex-direction:column;gap:8px'>
                    <textarea id='admCode' rows='16' style='width:100%;font-family:monospace;tab-size:2;resize:vertical;white-space:pre;overflow:auto' spellcheck='false' autocapitalize='off' autocomplete='off' autocorrect='off' translate='no' readonly></textarea>
                    <div style='display:flex;gap:8px;flex-wrap:wrap;align-items:center'>
                      <button id='btnLoadCode' type='button'>Load</button>
                      <button id='btnToggleEdit' type='button'>Edit</button>
                      <button id='btnWrap' type='button'>Wrap: Off</button>
                      <button id='btnSaveCode' type='button' style='background:#2563eb;color:#fff'>Save</button>
                      <span id='codeDirty' style='color:#6b7280;font-size:12px'>Clean</span>
                    </div>
                  </div>
                  <div style='margin-top:14px'>
                    <h4>DB Editor (superadmin)</h4>
                    <textarea id='admSQL' rows='8' placeholder='SELECT * FROM users LIMIT 10' style='width:100%;font-family:monospace;resize:vertical'></textarea>
                    <div style='display:flex;gap:8px;align-items:center;margin-top:6px'>
                      <button id='btnRunSQL' type='button' style='background:#2563eb;color:#fff'>Run SQL</button>
                    </div>
                    <pre id='sqlOut' style='margin-top:6px;max-height:220px;overflow:auto;background:#0b1020;color:#d1d5db;padding:8px;border-radius:8px'></pre>
                  </div>
                </div>
                <div style='grid-column: 1 / span 2;'>
                  <h4>Platform Toggles (superadmin)</h4>
                  <details id='admAllToggles' style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px'>
                    <summary style='cursor:pointer;font-weight:700'>All Toggles</summary>
                    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px'>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Global Chat Controls</div>
                        <label><input type='checkbox' id='PUBLIC_ENABLED'> Enable Public Chat</label><br>
                        <label><input type='checkbox' id='DM_ENABLED'> Enable Direct Messages (DMs)</label><br>
                        <label><input type='checkbox' id='GDM_ENABLED'> Enable Group Chats</label><br>
                        <label><input type='checkbox' id='MAINTENANCE_MODE'> Maintenance Mode (read-only)</label><br>
                        <label><input type='checkbox' id='INVITE_ONLY_MODE'> Invite-Only Mode (registration)</label><br>
                        <label><input type='checkbox' id='ANNOUNCEMENTS_ONLY'> Announcements Only (public admins-only)</label>
                        <div style='margin-top:8px;padding-top:6px;border-top:1px dashed #e5e7eb'>
                          <label style='display:inline-flex;gap:6px;align-items:center'><input type='checkbox' id='DOWNTIME_ENABLED'> Chatter is Down (maintenance)</label>
                          <textarea id='DOWNTIME_REASON' placeholder='Optional downtime reason' rows='2' style='width:100%;margin-top:6px'></textarea>
                        </div>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>User Management</div>
                        <label><input type='checkbox' id='UM_BAN_USER'> Ban User</label><br>
                        <label><input type='checkbox' id='UM_TIMEOUT_USER'> Timeout User</label><br>
                        <label><input type='checkbox' id='UM_SEARCH_USER'> Search User</label><br>
                        <label><input type='checkbox' id='UM_TEMP_BAN'> Set Temporary Ban</label><br>
                        <label><input type='checkbox' id='UM_GLOBAL_WARNING'> Send Global Warning</label><br>
                        <label><input type='checkbox' id='UM_SHADOW_BAN'> Shadow Ban</label>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Message & Channel Controls</div>
                        <label><input type='checkbox' id='MC_DELETE_MESSAGES'> Delete Messages</label><br>
                        <label><input type='checkbox' id='MC_EDIT_MESSAGES'> Edit Messages</label><br>
                        <label><input type='checkbox' id='MC_SEARCH_MESSAGES'> Search Messages</label><br>
                        <label><input type='checkbox' id='MC_PURGE_CHANNEL'> Purge Channel</label><br>
                        <label><input type='checkbox' id='MC_PIN_MESSAGE'> Pin Message</label><br>
                        <label><input type='checkbox' id='MC_BROADCAST_MESSAGE'> Broadcast Message</label><br>
                        <label><input type='checkbox' id='MC_VIEW_HISTORY'> View Message History</label><br>
                        <label><input type='checkbox' id='MC_MESSAGE_LIFESPAN'> Set Message Lifespan</label>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Group & DM Controls</div>
                        <label><input type='checkbox' id='GD_LOCK_GROUP'> Lock Group Chat</label><br>
                        <label><input type='checkbox' id='GD_UNLOCK_GROUP'> Unlock Group Chat</label><br>
                        <label><input type='checkbox' id='GD_REMOVE_USER'> Remove User from Group</label><br>
                        <label><input type='checkbox' id='GD_TRANSFER_OWNERSHIP'> Transfer Group Ownership</label><br>
                        <label><input type='checkbox' id='GD_ARCHIVE_GROUP'> Archive Group Chat</label><br>
                        <label><input type='checkbox' id='GD_DELETE_GROUP'> Delete Group Chat</label><br>
                        <label><input type='checkbox' id='GD_CLOSE_ALL_DMS'> Close All DMs</label><br>
                        <label><input type='checkbox' id='GD_DM_AS_SYSTEM'> Send DM as System</label><br>
                        <label><input type='checkbox' id='GD_SAVE_DM_LOGS'> Save DM Logs</label><br>
                        <label><input type='checkbox' id='GD_FORCE_LEAVE_GROUP'> Force Leave Group</label>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Admin Tools</div>
                        <label><input type='checkbox' id='ADMIN_SYNC_PERMS'> Sync Permissions</label><br>
                        <label><input type='checkbox' id='ADMIN_VIEW_ACTIVE'> View Active Admins</label><br>
                        <label><input type='checkbox' id='ADMIN_STEALTH_MODE'> Stealth Mode</label><br>
                        <label><input type='checkbox' id='ADMIN_EMERGENCY_SHUTDOWN'> Emergency Shutdown</label><br>
                        <label><input type='checkbox' id='ADMIN_SHOW_EMERGENCY_BLOCK'> Show Emergency Status (when offline)</label>
                        <div style='margin-top:8px;padding-top:6px;border-top:1px dashed #e5e7eb'>
                          <label style='display:inline-flex;gap:6px;align-items:center'><input type='checkbox' id='ALERTS_ENABLED'> On-screen Alert (bottom-left)</label>
                          <textarea id='ALERTS_TEXT' placeholder='Alert text' rows='2' style='width:100%;margin-top:6px'></textarea>
                        </div>
                      </div>
                    </div>
                    <div style='margin-top:8px'>
                      <button id='btnSaveAllToggles' type='button'>Save All Toggles</button>
                    </div>
                  </details>
                </div>
              </div>`;
            pop.appendChild(box); document.body.appendChild(pop);
            try { Language.translateFragment(pop); } catch(_){}
            // Wire existing static Quick Create User & Password Reset cards (no dynamic duplicates)
            try {
              const qbtn = box.querySelector('#quickCreateUserBtn');
              if (qbtn) qbtn.onclick = async ()=>{
                const u = (box.querySelector('#quickCreateUserName')?.value||'').trim();
                const p = (box.querySelector('#quickCreateUserPass')?.value||'').trim();
                const isA = !!box.querySelector('#quickCreateUserIsAdmin')?.checked;
                if (!u || !p){ showToast('Enter username and password','warn'); return; }
                try{
                  const r = await fetch('/api/admin/create_user',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:u,password:p,is_admin:isA})});
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast(j.error||'Failed','error'); return; }
                  showToast('User created','ok');
                  try{ box.querySelector('#quickCreateUserName').value=''; box.querySelector('#quickCreateUserPass').value=''; box.querySelector('#quickCreateUserIsAdmin').checked=false; }catch(e){}
                }catch(e){ showToast('Failed','error'); }
              };
              const prbtn = box.querySelector('#pwResetBtn');
              if (prbtn) prbtn.onclick = async ()=>{
                const u = (box.querySelector('#pwResetUser')?.value||'').trim();
                const p = (box.querySelector('#pwResetPass')?.value||'').trim();
                if (!u || !p){ showToast('Enter username and new password','warn'); return; }
                try{
                  const r = await fetch('/api/admin/reset_password',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:u,password:p})});
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast(j.error||'Failed','error'); return; }
                  showToast('Password reset','ok');
                  try{ box.querySelector('#pwResetUser').value=''; box.querySelector('#pwResetPass').value=''; }catch(e){}
                }catch(e){ showToast('Failed','error'); }
              };
            } catch(e){}
            // Wire existing ID Reset Behavior toggles (no dynamic block)
            try{
              const pub = box.querySelector('#toggleResetPublic') || document.getElementById('toggleResetPublic');
              const dm  = box.querySelector('#toggleResetDM') || document.getElementById('toggleResetDM');
              const gdm = box.querySelector('#toggleResetGDM') || document.getElementById('toggleResetGDM');
              const thr = box.querySelector('#toggleResetGroupThreads') || document.getElementById('toggleResetGroupThreads');
              if (pub && dm && gdm && thr){
                const apply = (j)=>{ try{ pub.checked=!!(j.reset_public||j.public||j.pub);}catch(_){} try{ dm.checked=!!(j.reset_dm||j.dm);}catch(_){} try{ gdm.checked=!!(j.reset_gdm||j.gdm);}catch(_){} try{ thr.checked=!!(j.reset_group_threads||j.group_threads||j.threads);}catch(_){} };
                (async ()=>{
                  try{
                    const r = await fetch('/api/admins/resets', {credentials:'same-origin'});
                    const j = await r.json().catch(()=>({}));
                    const data = (j && j.settings) ? j.settings : j; apply(data||{});
                  }catch(_){ try{ const r2=await fetch('/api/admins/resets/get',{credentials:'same-origin'}); const j2=await r2.json().catch(()=>({})); const data=(j2&&j2.settings)?j2.settings:j2; apply(data||{});}catch(e){} }
                })();
                const save = async ()=>{
                  const body = { reset_public: !!pub.checked, reset_dm: !!dm.checked, reset_gdm: !!gdm.checked, reset_group_threads: !!thr.checked };
                  const r = await fetch('/api/admins/resets', {method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify(body)});
                  try{ await r.json(); }catch(_){ }
                };
                pub.onchange = save; dm.onchange = save; gdm.onchange = save; thr.onchange = save;
              }
            } catch(e){}
            // Toast container (once)
            try {
              if (!document.getElementById('admToastContainer')){
                const t = document.createElement('div');
                t.id = 'admToastContainer';
                t.style.position='fixed'; t.style.right='16px'; t.style.bottom='16px'; t.style.zIndex='20001'; t.style.display='flex'; t.style.flexDirection='column'; t.style.gap='8px';
                document.body.appendChild(t);
              }
            } catch(e){}
            function showToast(msg, kind){
              try{
                const cont = document.getElementById('admToastContainer');
                const el = document.createElement('div');
                el.style.padding='10px 12px'; el.style.borderRadius='8px'; el.style.boxShadow='0 8px 20px rgba(0,0,0,0.15)'; el.style.color='#fff'; el.style.maxWidth='360px'; el.style.fontSize='14px';
                el.style.background = kind==='error' ? '#b91c1c' : (kind==='warn' ? '#b45309' : '#059669');
                el.textContent = msg;
                cont.appendChild(el);
                try { Language.translateFragment(el); } catch(_){}
                setTimeout(()=>{ try{ cont.removeChild(el); }catch(e){} }, 2400);
              }catch(e){}
            }
            // Make native alert non-blocking via toast within Admin Dashboard lifecycle
            try { window.__oldAlert = window.alert; window.alert = (m)=>showToast(String(m||'Notice'), 'warn'); } catch(e){}
            const close = ()=>{ try{ document.body.removeChild(pop); }catch(e){} };
            box.querySelector('#admClose').onclick = close;
            const btnResetAllIds = box.querySelector('#admResetAllIds');
            if (btnResetAllIds) btnResetAllIds.onclick = async ()=>{
              if (!confirm('Reset all autoincrement IDs for public messages, DMs, group messages, and group threads? This does NOT delete data, but will reset next IDs. Proceed?')) return;
              try{
                const r = await fetch('/api/admins/reset_all_ids', { method:'POST', credentials:'same-origin' });
                const j = await r.json().catch(()=>({}));
                if (!r.ok || !j.ok){ showToast(j.error||'Failed to reset IDs','error'); return; }
                showToast('All IDs reset','ok');
              }catch(e){ showToast('Failed to reset IDs','error'); }
            };
            const render = ()=>{
              const pill = (t, color)=>`<span style='display:inline-block;padding:2px 8px;border-radius:999px;background:${color};color:#fff;margin:2px;font-size:12px'>${t}</span>`;
              const admins = (info.admins||[]).map(u=>pill(u,'#2563eb')).join('') || '<span style="color:#666">None</span>';
              const busers = (info.banned_users||[]).map(u=>pill(u,'#b91c1c')).join('') || '<span style="color:#666">None</span>';
              const bips = (info.banned_ips||[]).map(ip=>pill(ip,'#b45309')).join('') || '<span style="color:#666">None</span>';
              box.querySelector('#admAdmins').innerHTML = admins;
              box.querySelector('#admBUsers').innerHTML = busers;
              box.querySelector('#admBIPs').innerHTML = bips;
              // Initialize toggle states from settings if present
              try {
                const s = (info.settings||{});
                const get1 = (k)=> String(s[k]||'0')==='1';
                const el1 = box.querySelector('#SEC_STRICT_ASSOCIATED_BAN'); if (el1) el1.checked = get1('SEC_STRICT_ASSOCIATED_BAN');
                const el2 = box.querySelector('#SEC_DEVICE_BAN_ON_LOGIN'); if (el2) el2.checked = get1('SEC_DEVICE_BAN_ON_LOGIN');
                const el3 = box.querySelector('#SEC_REG_BAN_SIMILAR_CID'); if (el3) el3.checked = get1('SEC_REG_BAN_SIMILAR_CID');
                // Generic: for every known setting key, apply to any checkbox with matching id
                Object.keys(s).forEach(k=>{
                  const els = box.querySelectorAll('#'+k);
                  els.forEach(el=>{
                    if ('checked' in el) el.checked = get1(k);
                    if (k === 'MC_MESSAGE_LIFESPAN_DAYS' && 'value' in el) el.value = String(s[k]||'0');
                  });
                });
                // Ensure lifespan input has a value even if no matching key above
                const daysEl = box.querySelector('#MC_MESSAGE_LIFESPAN_DAYS');
                if (daysEl && !daysEl.value) daysEl.value = String(s.MC_MESSAGE_LIFESPAN_DAYS||'0');
              } catch(e){}
              // Emergency Status block: only show when emergency is on OR admin explicitly opted in
              try {
                const emOn = get1('ADMIN_EMERGENCY_SHUTDOWN');
                const showBlock = get1('ADMIN_SHOW_EMERGENCY_BLOCK');
                const cardEl = box.querySelector('#admEmergencyCard');
                const emStatusEl = box.querySelector('#admEmergencyStatus');
                const emSnapEl = box.querySelector('#admEmergencySnapshot');
                const stagesEl = box.querySelector('#admEmergencyStages');
                
                if (!cardEl) { /* nothing to do */ }
                else if (!(emOn || showBlock)) {
                  cardEl.style.display = 'none';
                } else {
                  cardEl.style.display = '';
                  if (emStatusEl) {
                    if (emOn) {
                      emStatusEl.innerHTML = '🚨 <span style="color:#dc2626;font-weight:bold">Emergency shutdown: ACTIVE</span>';
                      // Show recovery stage controls when emergency is active
                      if (stagesEl) stagesEl.style.display = '';
                    } else {
                      emStatusEl.innerHTML = '✅ <span style="color:#16a34a">Emergency shutdown: inactive</span>';
                      // Hide recovery stage controls when emergency is inactive
                      if (stagesEl) stagesEl.style.display = 'none';
                    }
                  }
                  if (emSnapEl) {
                    const snap = s.EMERGENCY_LAST_SNAPSHOT || '';
                    const when = s.EMERGENCY_LAST_TIME || '';
                    if (snap || when) {
                      const parts = [];
                      if (when) parts.push(`Last snapshot: ${when}`);
                      if (snap) parts.push(snap);
                      emSnapEl.textContent = parts.join('  ');
                    } else {
                      emSnapEl.textContent = 'No emergency snapshots recorded yet.';
                    }
                  }
                }
              } catch(_){ }
            };
            render();
            // Danger tooltip for TRUE BAN PUBLIC IP toggle (shows after 2s hover)
            try {
              const dangerLbl = box.querySelector('#lbl_SEC_STRICT');
              if (dangerLbl){
                let hoverTimer = null; let tip = null;
                const showTip = (e)=>{
                  if (tip) return;
                  tip = document.createElement('div');
                  tip.className = 'popover';
                  tip.textContent = 'DANGER — MAY HAVE UNEXPECTED CONSEQUENCES (bans entire public IP). Use only if necessary.';
                  tip.style.position = 'fixed';
                  tip.style.left = (e.clientX + 10) + 'px';
                  tip.style.top = (e.clientY + 10) + 'px';
                  document.body.appendChild(tip);
                };
                const hideTip = ()=>{ if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; } if (tip){ try { document.body.removeChild(tip); } catch(e){} tip = null; } };
                dangerLbl.addEventListener('mouseenter', (e)=>{ hideTip(); hoverTimer = setTimeout(()=>showTip(e), 2000); });
                dangerLbl.addEventListener('mousemove', (e)=>{ if (tip){ tip.style.left = (e.clientX + 10) + 'px'; tip.style.top = (e.clientY + 10) + 'px'; } });
                dangerLbl.addEventListener('mouseleave', hideTip);
              }
            } catch(e){}
            // Ensure adminOnline helper exists
            if (typeof adminOnline !== 'function') {
              window.adminOnline = async function(){ const r = await fetch('/api/admin/online'); return await r.json(); };
            }
            async function renderOnline(){
              try {
                const data = await adminOnline();
                const list = (data.online||[]).map(row => {
                  const u = row.username;
                  const priv = row.private||''; const pub = row.public||''; const immune = !!row.immune; const cid = row.client_id||'';
                  const privB = !!row.private_banned; const pubB = !!row.public_banned; const devB = !!row.device_banned;
                  const badgeColor = immune ? '#6b21a8' : '#111827';
                  const badge = `<span style='display:inline-block;padding:2px 8px;border-radius:8px;background:${badgeColor};color:#fff;font-size:12px'>${u}</span>`;
                  const cidTag = cid ? `<span title='client_id' style='display:inline-block;padding:2px 8px;border-radius:8px;background:#0ea5e9;color:#fff;font-size:12px'>${cid}</span>` : '';
                  const ipPrivTag = priv ? `<span title='private' style='display:inline-block;padding:2px 8px;border-radius:8px;background:#6b7280;color:#fff;font-size:12px'>${priv}</span>` : '';
                  const ipPubTag = pub ? `<span title='public' style='display:inline-block;padding:2px 8px;border-radius:8px;background:#374151;color:#fff;font-size:12px'>${pub}</span>` : '';
                  const btnPriv = priv && !privB ? `<button data-ip='${priv}' data-user='${u}' class='btnBanPriv' style='padding:4px 8px;font-size:12px;background:#b45309;color:#fff;border-radius:6px'>Ban Private</button>` : '';
                  const btnPrivUn = priv && privB ? `<button data-ip='${priv}' class='btnUnbanPriv' style='padding:4px 8px;font-size:12px'>Unban Private</button>` : '';
                  const btnPub = pub && !pubB ? `<button data-ip='${pub}' data-user='${u}' class='btnBanPub' style='padding:4px 8px;font-size:12px;background:#b45309;color:#fff;border-radius:6px'>Ban Public</button>` : '';
                  const btnPubUn = pub && pubB ? `<button data-ip='${pub}' class='btnUnbanPub' style='padding:4px 8px;font-size:12px'>Unban Public</button>` : '';
                  const btnDev = cid && !devB ? `<button data-cid='${cid}' data-user='${u}' class='btnBanDevice' style='padding:4px 8px;font-size:12px;background:#ef4444;color:#fff;border-radius:6px'>Ban Device</button>` : '';
                  const btnDevUn = cid && devB ? `<button data-cid='${cid}' class='btnUnbanDevice' style='padding:4px 8px;font-size:12px'>Unban Device</button>` : '';
                  return `<div style='display:flex;gap:8px;align-items:center;justify-content:space-between;border:1px solid #e5e7eb;border-radius:8px;padding:6px;background:#f9fafb'>
                            <div style='display:flex;gap:6px;align-items:center'>${badge}${cidTag}${ipPrivTag}${ipPubTag}</div>
                            <div style='display:flex;gap:6px'>${btnPriv}${btnPrivUn}${btnPub}${btnPubUn}${btnDev}${btnDevUn}</div>
                          </div>`;
                }).join('') || '<span style=\"color:#666\">None</span>';
                box.querySelector('#admOnline').innerHTML = list;
                function wireBan(cls){
                  box.querySelectorAll(cls).forEach(el => {
                    el.onclick = async ()=>{
                      const ip = el.getAttribute('data-ip');
                      const user = el.getAttribute('data-user');
                      if (!ip) return;
                      const r2 = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'ip', action:'ban', value: ip, username: user })});
                      const d2 = await r2.json(); if (!r2.ok){ alert(d2.error||'Failed'); return; } alert('IP banned');
                      await refreshAll();
                    };
                  });
                }
                wireBan('.btnBanPriv'); wireBan('.btnBanPub');
                // Ban device by client_id
                box.querySelectorAll('.btnBanDevice').forEach(el => {
                  el.onclick = async ()=>{
                    const cid = el.getAttribute('data-cid'); const user = el.getAttribute('data-user');
                    if (!cid) return;
                    const r2 = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'ban', client_id: cid, username: user })});
                    const d2 = await r2.json(); if (!r2.ok){ alert(d2.error||'Failed'); return; } alert('Device banned');
                    await refreshAll();
                  };
                });
                // Unban IP/device buttons
                function wireUnban(cls, kind){
                  box.querySelectorAll(cls).forEach(el => {
                    el.onclick = async ()=>{
                      const ip = el.getAttribute('data-ip'); const cid = el.getAttribute('data-cid');
                      if (kind==='priv' || kind==='pub'){
                        if (!ip) return;
                        const r2 = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'ip', action:'unban', value: ip })});
                        const d2 = await r2.json(); if (!r2.ok){ alert(d2.error||'Failed'); return; } alert('IP unbanned');
                      } else if (kind==='dev'){
                        if (!cid) return;
                        const r2 = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'unban', client_id: cid })});
                        const d2 = await r2.json(); if (!r2.ok){ alert(d2.error||'Failed'); return; } alert('Device unbanned');
                      }
                      await refreshAll();
                    };
                  });
                }
                wireUnban('.btnUnbanPriv','priv'); wireUnban('.btnUnbanPub','pub'); wireUnban('.btnUnbanDevice','dev');
              } catch(e){ box.querySelector('#admOnline').textContent = 'Failed to load'; }
            }
            function wireTrueBan(){
              try {
                const btnTrueBan2 = box.querySelector('#btnTrueBan2');
                const btnTrueUnban2 = box.querySelector('#btnTrueUnban2');
                const tb2User = box.querySelector('#tb2User');
                const tb2CID = box.querySelector('#tb2CID');
                const btnSaveTrueBanToggles = box.querySelector('#btnSaveTrueBanToggles');
                if (btnTrueBan2) btnTrueBan2.onclick = async () => {
                  const user = (tb2User?.value||'').trim(); const client_id = (tb2CID?.value||'').trim();
                  if (!user) { showToast('Enter username', 'warn'); return; }
                  try {
                    const res = await fetch('/api/admin/true_ban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                    const j = await res.json().catch(()=>({}));
                    if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                    showToast('True Ban applied', 'ok');
                    await refreshAll();
                  } catch(e) { showToast('Failed', 'error'); }
                };
                if (btnTrueUnban2) btnTrueUnban2.onclick = async () => {
                  const user = (tb2User?.value||'').trim(); const client_id = (tb2CID?.value||'').trim();
                  if (!user) { showToast('Enter username', 'warn'); return; }
                  try {
                    const res = await fetch('/api/admin/true_unban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                    const j = await res.json().catch(()=>({}));
                    if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                    showToast('True Unban completed', 'ok');
                    await refreshAll();
                  } catch(e) { showToast('Failed', 'error'); }
                };
                if (btnSaveTrueBanToggles) btnSaveTrueBanToggles.onclick = async () => {
                  try {
                    const payload = {
                      SEC_STRICT_ASSOCIATED_BAN: box.querySelector('#SEC_STRICT_ASSOCIATED_BAN')?.checked ? '1' : '0',
                      SEC_DEVICE_BAN_ON_LOGIN: box.querySelector('#SEC_DEVICE_BAN_ON_LOGIN')?.checked ? '1' : '0',
                      SEC_REG_BAN_SIMILAR_CID: box.querySelector('#SEC_REG_BAN_SIMILAR_CID')?.checked ? '1' : '0',
                    };
                    const res = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                    const j = await res.json().catch(()=>({}));
                    if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed to save toggles', 'error'); return; }
                    showToast('True Ban toggles saved', 'ok');
                  } catch(e) { showToast('Failed to save toggles', 'error'); }
                };
              } catch(e){}
            }
            wireTrueBan();

            // Ensure settings present; fetch persisted app settings for toggle states
            (async ()=>{
              try {
                const r = await fetch('/api/admin/app_settings');
                const j = await r.json().catch(()=>({}));
                if (r.ok && j && j.ok && j.settings){
                  info.settings = j.settings;
                  try {
                    const s = j.settings || {};
                    const ids = [
                      'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED','MAINTENANCE_MODE','INVITE_ONLY_MODE','ANNOUNCEMENTS_ONLY',
                      'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
                      'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_SEARCH_MESSAGES','MC_PURGE_CHANNEL','MC_PIN_MESSAGE','MC_BROADCAST_MESSAGE','MC_VIEW_HISTORY','MC_MESSAGE_LIFESPAN',
                      'GD_LOCK_GROUP','GD_UNLOCK_GROUP','GD_REMOVE_USER','GD_TRANSFER_OWNERSHIP','GD_ARCHIVE_GROUP','GD_DELETE_GROUP','GD_CLOSE_ALL_DMS','GD_DM_AS_SYSTEM','GD_SAVE_DM_LOGS','GD_FORCE_LEAVE_GROUP',
                      'ADMIN_SYNC_PERMS','ADMIN_VIEW_ACTIVE','ADMIN_STEALTH_MODE','ADMIN_EMERGENCY_SHUTDOWN'
                    ];
                    ids.forEach(id=>{ const el = box.querySelector('#'+id); if (el && 'checked' in el) el.checked = String(s[id]||'0')==='1'; });
                    const dr = box.querySelector('#DOWNTIME_REASON'); if (dr) dr.value = s.DOWNTIME_REASON || '';
                    const at = box.querySelector('#ALERTS_TEXT'); if (at) at.value = s.ALERTS_TEXT || '';
                  } catch(e){}
                  render();
                }
              } catch(e){}
            })();

            async function refreshAll(){
              try { const data = await adminOverview(); info = data; render(); } catch(e){}
              await renderOnline();
              // Banned devices list render
              const bd = (info.banned_devices||[]);
              const wrap = box.querySelector('#dtBannedList');
              if (wrap) {
                wrap.innerHTML = bd.map(x=>`<div style='display:flex;gap:6px;align-items:center;justify-content:space-between;border-bottom:1px dashed #e5e7eb;padding:4px 0'>
                  <span title='client_id'>${(x.client_id||'').slice(0,36)}</span>
                  <span title='username' style='color:#6b7280'>${x.username||''}</span>
                  <button class='btnUnbanDeviceRow' data-cid='${x.client_id||''}' style='padding:2px 6px'>Unban</button>
                </div>`).join('') || '<span style="color:#666">None</span>';
                wrap.querySelectorAll('.btnUnbanDeviceRow').forEach(el=>{
                  el.onclick = async ()=>{
                    const cid = el.getAttribute('data-cid'); if (!cid) return;
                    const r = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'unban', client_id: cid })});
                    const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Device unbanned'); await refreshAll();
                  };
                });
              }
            }
            box.querySelector('#admRefresh').onclick = refreshAll;
            // Save Message Lifespan
            try {
              const btnSaveLife = box.querySelector('#btnSaveLifespan');
              if (btnSaveLife) btnSaveLife.onclick = async ()=>{
                try{
                  const payload = {
                    MC_MESSAGE_LIFESPAN: box.querySelector('#MC_MESSAGE_LIFESPAN')?.checked ? '1' : '0',
                    MC_MESSAGE_LIFESPAN_DAYS: String(box.querySelector('#MC_MESSAGE_LIFESPAN_DAYS')?.value||'0'),
                  };
                  const r = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok) { showToast((j&&j.error)||'Failed to save lifespan', 'error'); return; }
                  showToast('Message lifespan saved', 'ok');
                  await refreshAll();
                } catch(e) { showToast('Failed to save lifespan', 'error'); }
              };
            } catch(e){}
            const btnCleanup = box.querySelector('#admCleanup'); if (btnCleanup) btnCleanup.onclick = async ()=>{
              try {
                const r = await fetch('/api/admin/cleanup_sockets', { method:'POST' });
                const d = await r.json().catch(()=>({}));
                if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
                alert(`Disconnected: ${d.disconnected||0}, Pruned: ${d.pruned||0}`);
              } catch(e) { alert('Failed'); }
              await refreshAll();
            };
            // Group Tools wiring
            try {
              const q = (sel)=> box.querySelector(sel);
              const getTid = ()=> parseInt((q('#gtTid')?.value||'0'),10)||0;
              const getUser = ()=> (q('#gtUser')?.value||'').trim();
              const getNewOwner = ()=> (q('#gtNewOwner')?.value||'').trim();
              const call = async (url, payload)=>{
                try{
                  const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload||{}) });
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast((j&&j.error)||'Failed', 'error'); return false; }
                  showToast('Done', 'ok');
                  try { await loadGDMs(); } catch(e){}
                  return true;
                }catch(e){ showToast('Failed', 'error'); return false; }
              };
              const btnGtLock = q('#btnGtLock'); if (btnGtLock) btnGtLock.onclick = ()=>{ const tid=getTid(); if(!tid){showToast('Enter thread_id','warn');return;} call('/api/gdm/lock',{tid}); };
              const btnGtUnlock = q('#btnGtUnlock'); if (btnGtUnlock) btnGtUnlock.onclick = ()=>{ const tid=getTid(); if(!tid){showToast('Enter thread_id','warn');return;} call('/api/gdm/unlock',{tid}); };
              const btnGtRemove = q('#btnGtRemove'); if (btnGtRemove) btnGtRemove.onclick = ()=>{ const tid=getTid(); const u=getUser(); if(!tid||!u){showToast('Enter thread_id and username','warn');return;} call('/api/gdm/remove_member',{tid, username:u}); };
              const btnGtTransfer = q('#btnGtTransfer'); if (btnGtTransfer) btnGtTransfer.onclick = ()=>{ const tid=getTid(); const no=getNewOwner(); if(!tid||!no){showToast('Enter thread_id and new owner','warn');return;} call('/api/gdm/transfer',{tid, new_owner:no}); };
              const btnGtArchive = q('#btnGtArchive'); if (btnGtArchive) btnGtArchive.onclick = ()=>{ const tid=getTid(); if(!tid){showToast('Enter thread_id','warn');return;} call('/api/gdm/archive',{tid}); };
              const btnGtDelete = q('#btnGtDelete'); if (btnGtDelete) btnGtDelete.onclick = ()=>{ const tid=getTid(); if(!tid){showToast('Enter thread_id','warn');return;} if(!confirm('Delete this group?')) return; call('/api/gdm/delete',{tid}); };
              const btnGtForceLeave = q('#btnGtForceLeave'); if (btnGtForceLeave) btnGtForceLeave.onclick = ()=>{ const tid=getTid(); const u=getUser(); if(!tid||!u){showToast('Enter thread_id and username','warn');return;} call('/api/gdm/force_leave',{tid, username:u}); };
            } catch(e){}
            // actions
            // DB Editor
            try {
              const btnRunSQL = box.querySelector('#btnRunSQL');
              if (btnRunSQL) btnRunSQL.onclick = async ()=>{
                try{
                  const sql = (box.querySelector('#admSQL')?.value||'').trim();
                  if (!sql){ showToast('Enter SQL', 'warn'); return; }
                  const r = await fetch('/api/admin/sql_run', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ sql }) });
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast((j&&j.error)||'Failed', 'error'); return; }
                  box.querySelector('#sqlOut').textContent = JSON.stringify(j.rows||[], null, 2);
                }catch(e){ showToast('Failed', 'error'); }
              };
            } catch(e){}
            // Save All Toggles (including text settings)
            try {
              const btnSaveAll = box.querySelector('#btnSaveAllToggles');
              if (btnSaveAll) btnSaveAll.onclick = async ()=>{
                try{
                  const payload = {};
                  const ids = [
                    'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED','MAINTENANCE_MODE','INVITE_ONLY_MODE','ANNOUNCEMENTS_ONLY',
                    'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
                    'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_SEARCH_MESSAGES','MC_PURGE_CHANNEL','MC_PIN_MESSAGE','MC_BROADCAST_MESSAGE','MC_VIEW_HISTORY','MC_MESSAGE_LIFESPAN',
                    'GD_LOCK_GROUP','GD_UNLOCK_GROUP','GD_REMOVE_USER','GD_TRANSFER_OWNERSHIP','GD_ARCHIVE_GROUP','GD_DELETE_GROUP','GD_CLOSE_ALL_DMS','GD_DM_AS_SYSTEM','GD_SAVE_DM_LOGS','GD_FORCE_LEAVE_GROUP',
                    'ADMIN_SYNC_PERMS','ADMIN_VIEW_ACTIVE','ADMIN_STEALTH_MODE','ADMIN_EMERGENCY_SHUTDOWN',
                    'DOWNTIME_ENABLED','ALERTS_ENABLED'
                  ];
                  ids.forEach(id=>{ const el = box.querySelector('#'+id); if (el && 'checked' in el) payload[id] = el.checked? '1':'0'; });
                  payload['DOWNTIME_REASON'] = (box.querySelector('#DOWNTIME_REASON')?.value||'');
                  payload['ALERTS_TEXT'] = (box.querySelector('#ALERTS_TEXT')?.value||'');
                  let r = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                  let j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){
                    // Retry legacy shape {settings: payload}
                    r = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ settings: payload }) });
                    j = await r.json().catch(()=>({}));
                  }
                  if (!r.ok || !j.ok){
                    // Final fallback: persist critical settings via /api/admin/settings
                    const subset = {
                      DOWNTIME_ENABLED: payload.DOWNTIME_ENABLED,
                      DOWNTIME_REASON: payload.DOWNTIME_REASON,
                      ALERTS_ENABLED: payload.ALERTS_ENABLED,
                      ALERTS_TEXT: payload.ALERTS_TEXT,
                    };
                    const r2 = await fetch('/api/admin/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(subset) });
                    const j2 = await r2.json().catch(()=>({}));
                    if (!r2.ok || !j2.ok){ showToast((j&&j.error)||'Failed', 'error'); return; }
                    showToast('Settings saved', 'ok');
                    // Immediately refresh on-screen alert if present
                    try { window.__refreshAlert && window.__refreshAlert(); } catch(e){}
                    return;
                  }
                  showToast('Toggles saved', 'ok');
                  // Immediately refresh on-screen alert if present
                  try { window.__refreshAlert && window.__refreshAlert(); } catch(e){}
                }catch(e){ showToast('Failed', 'error'); }
              };
            } catch(e){}
            // Broadcast
            try {
              const btnBroadcast = box.querySelector('#btnBroadcast');
              if (btnBroadcast) btnBroadcast.onclick = async ()=>{
                const scope = (box.querySelector('#mtBroadcastScope')?.value||'public');
                const text = (box.querySelector('#mtBroadcastText')?.value||'').trim();
                const thread_id = parseInt((box.querySelector('#mtBroadcastThreadId')?.value||'0'),10)||0;
                const to_user = (box.querySelector('#mtBroadcastToUser')?.value||'').trim();
                if (!text){ showToast('Enter message', 'warn'); return; }
                const payload = { scope, text };
                if (scope==='gdm') payload.thread_id = thread_id;
                if (scope==='dm') payload.to_user = to_user;
                try{
                  const r = await fetch('/api/admin/broadcast', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast((j&&j.error)||'Failed', 'error'); return; }
                  showToast('Broadcast sent', 'ok');
                  box.querySelector('#mtBroadcastText').value = '';
                }catch(e){ showToast('Failed', 'error'); }
              };
            } catch(e){}
            // History load
            try {
              const btnLoadHist = box.querySelector('#btnLoadHist');
              if (btnLoadHist) btnLoadHist.onclick = async ()=>{
                const kind = (box.querySelector('#mtHistType')?.value||'public');
                const thread_id = parseInt((box.querySelector('#mtHistThreadId')?.value||'0'),10)||0;
                const lim = parseInt((box.querySelector('#mtHistLimit')?.value||'50'),10)||50;
                const p = new URLSearchParams(); p.set('type', kind); p.set('limit', String(lim)); if (kind==='gdm' && thread_id) p.set('thread_id', String(thread_id));
                try{
                  const r = await fetch('/api/admin/history?'+p.toString()); const j = await r.json();
                  const out = box.querySelector('#mtHistOut'); if (!out){ return; }
                  if (!r.ok){ out.textContent = j.error||'Failed'; return; }
                  const items = j.items||[];
                  out.innerHTML = items.map(m=>`<div style='border-bottom:1px dashed #e5e7eb;padding:4px 0'>
                    <div style='font-size:12px;color:#6b7280'>#${m.id} — ${m.username} — ${m.created_at}</div>
                    <div>${m.text}</div>
                  </div>`).join('') || '<span style="color:#666">None</span>';
                }catch(e){ const out = box.querySelector('#mtHistOut'); if (out) out.textContent = 'Failed'; }
              };
            } catch(e){}
            box.querySelector('#btnAddAdmin').onclick = async ()=>{
              const u = box.querySelector('#admUser').value.trim(); if (!u) return;
              const r = await fetch('/api/admin/role', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'add', role:'admin', username:u })});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} info.admins = data.admins; render();
            };
            box.querySelector('#btnRmAdmin').onclick = async ()=>{
              const u = box.querySelector('#admUser').value.trim(); if (!u) return;
              const r = await fetch('/api/admin/role', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'remove', role:'admin', username:u })});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} info.admins = data.admins; render();
            };
            box.querySelector('#btnBanUser').onclick = async ()=>{
              const u = box.querySelector('#admBanUser').value.trim(); if (!u) return;
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'user', action:'ban', value:u })});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} await refreshAll();
            };
            box.querySelector('#btnUnbanUser').onclick = async ()=>{
              const u = box.querySelector('#admBanUser').value.trim(); if (!u) return;
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'user', action:'unban', value:u })});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} await refreshAll();
            };
            box.querySelector('#btnBanIP').onclick = async ()=>{
              const ip = (box.querySelector('#admBanIP').value||'').trim();
              const user = (box.querySelector('#admBanIPUser').value||'').trim();
              if (!ip && !user) { alert('Enter an IP or a username'); return; }
              const payload = { type:'ip', action:'ban', value: ip, username: user };
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} await refreshAll();
            };
            box.querySelector('#btnUnbanIP').onclick = async ()=>{
              const ip = (box.querySelector('#admBanIP').value||'').trim();
              const user = (box.querySelector('#admBanIPUser').value||'').trim();
              if (!ip && !user) { alert('Enter an IP or a username'); return; }
              const payload = { type:'ip', action:'unban', value: ip, username: user };
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;}
              await refreshAll();
            };
            };
            // User Management wiring
            
            // Emergency Control Handlers
            try {
              const btnEmergencyActivate = box.querySelector('#btnEmergencyActivate');
              const btnEmergencyDeactivate = box.querySelector('#btnEmergencyDeactivate');
              const btnRefreshEmergencyLogs = box.querySelector('#btnRefreshEmergencyLogs');
              const admEmergencyLogs = box.querySelector('#admEmergencyLogs');
              const admEmergencyStages = box.querySelector('#admEmergencyStages');
              
              if (btnEmergencyActivate) {
                btnEmergencyActivate.onclick = async () => {
                  if (!confirm('⚠️ CRITICAL: This will activate emergency shutdown mode and block all user operations. Continue?')) return;
                  const trigger = prompt('Enter trigger reason (optional):') || 'Manual activation';
                  try {
                    const r = await fetch('/api/emergency/activate', {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      body: JSON.stringify({ trigger })
                    });
                    const data = await r.json();
                    if (!r.ok) { alert(data.error || 'Failed to activate emergency shutdown'); return; }
                    alert('✅ Emergency shutdown activated successfully');
                    await refreshAll();
                  } catch (e) {
                    alert('❌ Failed to activate emergency shutdown: ' + e.message);
                  }
                };
              }
              
              if (btnEmergencyDeactivate) {
                btnEmergencyDeactivate.onclick = async () => {
                  if (!confirm('Deactivate emergency shutdown and return to normal operation?')) return;
                  try {
                    const r = await fetch('/api/emergency/deactivate', {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      body: JSON.stringify({})
                    });
                    const data = await r.json();
                    if (!r.ok) { alert(data.error || 'Failed to deactivate emergency shutdown'); return; }
                    alert('✅ Emergency shutdown deactivated successfully');
                    await refreshAll();
                  } catch (e) {
                    alert('❌ Failed to deactivate emergency shutdown: ' + e.message);
                  }
                };
              }
              
              // Recovery stage buttons
              const stageButtons = box.querySelectorAll('[data-stage]');
              stageButtons.forEach(btn => {
                btn.onclick = async () => {
                  const stage = parseInt(btn.dataset.stage);
                  const stageNames = ['Full Shutdown', 'Read-Only', 'Chat-Only', 'Full Recovery'];
                  if (!confirm(`Set recovery stage to ${stage}: ${stageNames[stage]}?`)) return;
                  try {
                    const r = await fetch('/api/emergency/stage', {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      body: JSON.stringify({ stage })
                    });
                    const data = await r.json();
                    if (!r.ok) { alert(data.error || 'Failed to set recovery stage'); return; }
                    alert(`✅ Recovery stage set to ${stage}: ${stageNames[stage]}`);
                    await refreshAll();
                  } catch (e) {
                    alert('❌ Failed to set recovery stage: ' + e.message);
                  }
                };
              });
              
              // Emergency logs refresh
              if (btnRefreshEmergencyLogs && admEmergencyLogs) {
                btnRefreshEmergencyLogs.onclick = async () => {
                  try {
                    const r = await fetch('/api/emergency/logs');
                    const data = await r.json();
                    if (!r.ok) { 
                      admEmergencyLogs.innerHTML = '<div style="color:#dc2626">Failed to load logs: ' + (data.error || 'Unknown error') + '</div>';
                      return; 
                    }
                    
                    if (!data.logs || data.logs.length === 0) {
                      admEmergencyLogs.innerHTML = '<div style="color:#6b7280">No emergency logs found.</div>';
                      return;
                    }
                    
                    const logsHtml = data.logs.map(log => {
                      const levelColor = {
                        'CRITICAL': '#dc2626',
                        'ERROR': '#ea580c', 
                        'WARNING': '#d97706',
                        'INFO': '#059669'
                      }[log.level] || '#6b7280';
                      
                      return `<div style="margin-bottom:4px;padding:4px;border-left:3px solid ${levelColor};background:#f9fafb">
                        <div style="font-weight:600;color:${levelColor}">[${log.level}] ${log.timestamp}</div>
                        <div style="margin-top:2px">${log.message}</div>
                        ${log.admin ? `<div style="font-size:11px;color:#6b7280;margin-top:2px">Admin: ${log.admin}</div>` : ''}
                      </div>`;
                    }).join('');
                    
                    admEmergencyLogs.innerHTML = logsHtml;
                  } catch (e) {
                    admEmergencyLogs.innerHTML = '<div style="color:#dc2626">Failed to load logs: ' + e.message + '</div>';
                  }
                };
              }
            } catch (e) {
              console.error('Failed to setup emergency controls:', e);
            }

            const umSearch = box.querySelector('#umSearch');
            const umResults = box.querySelector('#umResults');
            const umUser = box.querySelector('#umUser');
            async function doSearch(){
              const q = (umSearch.value||'').trim();
              try{
                const r = await fetch('/api/admin/user_search?q='+encodeURIComponent(q));
                const d = await r.json();
                if (!r.ok) { umResults.textContent = d.error||'Failed'; return; }
                umResults.innerHTML = (d.users||[]).map(u=>`<button class='selUser' data-u='${u}' style='margin:2px;padding:4px 6px'>${u}</button>`).join('') || '<span style="color:#666">No results</span>';
                umResults.querySelectorAll('.selUser').forEach(el=>{ el.onclick = ()=>{ umUser.value = el.getAttribute('data-u')||''; } });
              }catch(e){ umResults.textContent = 'Failed'; }
            }
            if (umSearch) umSearch.oninput = ()=>{ window.clearTimeout(umSearch._t); umSearch._t = setTimeout(doSearch, 250); };
            function applyUMToggles(map){
              const setDis = (id, on)=>{ const el = box.querySelector(id); if (el) el.disabled = !on; };
              setDis('#btnUMBan', String(map.UM_BAN_USER||'1')==='1');
              setDis('#btnUMUnban', String(map.UM_BAN_USER||'1')==='1');
              setDis('#btnUMTimeout', String(map.UM_TIMEOUT_USER||'1')==='1');
              setDis('#btnUMWarn', String(map.UM_GLOBAL_WARNING||'1')==='1');
              setDis('#btnUMShadow', String(map.UM_SHADOW_BAN||'1')==='1');
              setDis('#btnUMUnshadow', String(map.UM_SHADOW_BAN||'1')==='1');
              setDis('#btnShadowTop', String(map.UM_SHADOW_BAN||'1')==='1');
              setDis('#btnUnshadowTop', String(map.UM_SHADOW_BAN||'1')==='1');
            }
            // Use toggles map when loaded
            let lastToggles = null;
            // Code editor actions (superadmin-only endpoint)
            const codeEl = ()=> box.querySelector('#admCode');
            const setDirty = (v)=>{ const el=box.querySelector('#codeDirty'); if(el) el.textContent = v? 'Unsaved changes' : 'Clean'; };
            const loadCode = async ()=>{
              try {
                const r = await fetch('/api/admin/code');
                const d = await r.json();
                if (!r.ok) { alert(d && d.error ? d.error : 'Failed to load code'); return; }
                codeEl().value = d.content || '';
                setDirty(false);
              } catch(e){ alert('Failed to load code'); }
            };
            // simple debounce to avoid rapid heavy saves
            let saving = false; let wrapOn=false; let editOn=false;
            const saveCode = async ()=>{
              if (saving) return; saving = true;
              try {
                const content = codeEl().value;
                const r = await fetch('/api/admin/code', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ content, restart: true }) });
                const d = await r.json();
                if (!r.ok || !d.ok) { alert(d && d.error ? d.error : 'Failed to save'); return; }
                alert('Saved. The server may need a manual restart to apply changes.');
                setDirty(false);
              } catch(e){ alert('Failed to save'); }
              finally { saving = false; }
            };
            const lc = box.querySelector('#btnLoadCode'); if (lc) lc.onclick = loadCode;
            const sc = box.querySelector('#btnSaveCode'); if (sc) sc.onclick = saveCode;
            const te = box.querySelector('#btnToggleEdit'); if (te) te.onclick = ()=>{ editOn=!editOn; codeEl().readOnly = !editOn; te.textContent = editOn? 'Readonly' : 'Edit'; if (editOn) codeEl().focus(); };
            const bw = box.querySelector('#btnWrap'); if (bw) bw.onclick = ()=>{ wrapOn=!wrapOn; codeEl().style.whiteSpace = wrapOn? 'pre-wrap':'pre'; bw.textContent = `Wrap: ${wrapOn?'On':'Off'}`; };
            // Mark dirty on edit, throttled with rAF
            let rafId = null;
            codeEl().addEventListener('input', ()=>{
              if (rafId) return; rafId = requestAnimationFrame(()=>{ setDirty(true); rafId=null; });
            });
            // Auto-load on open
            try { await loadCode(); } catch(e){}
            // Load all toggles generically
            async function loadAllToggles(){
              try {
                const r = await fetch('/api/admin/app_settings');
                const d = await r.json();
                if (!r.ok) return;
                Object.keys(d||{}).forEach(k=>{
                  const el = box.querySelector(`#${k}`);
                  if (el && el.type === 'checkbox') el.checked = String(d[k])==='1';
                });
                lastToggles = d;
                applyUMToggles(d||{});
              } catch(e){}
            }
            await loadAllToggles();
            // Device Tools wiring
            const btnBanDevOff = box.querySelector('#btnBanDeviceOffline'); if (btnBanDevOff) btnBanDevOff.onclick = async ()=>{
              const u = (box.querySelector('#dtUser').value||'').trim(); const cid = (box.querySelector('#dtClientId').value||'').trim();
              if (!u && !cid) { alert('Enter username or client_id'); return; }
              const payload = { action:'ban' }; if (cid) payload.client_id = cid; if (u) payload.username = u;
              const r = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Device banned'); await refreshAll();
            };
            const btnUnbanDevOff = box.querySelector('#btnUnbanDeviceOffline'); if (btnUnbanDevOff) btnUnbanDevOff.onclick = async ()=>{
              const u = (box.querySelector('#dtUser').value||'').trim(); const cid = (box.querySelector('#dtClientId').value||'').trim();
              if (!u && !cid) { alert('Enter username or client_id'); return; }
              if (cid){
                const r = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'unban', client_id: cid })});
                const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Device unbanned'); await refreshAll();
              } else if (u){
                const r = await fetch('/api/admin/unban_devices_for_user', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username: u })});
                const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('All devices unbanned for user'); await refreshAll();
              }
            };
            const btnUnbanAllUser = box.querySelector('#btnUnbanAllDevicesUser'); if (btnUnbanAllUser) btnUnbanAllUser.onclick = async ()=>{
              const u = (box.querySelector('#dtUser').value||'').trim(); if (!u){ alert('Enter username'); return; }
              const r = await fetch('/api/admin/unban_devices_for_user', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username: u })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('All devices unbanned for user'); await refreshAll();
            };
            // UM buttons
            const btnUMBan = box.querySelector('#btnUMBan'); if (btnUMBan) btnUMBan.onclick = async ()=>{
              const u = (umUser.value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'user', action:'ban', value: u })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Banned'); await refreshAll();
            };
            const btnUMUnban = box.querySelector('#btnUMUnban'); if (btnUMUnban) btnUMUnban.onclick = async ()=>{
              const u = (umUser.value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'user', action:'unban', value: u })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Unbanned'); await refreshAll();
            };
            const btnUMShadow = box.querySelector('#btnUMShadow'); if (btnUMShadow) btnUMShadow.onclick = async ()=>{
              const u = (umUser.value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/shadow', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, action: 'add' })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Shadow banned');
            };
            const btnUMUnshadow = box.querySelector('#btnUMUnshadow'); if (btnUMUnshadow) btnUMUnshadow.onclick = async ()=>{
              const u = (umUser.value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/shadow', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, action: 'remove' })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Unshadowed');
            };
            const btnUMTimeout = box.querySelector('#btnUMTimeout'); if (btnUMTimeout) btnUMTimeout.onclick = async ()=>{
              const u = (umUser.value||'').trim(); if (!u) return; const m = parseInt((box.querySelector('#umMinutes').value||'5'),10)||5;
              const r = await fetch('/api/admin/timeout', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, minutes: m })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Timed out');
            };
            const btnUMWarn = box.querySelector('#btnUMWarn'); if (btnUMWarn) btnUMWarn.onclick = async ()=>{
              const u = (umUser.value||'').trim(); const msg = (box.querySelector('#umWarnMsg').value||'').trim(); if (!u || !msg) return;
              const r = await fetch('/api/admin/warn', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, message: msg })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Warning sent');
            };
            // Top-level Shadow buttons (Banned Users card)
            const btnShadowTop = box.querySelector('#btnShadowTop'); if (btnShadowTop) btnShadowTop.onclick = async ()=>{
              const u = (box.querySelector('#admBanUser').value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/shadow', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, action: 'add' })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Shadow banned');
            };
            const btnUnshadowTop = box.querySelector('#btnUnshadowTop'); if (btnUnshadowTop) btnUnshadowTop.onclick = async ()=>{
              const u = (box.querySelector('#admBanUser').value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/shadow', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, action: 'remove' })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Unshadowed');
            };
            // (Save All Toggles handler is wired earlier; no generic override here)
            // Messaging Tools wiring
            const btnBroadcast = box.querySelector('#btnBroadcast'); if (btnBroadcast) btnBroadcast.onclick = async ()=>{
              const scope = (box.querySelector('#mtScope').value||'public');
              const text = (box.querySelector('#mtBroadcastText').value||'').trim();
              const thread_id = parseInt((box.querySelector('#mtBroadcastThreadId').value||'0'),10)||0;
              const to_user = (box.querySelector('#mtBroadcastToUser').value||'').trim();
              if (!text) { alert('Enter message'); return; }
              const payload = { scope, text };
              if (scope==='gdm') payload.thread_id = thread_id;
              if (scope==='dm') payload.to_user = to_user;
              const r = await fetch('/api/admin/broadcast', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              const d = await r.json().catch(()=>({}));
              if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
              alert('Broadcast sent');
            };
            const btnPin = box.querySelector('#btnPin'); if (btnPin) btnPin.onclick = async ()=>{
              const type = (box.querySelector('#mtPinType').value||'public');
              const id = parseInt((box.querySelector('#mtPinMsgId').value||'0'),10)||0;
              const thread_id = parseInt((box.querySelector('#mtPinThreadId').value||'0'),10)||0;
              if (!id) { alert('Enter message id'); return; }
              const payload = { type, id, action:'pin' };
              if (type==='gdm') payload.thread_id = thread_id;
              const r = await fetch('/api/admin/pin', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              const d = await r.json().catch(()=>({}));
              if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
              alert('Pinned');
            };
            const btnUnpin = box.querySelector('#btnUnpin'); if (btnUnpin) btnUnpin.onclick = async ()=>{
              const type = (box.querySelector('#mtPinType').value||'public');
              const id = parseInt((box.querySelector('#mtPinMsgId').value||'0'),10)||0;
              const thread_id = parseInt((box.querySelector('#mtPinThreadId').value||'0'),10)||0;
              if (!id) { alert('Enter message id'); return; }
              const payload = { type, id, action:'unpin' };
              if (type==='gdm') payload.thread_id = thread_id;
              const r = await fetch('/api/admin/pin', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              const d = await r.json().catch(()=>({}));
              if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
              alert('Unpinned');
            };
            const btnLoadHist = box.querySelector('#btnLoadHist'); if (btnLoadHist) btnLoadHist.onclick = async ()=>{
              const type = (box.querySelector('#mtHistType').value||'public');
              const limit = parseInt((box.querySelector('#mtHistLimit').value||'50'),10)||50;
              const tid = parseInt((box.querySelector('#mtHistThreadId').value||'0'),10)||0;
              // If limit > 20, load from chat_messages.txt via log endpoint and open in popup
              if (limit > 20) {
                try {
                  const r = await fetch('/api/admin/history_log');
                  const txt = await r.text();
                  const win = window.open('', 'HistoryLog', 'width=900,height=600,scrollbars=yes');
                  if (win && win.document) {
                    win.document.write('<html><head><title>Chat History</title><style>body{font-family:monospace;white-space:pre-wrap;background:#111827;color:#e5e7eb;margin:0;padding:12px;} pre{margin:0;}</style></head><body><pre></pre></body></html>');
                    try {
                      win.document.body.querySelector('pre').textContent = txt || '(no history)';
                    } catch(_e) {}
                    win.document.close();
                  }
                } catch(e) {
                  alert('Failed to load history from log file');
                }
                return;
              }
              const qs = new URLSearchParams({ type, limit: String(limit) });
              if (type==='gdm' && tid>0) qs.set('thread_id', String(tid));
              const r = await fetch('/api/admin/history?'+qs.toString());
              const d = await r.json().catch(()=>({items:[]}));
              const out = (d.items||[]).map(m=>`#${m.id} <b>${(m.username||'')}</b>: <span>${(m.text||'')}</span> <i>${(m.created_at||'')}</i>`).join('<br>') || '<span style="color:#666">None</span>';
              box.querySelector('#mtHistOut').innerHTML = out;
            };
            const btnSaveLifespan = box.querySelector('#btnSaveLifespan'); if (btnSaveLifespan) btnSaveLifespan.onclick = async ()=>{
              const on = box.querySelector('#MC_MESSAGE_LIFESPAN').checked ? '1' : '0';
              const days = String(parseInt((box.querySelector('#MC_MESSAGE_LIFESPAN_DAYS').value||'0'),10)||0);
              const payload = { MC_MESSAGE_LIFESPAN: on, MC_MESSAGE_LIFESPAN_DAYS: days };
              const r = await fetch('/api/admin/app_settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              const d = await r.json().catch(()=>({}));
              if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
              alert('Lifespan saved');
            };
            const rb = box.querySelector('#admRestart'); if (rb) rb.onclick = async ()=>{
              if (!confirm('Restart the server now? Active connections will drop.')) return;
              try {
                const r = await fetch('/api/admin/restart', { method:'POST' });
                const d = await r.json().catch(()=>({}));
                if (!r.ok) { alert((d&&d.error)||'Failed'); return; }
                alert('Restarting in 1-2 seconds...');
              } catch(e){ alert('Failed'); }
            };
            await renderOnline();
          }
          // Bind buttons if present
          const b1 = document.getElementById('btnAdminDashHeader');
          const b2 = document.getElementById('btnAdminDashSettings');
          const b3 = document.getElementById('btnAdminDash');
          if (b1) b1.onclick = openAdminDashboard;
          if (b2) b2.onclick = openAdminDashboard;
          if (b3) b3.onclick = openAdminDashboard;
        })();
        {% endif %}
        document.getElementById('saveTheme').onclick = async () => {
            const theme = (document.getElementById('setTheme').value||'').trim().toLowerCase();
            const bio = document.getElementById('setBio') ? document.getElementById('setBio').value : '';
            const status = document.getElementById('setStatus') ? document.getElementById('setStatus').value : '';
            const payload = { theme, bio, status };
            const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
            const info = await res.json();
            if (!res.ok) { alert(info && info.error ? info.error : 'Failed to save'); return; }
            alert('Settings saved');
            try { await getProfiles(true); } catch(e) {}
            try { await refreshRightOnline(); } catch(e) {}
        };
        // Explicit Save Profile button support (if present)
        (function(){
          const btn = document.getElementById('saveProfile');
          if (!btn) return;
          btn.onclick = async () => {
            const bio = document.getElementById('setBio') ? document.getElementById('setBio').value : '';
            const status = document.getElementById('setStatus') ? document.getElementById('setStatus').value : '';
            const payload = { bio, status };
            const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
            const info = await res.json().catch(()=>null);
            if (!res.ok) { alert((info&&info.error)||'Failed to save profile'); return; }
            alert('Profile saved');
            try { await getProfiles(true); } catch(e) {}
            try { await refreshRightOnline(); } catch(e) {}
          };
        })();
        // Mark all as read
        (function(){
          const btn = document.getElementById('markAllReadBtn');
          if (!btn) return;
          btn.onclick = () => {
            try {
              localStorage.setItem('unreadDM','{}');
              localStorage.setItem('unreadGDM','{}');
            } catch(e) {}
            loadDMs();
            loadGDMs();
            updateTitleUnread();
            alert('All conversations marked as read');
          };
        })();
        // Clear all messages (admins only)
        (function(){
          const btn = document.getElementById('clearAllMsgs');
          if (!btn) return;
          try {
            btn.style.display = (isAdmin || SUPERADMINS.includes(me)) ? 'inline-block' : 'none';
          } catch(e) {}
          btn.onclick = async () => {
            if (!confirm('This will clear your DMs and group messages. If you are a superadmin, it will also clear public and all group messages. Continue?')) return;
            try {
              const res = await fetch('/api/clear/all', { method:'POST' });
              const info = await res.json().catch(()=>({}));
              if (!res.ok) { alert((info&&info.error)||'Failed to clear'); return; }
              try { localStorage.setItem('unreadDM','{}'); localStorage.setItem('unreadGDM','{}'); } catch(e) {}
              chatEl.innerHTML = '';
              messagesLoaded = false;
              switchToPublic();
              loadDMs();
              loadGDMs();
              updateTitleUnread();
              alert('Messages cleared');
            } catch(e) { alert('Failed'); }
          };
        })();
        document.getElementById('avatarForm').onsubmit = async (ev) => {
            ev.preventDefault();
            const fd = new FormData(document.getElementById('avatarForm'));
            const res = await fetch('/api/upload/avatar', { method:'POST', body: fd });
            const info = await res.json();
            if (!res.ok) { alert(info && info.error ? info.error : 'Upload failed'); return; }
            alert('Avatar updated');
            refreshRightOnline();
        };
        const delAvaBtn = document.getElementById('deleteAvatarBtn');
        if (delAvaBtn) delAvaBtn.onclick = async () => {
            const res = await fetch('/api/delete/avatar', { method:'POST' });
            if (!res.ok) { try { const info = await res.json(); alert(info.error||'Failed'); } catch(e) { alert('Failed'); } return; }
            alert('Avatar removed');
            refreshRightOnline();
        };

        // Hide deprecated friends UI if present
        (function(){
          try {
            const el = document.getElementById('allowDmNonfriends');
            if (el) {
              const row = el.closest('div') || el.parentElement;
              if (row) row.style.display = 'none';
            }
          } catch(e) {}
        })();
        // Update online count on page load
        updateOnlineCount();
        refreshRightOnline();
        setInterval(refreshRightOnline, 5000);
        // No periodic refresh
        loadDMs();
        loadGDMs();
        // Auto-open group via ?tid=
        try {
            const qs = new URLSearchParams(location.search);
            const tidParam = parseInt(qs.get('tid'));
            if (tidParam) {
                // remove from closed if present
                const arr = JSON.parse(localStorage.getItem('closedGDMs')||'[]');
                const sid = String(tidParam);
                const idx = arr.indexOf(sid);
                if (idx >= 0) { arr.splice(idx,1); localStorage.setItem('closedGDMs', JSON.stringify(arr)); }
                setTimeout(()=>openGDM(tidParam), 0);
            }
        } catch(e) {}
        updateTitleUnread();
        document.addEventListener('visibilitychange', updateTitleUnread);

        // Resizable columns: left and right
        try {
            const container = document.body; // page wrapper
            // Left resizer
            const resizerLeft = document.createElement('div');
            resizerLeft.id = 'resizerLeft';
            resizerLeft.title = 'Drag to resize';
            Object.assign(resizerLeft.style, {
                width:'4px', cursor:'col-resize', backgroundImage:'linear-gradient(#bbb 50%, transparent 50%)', backgroundSize:'4px 8px', backgroundRepeat:'repeat-y',
                zIndex:'10001'
            });
            // Insert after leftbar
            leftbar.parentElement.insertBefore(resizerLeft, leftbar.nextSibling);
            const loadLeftWidth = () => {
                const w = parseInt(localStorage.getItem('leftbarWidth')||'0');
                if (w>120 && w<500) leftbar.style.width = w+'px';
            };
            loadLeftWidth();
            let draggingL = false;
            resizerLeft.addEventListener('mousedown', e => { draggingL = true; document.body.style.userSelect='none'; });
            window.addEventListener('mouseup', ()=>{ draggingL=false; document.body.style.userSelect=''; });
            window.addEventListener('mousemove', e => {
                if (!draggingL) return;
                const x = e.clientX;
                const min=120, max=500;
                let w = Math.max(min, Math.min(max, x));
                leftbar.style.width = w + 'px';
                localStorage.setItem('leftbarWidth', String(w));
            });

            // Right resizer
            const rightOnlineListEl = document.getElementById('rightOnlineList');
            const rightbar = document.getElementById('rightbar') || (rightOnlineListEl ? rightOnlineListEl.parentElement : null);
            if (rightbar) {
                const resizerRight = document.createElement('div');
                resizerRight.id = 'resizerRight';
                resizerRight.title = 'Drag to resize';
                Object.assign(resizerRight.style, {
                    width:'4px', cursor:'col-resize', backgroundImage:'linear-gradient(#bbb 50%, transparent 50%)', backgroundSize:'4px 8px', backgroundRepeat:'repeat-y',
                    zIndex:'10001'
                });
                rightbar.parentElement.insertBefore(resizerRight, rightbar);
                const loadRightWidth = () => {
                    const w = parseInt(localStorage.getItem('rightbarWidth')||'0');
                    if (w>160 && w<600) rightbar.style.width = w+'px';
                };
                loadRightWidth();
                let draggingR = false;
                resizerRight.addEventListener('mousedown', e => { draggingR = true; document.body.style.userSelect='none'; });
                window.addEventListener('mouseup', ()=>{ draggingR=false; document.body.style.userSelect=''; });
                window.addEventListener('mousemove', e => {
                    if (!draggingR) return;
                    const winW = window.innerWidth;
                    const x = e.clientX;
                    // width of rightbar = remaining space from mouse to right edge
                    const min=160, max=600;
                    let w = Math.max(min, Math.min(max, winW - x));
                    rightbar.style.width = w + 'px';
                    localStorage.setItem('rightbarWidth', String(w));
                });
            }
        } catch(e) { console.warn('Resizers init failed', e); }
    </script>
</body>
</html>
"""

@app.context_processor
def inject():
    return dict(base_css=BASE_CSS)

# Run the application
if __name__ == "__main__":
    try:
        with app.app_context():
            init_db()
            recover_failed_username_changes()  # Recover from any failed username changes
            load_banned_ips()
        
        # Add global exception handler for critical errors
        def handle_critical_exception(exc_type, exc_value, exc_traceback):
            try:
                emergency_shutdown_activate(
                    trigger="SYSTEM_CRITICAL_ERROR",
                    admin="SYSTEM",
                    auto_backup=True,
                    db_path=DB_PATH,
                    get_db_func=get_db,
                    get_setting_func=get_setting,
                    set_setting_func=set_setting,
                    connected_sockets=connected_sockets,
                    spam_strikes=spam_strikes
                )
            except Exception:
                pass
            # Re-raise the original exception
            raise exc_value
        
        import sys
        sys.excepthook = handle_critical_exception
        
        socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Critical error: {e}")
        try:
            emergency_shutdown_activate(
                trigger="SYSTEM_STARTUP_ERROR",
                admin="SYSTEM",
                auto_backup=True
            )
        except Exception:
            pass
        raise
