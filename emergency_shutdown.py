#!/usr/bin/env python3
"""
Emergency Shutdown System for Chatter
Comprehensive emergency shutdown mechanism for instant and safe application offline mode
"""

import os
import time
import shutil
from datetime import datetime, timedelta
from collections import defaultdict

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

