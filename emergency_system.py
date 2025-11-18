# ============================================================================
# COMPREHENSIVE EMERGENCY SHUTDOWN SYSTEM ENHANCEMENTS
# ============================================================================

# Emergency system state tracking
emergency_system_state = {
    'active_users_at_shutdown': [],
    'recent_actions_at_shutdown': [],
    'system_metrics_at_shutdown': {},
    'shutdown_trigger': None,
    'shutdown_timestamp': None,
    'recovery_stage': 'normal',  # normal, emergency, recovery_stage1, recovery_stage2, recovery_stage3
    'locked_users': set(),
    'automatic_triggers_active': True,
    'last_health_check': 0,
    'resource_monitoring': {
        'cpu_alerts': 0,
        'memory_alerts': 0,
        'db_connection_failures': 0,
        'exception_count': 0,
        'ddos_score': 0
    }
}

def _get_system_metrics():
    """Collect current system metrics for monitoring and logging"""
    try:
        import psutil
        metrics = {
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'active_connections': len(online_users),
            'timestamp': time.time()
        }
    except ImportError:
        # Fallback metrics without psutil
        metrics = {
            'active_connections': len(online_users),
            'timestamp': time.time(),
            'cpu_percent': 0,
            'memory_percent': 0,
            'disk_usage': 0
        }
    except Exception:
        metrics = {'timestamp': time.time(), 'error': 'metrics_collection_failed'}
    
    return metrics

def _capture_emergency_snapshot():
    """Capture comprehensive system state during emergency shutdown"""
    try:
        # Capture active users
        emergency_system_state['active_users_at_shutdown'] = list(online_users.keys())
        
        # Capture system metrics
        emergency_system_state['system_metrics_at_shutdown'] = _get_system_metrics()
        
        # Capture recent actions (last 50 from audit log)
        try:
            db = get_db()
            cur = db.cursor()
            cur.execute('SELECT actor, action, target, created_at FROM admin_audit ORDER BY created_at DESC LIMIT 50')
            emergency_system_state['recent_actions_at_shutdown'] = [
                {'actor': r[0], 'action': r[1], 'target': r[2], 'timestamp': r[3]}
                for r in cur.fetchall()
            ]
        except Exception:
            emergency_system_state['recent_actions_at_shutdown'] = []
        
        # Set shutdown timestamp
        emergency_system_state['shutdown_timestamp'] = time.time()
        
        # Log comprehensive emergency state
        _log_incident('emergency_state_capture', {
            'active_users': len(emergency_system_state['active_users_at_shutdown']),
            'system_metrics': emergency_system_state['system_metrics_at_shutdown'],
            'recent_actions_count': len(emergency_system_state['recent_actions_at_shutdown']),
            'trigger': emergency_system_state.get('shutdown_trigger', 'manual')
        })
        
    except Exception as e:
        _log_incident('emergency_state_capture_failed', {'error': str(e)})

def _trigger_emergency_shutdown(trigger_source, trigger_details=None, actor=None):
    """Trigger emergency shutdown with comprehensive logging and state capture"""
    try:
        # Set emergency state
        emergency_system_state['shutdown_trigger'] = trigger_source
        emergency_system_state['recovery_stage'] = 'emergency'
        
        # Capture system state before shutdown
        _capture_emergency_snapshot()
        
        # Enable emergency shutdown setting
        set_setting('ADMIN_EMERGENCY_SHUTDOWN', '1')
        
        # Create database snapshot
        _maybe_snapshot_db_on_emergency('0', '1')
        
        # Log the emergency trigger
        meta = {
            'trigger_source': trigger_source,
            'trigger_details': trigger_details or {},
            'actor': actor or session.get('username', 'system'),
            'active_users_count': len(online_users),
            'timestamp': time.time()
        }
        _log_incident('emergency_shutdown_triggered', meta)
        
        # Send emergency notifications to all connected users
        try:
            socketio.emit('emergency_shutdown', {
                'message': 'Emergency maintenance in progress. Chat is now read-only.',
                'timestamp': time.time()
            }, room='chat_room')
        except Exception:
            pass
        
        return True
        
    except Exception as e:
        _log_incident('emergency_shutdown_failed', {'error': str(e), 'trigger': trigger_source})
        return False

def _check_automatic_triggers():
    """Monitor system health and trigger emergency shutdown if thresholds exceeded"""
    if not emergency_system_state['automatic_triggers_active']:
        return
    
    try:
        now = time.time()
        
        # Only check every 30 seconds to avoid overhead
        if now - emergency_system_state['last_health_check'] < 30:
            return
        
        emergency_system_state['last_health_check'] = now
        
        # Get current metrics
        metrics = _get_system_metrics()
        
        # Check CPU usage (trigger if >90% for extended period)
        if metrics.get('cpu_percent', 0) > 90:
            emergency_system_state['resource_monitoring']['cpu_alerts'] += 1
            if emergency_system_state['resource_monitoring']['cpu_alerts'] >= 3:
                _trigger_emergency_shutdown('cpu_exhaustion', {
                    'cpu_percent': metrics['cpu_percent'],
                    'consecutive_alerts': emergency_system_state['resource_monitoring']['cpu_alerts']
                })
                return
        else:
            emergency_system_state['resource_monitoring']['cpu_alerts'] = 0
        
        # Check memory usage (trigger if >95%)
        if metrics.get('memory_percent', 0) > 95:
            emergency_system_state['resource_monitoring']['memory_alerts'] += 1
            if emergency_system_state['resource_monitoring']['memory_alerts'] >= 2:
                _trigger_emergency_shutdown('memory_exhaustion', {
                    'memory_percent': metrics['memory_percent'],
                    'consecutive_alerts': emergency_system_state['resource_monitoring']['memory_alerts']
                })
                return
        else:
            emergency_system_state['resource_monitoring']['memory_alerts'] = 0
        
        # Check for too many active connections (potential DDoS)
        active_count = len(online_users)
        if active_count > 1000:  # Configurable threshold
            emergency_system_state['resource_monitoring']['ddos_score'] += 1
            if emergency_system_state['resource_monitoring']['ddos_score'] >= 5:
                _trigger_emergency_shutdown('ddos_detected', {
                    'active_connections': active_count,
                    'threshold': 1000
                })
                return
        else:
            emergency_system_state['resource_monitoring']['ddos_score'] = max(0, 
                emergency_system_state['resource_monitoring']['ddos_score'] - 1)
        
    except Exception as e:
        _log_incident('automatic_trigger_check_failed', {'error': str(e)})

def _staged_recovery_step(stage, actor=None):
    """Execute staged recovery steps"""
    try:
        actor = actor or session.get('username', 'system')
        
        if stage == 'stage1':  # Enable read-only chat
            emergency_system_state['recovery_stage'] = 'recovery_stage1'
            set_setting('EMERGENCY_RECOVERY_STAGE', '1')
            _log_incident('recovery_stage1', {'actor': actor, 'description': 'Read-only chat enabled'})
            
        elif stage == 'stage2':  # Enable limited write operations
            emergency_system_state['recovery_stage'] = 'recovery_stage2'
            set_setting('EMERGENCY_RECOVERY_STAGE', '2')
            _log_incident('recovery_stage2', {'actor': actor, 'description': 'Limited write operations enabled'})
            
        elif stage == 'stage3':  # Full system recovery
            emergency_system_state['recovery_stage'] = 'recovery_stage3'
            set_setting('EMERGENCY_RECOVERY_STAGE', '3')
            _log_incident('recovery_stage3', {'actor': actor, 'description': 'Full system recovery initiated'})
            
        elif stage == 'complete':  # Complete recovery
            emergency_system_state['recovery_stage'] = 'normal'
            emergency_system_state['locked_users'].clear()
            set_setting('ADMIN_EMERGENCY_SHUTDOWN', '0')
            set_setting('EMERGENCY_RECOVERY_STAGE', '0')
            _log_incident('recovery_complete', {'actor': actor, 'description': 'Emergency shutdown ended'})
            
            # Notify all users
            try:
                socketio.emit('emergency_recovery', {
                    'message': 'Emergency maintenance completed. Full functionality restored.',
                    'timestamp': time.time()
                }, room='chat_room')
            except Exception:
                pass
        
        return True
        
    except Exception as e:
        _log_incident('staged_recovery_failed', {'stage': stage, 'error': str(e), 'actor': actor})
        return False

def _lock_user_emergency(username, reason='Emergency lockdown', actor=None):
    """Lock a specific user during emergency"""
    try:
        emergency_system_state['locked_users'].add(username)
        actor = actor or session.get('username', 'system')
        
        _log_incident('emergency_user_lock', {
            'target_user': username,
            'reason': reason,
            'actor': actor,
            'timestamp': time.time()
        })
        
        # Disconnect user if online
        try:
            if username in online_users:
                # Send notification before disconnect
                socketio.emit('system_message', 
                    f'Your account has been temporarily locked: {reason}', 
                    room=f'user:{username}')
                # Note: Actual disconnection would require tracking socket IDs
        except Exception:
            pass
        
        return True
        
    except Exception as e:
        _log_incident('emergency_user_lock_failed', {'error': str(e), 'target': username})
        return False

def _unlock_user_emergency(username, actor=None):
    """Unlock a user during emergency"""
    try:
        emergency_system_state['locked_users'].discard(username)
        actor = actor or session.get('username', 'system')
        
        _log_incident('emergency_user_unlock', {
            'target_user': username,
            'actor': actor,
            'timestamp': time.time()
        })
        
        return True
        
    except Exception as e:
        _log_incident('emergency_user_unlock_failed', {'error': str(e), 'target': username})
        return False

def _is_user_locked_emergency(username):
    """Check if user is locked during emergency"""
    return username in emergency_system_state['locked_users']

