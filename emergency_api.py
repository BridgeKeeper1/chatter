# ============================================================================
# EMERGENCY MANAGEMENT API ENDPOINTS
# ============================================================================

@app.route('/api/admin/emergency/trigger', methods=['POST'])
def api_admin_emergency_trigger():
    """Manually trigger emergency shutdown"""
    if not session.get('username') or not is_superadmin(session['username']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json() or {}
        trigger_source = data.get('trigger_source', 'manual_admin')
        trigger_details = data.get('details', {})
        
        success = _trigger_emergency_shutdown(
            trigger_source=trigger_source,
            trigger_details=trigger_details,
            actor=session['username']
        )
        
        if success:
            return jsonify({'success': True, 'message': 'Emergency shutdown triggered'})
        else:
            return jsonify({'error': 'Failed to trigger emergency shutdown'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/emergency/status', methods=['GET'])
def api_admin_emergency_status():
    """Get comprehensive emergency system status"""
    if not session.get('username') or not is_superadmin(session['username']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        status = {
            'emergency_active': _is_emergency_shutdown(),
            'recovery_stage': emergency_system_state.get('recovery_stage', 'normal'),
            'shutdown_trigger': emergency_system_state.get('shutdown_trigger'),
            'shutdown_timestamp': emergency_system_state.get('shutdown_timestamp'),
            'active_users_at_shutdown': emergency_system_state.get('active_users_at_shutdown', []),
            'locked_users': list(emergency_system_state.get('locked_users', set())),
            'current_metrics': _get_system_metrics(),
            'resource_monitoring': emergency_system_state.get('resource_monitoring', {}),
            'automatic_triggers_active': emergency_system_state.get('automatic_triggers_active', True),
            'recent_actions': emergency_system_state.get('recent_actions_at_shutdown', [])[:10]  # Last 10 actions
        }
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/emergency/recovery/<stage>', methods=['POST'])
def api_admin_emergency_recovery(stage):
    """Execute staged recovery steps"""
    if not session.get('username') or not is_superadmin(session['username']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        valid_stages = ['stage1', 'stage2', 'stage3', 'complete']
        if stage not in valid_stages:
            return jsonify({'error': f'Invalid stage. Must be one of: {valid_stages}'}), 400
        
        success = _staged_recovery_step(stage, actor=session['username'])
        
        if success:
            return jsonify({'success': True, 'message': f'Recovery {stage} executed'})
        else:
            return jsonify({'error': f'Failed to execute recovery {stage}'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/emergency/lock_user', methods=['POST'])
def api_admin_emergency_lock_user():
    """Lock a specific user during emergency"""
    if not session.get('username') or not is_superadmin(session['username']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json() or {}
        target_user = data.get('username', '').strip()
        reason = data.get('reason', 'Emergency lockdown')
        
        if not target_user:
            return jsonify({'error': 'Username required'}), 400
        
        success = _lock_user_emergency(target_user, reason, actor=session['username'])
        
        if success:
            return jsonify({'success': True, 'message': f'User {target_user} locked'})
        else:
            return jsonify({'error': f'Failed to lock user {target_user}'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/emergency/unlock_user', methods=['POST'])
def api_admin_emergency_unlock_user():
    """Unlock a specific user during emergency"""
    if not session.get('username') or not is_superadmin(session['username']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json() or {}
        target_user = data.get('username', '').strip()
        
        if not target_user:
            return jsonify({'error': 'Username required'}), 400
        
        success = _unlock_user_emergency(target_user, actor=session['username'])
        
        if success:
            return jsonify({'success': True, 'message': f'User {target_user} unlocked'})
        else:
            return jsonify({'error': f'Failed to unlock user {target_user}'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/emergency/toggle_triggers', methods=['POST'])
def api_admin_emergency_toggle_triggers():
    """Toggle automatic emergency triggers on/off"""
    if not session.get('username') or not is_superadmin(session['username']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json() or {}
        enabled = data.get('enabled', True)
        
        emergency_system_state['automatic_triggers_active'] = bool(enabled)
        
        _log_incident('emergency_triggers_toggled', {
            'enabled': enabled,
            'actor': session['username'],
            'timestamp': time.time()
        })
        
        return jsonify({
            'success': True, 
            'message': f'Automatic triggers {"enabled" if enabled else "disabled"}',
            'enabled': enabled
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

