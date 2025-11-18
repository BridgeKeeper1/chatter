              // Enhanced Emergency Management JavaScript
              try {
                const emOn = get1('ADMIN_EMERGENCY_SHUTDOWN');
                const showBlock = get1('ADMIN_SHOW_EMERGENCY_BLOCK');
                const cardEl = box.querySelector('#admEmergencyCard');
                const emStatusEl = box.querySelector('#admEmergencyStatus');
                const emSnapEl = box.querySelector('#admEmergencySnapshot');
                const recoveryControlsEl = box.querySelector('#recoveryControls');
                const metricsDisplayEl = box.querySelector('#metricsDisplay');
                
                if (!cardEl) { /* nothing to do */ }
                else if (!(emOn || showBlock)) {
                  cardEl.style.display = 'none';
                } else {
                  cardEl.style.display = '';
                  
                  // Update status display
                  if (emStatusEl) {
                    emStatusEl.textContent = emOn ? '🚨 Emergency shutdown: ACTIVE' : '✅ Emergency shutdown: inactive';
                    emStatusEl.style.color = emOn ? '#dc2626' : '#059669';
                  }
                  
                  // Update snapshot info
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
                  
                  // Show/hide recovery controls based on emergency state
                  if (recoveryControlsEl) {
                    recoveryControlsEl.style.display = emOn ? '' : 'none';
                  }
                  
                  // Load and display system metrics
                  if (metricsDisplayEl) {
                    fetch('/api/admin/emergency/status')
                      .then(r => r.json())
                      .then(data => {
                        if (data.current_metrics) {
                          const m = data.current_metrics;
                          const parts = [];
                          if (m.cpu_percent) parts.push(`CPU: ${m.cpu_percent.toFixed(1)}%`);
                          if (m.memory_percent) parts.push(`Memory: ${m.memory_percent.toFixed(1)}%`);
                          if (m.active_connections !== undefined) parts.push(`Users: ${m.active_connections}`);
                          metricsDisplayEl.textContent = parts.join(' | ') || 'Metrics unavailable';
                        }
                      })
                      .catch(() => {
                        metricsDisplayEl.textContent = 'Metrics unavailable';
                      });
                  }
                }
                
                // Emergency control button handlers
                const btnTriggerEmergency = box.querySelector('#btnTriggerEmergency');
                const btnEmergencyStatus = box.querySelector('#btnEmergencyStatus');
                const btnToggleTriggers = box.querySelector('#btnToggleTriggers');
                
                if (btnTriggerEmergency) {
                  btnTriggerEmergency.onclick = () => {
                    if (confirm('⚠️ This will immediately trigger emergency shutdown. Continue?')) {
                      fetch('/api/admin/emergency/trigger', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({trigger_source: 'manual_admin'})
                      })
                      .then(r => r.json())
                      .then(data => {
                        if (data.success) {
                          alert('✅ Emergency shutdown triggered');
                          location.reload();
                        } else {
                          alert('❌ Failed: ' + (data.error || 'Unknown error'));
                        }
                      })
                      .catch(e => alert('❌ Error: ' + e.message));
                    }
                  };
                }
                
                if (btnEmergencyStatus) {
                  btnEmergencyStatus.onclick = () => {
                    fetch('/api/admin/emergency/status')
                      .then(r => r.json())
                      .then(data => {
                        const info = [
                          `Emergency Active: ${data.emergency_active ? 'YES' : 'NO'}`,
                          `Recovery Stage: ${data.recovery_stage || 'normal'}`,
                          `Trigger: ${data.shutdown_trigger || 'none'}`,
                          `Locked Users: ${(data.locked_users || []).length}`,
                          `Auto-Triggers: ${data.automatic_triggers_active ? 'ON' : 'OFF'}`
                        ];
                        alert(info.join('\\n'));
                      })
                      .catch(e => alert('❌ Error: ' + e.message));
                  };
                }
                
                if (btnToggleTriggers) {
                  btnToggleTriggers.onclick = () => {
                    const enable = confirm('Enable automatic emergency triggers?\\n\\nCancel = Disable triggers');
                    fetch('/api/admin/emergency/toggle_triggers', {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      body: JSON.stringify({enabled: enable})
                    })
                    .then(r => r.json())
                    .then(data => {
                      if (data.success) {
                        alert(`✅ Auto-triggers ${data.enabled ? 'enabled' : 'disabled'}`);
                      } else {
                        alert('❌ Failed: ' + (data.error || 'Unknown error'));
                      }
                    })
                    .catch(e => alert('❌ Error: ' + e.message));
                  };
                }
                
                // Recovery stage button handlers
                ['Stage1', 'Stage2', 'Stage3', 'Complete'].forEach(stage => {
                  const btn = box.querySelector(`#btnRecovery${stage}`);
                  if (btn) {
                    btn.onclick = () => {
                      const stageKey = stage.toLowerCase();
                      if (confirm(`Execute recovery ${stage}?`)) {
                        fetch(`/api/admin/emergency/recovery/${stageKey}`, {method: 'POST'})
                          .then(r => r.json())
                          .then(data => {
                            if (data.success) {
                              alert(`✅ Recovery ${stage} executed`);
                              location.reload();
                            } else {
                              alert('❌ Failed: ' + (data.error || 'Unknown error'));
                            }
                          })
                          .catch(e => alert('❌ Error: ' + e.message));
                      }
                    };
                  }
                });
                
                // User lock/unlock handlers
                const btnLockUser = box.querySelector('#btnLockUser');
                const btnUnlockUser = box.querySelector('#btnUnlockUser');
                const lockUsernameInput = box.querySelector('#lockUsername');
                const lockReasonInput = box.querySelector('#lockReason');
                
                if (btnLockUser && lockUsernameInput) {
                  btnLockUser.onclick = () => {
                    const username = lockUsernameInput.value.trim();
                    const reason = lockReasonInput ? lockReasonInput.value.trim() : '';
                    if (!username) {
                      alert('Please enter a username');
                      return;
                    }
                    if (confirm(`Lock user "${username}" during emergency?`)) {
                      fetch('/api/admin/emergency/lock_user', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username, reason: reason || 'Emergency lockdown'})
                      })
                      .then(r => r.json())
                      .then(data => {
                        if (data.success) {
                          alert(`✅ User ${username} locked`);
                          lockUsernameInput.value = '';
                          if (lockReasonInput) lockReasonInput.value = '';
                        } else {
                          alert('❌ Failed: ' + (data.error || 'Unknown error'));
                        }
                      })
                      .catch(e => alert('❌ Error: ' + e.message));
                    }
                  };
                }
                
                if (btnUnlockUser && lockUsernameInput) {
                  btnUnlockUser.onclick = () => {
                    const username = lockUsernameInput.value.trim();
                    if (!username) {
                      alert('Please enter a username');
                      return;
                    }
                    if (confirm(`Unlock user "${username}"?`)) {
                      fetch('/api/admin/emergency/unlock_user', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username})
                      })
                      .then(r => r.json())
                      .then(data => {
                        if (data.success) {
                          alert(`✅ User ${username} unlocked`);
                          lockUsernameInput.value = '';
                        } else {
                          alert('❌ Failed: ' + (data.error || 'Unknown error'));
                        }
                      })
                      .catch(e => alert('❌ Error: ' + e.message));
                    }
                  };
                }
                
              } catch(_){ }

