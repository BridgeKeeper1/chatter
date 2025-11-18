# STATUS CIRCLE IMPROVEMENTS - Enhanced from 8px to 12px with 3px borders
# These changes make status indicators more visible and professional

# 1. Admin items status circles (line ~731)
const items=(list||[]).map(function(a){ 
    return '<div class="admin-item" style="display:flex;align-items:center;gap:6px;padding:4px 0">' +
           '<span class="dot" style="width:12px;height:12px;border-radius:50%;background:#22c55e;display:inline-block;border:3px solid #fff"></span>' +
           '<span>'+a.username+'</span>'+badge(a.role)+'</div>'; 
}).join('');

# 2. Admin mirror status circles (line ~734)
function mirror(list){ 
    const host=bySel(); 
    if(!host) return; 
    host.querySelectorAll('.admin-mirror').forEach(function(el){ el.remove(); }); 
    (list||[]).forEach(function(a){ 
        const el=document.createElement('div'); 
        el.className='admin-mirror'; 
        el.style.display='flex'; 
        el.style.alignItems='center'; 
        el.style.gap='6px'; 
        el.style.padding='4px 0'; 
        el.innerHTML = '<span class="dot" style="width:12px;height:12px;border-radius:50%;background:#22c55e;display:inline-block;border:3px solid #fff"></span>' +
                      '<span>'+a.username+'</span>'+badge(a.role); 
        host.appendChild(el); 
    }); 
}

# 3. General status dot CSS (line ~9081-9086)
.status-dot {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #4CAF50;
    margin-right: 4px;
    border: 3px solid #fff;
}

# 4. Profile popover status circles (line ~10988-10989)
<img src='${ava}' alt='' style='width:28px;height:28px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
<span style='position:absolute;right:-2px;bottom:-2px;display:inline-block;width:12px;height:12px;border-radius:50%;background:${color};border:3px solid #fff'></span>

# 5. Another profile popover instance (line ~11008-11009)
<img src='${ava}' alt='' style='width:28px;height:28px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
<span style='position:absolute;right:-2px;bottom:-2px;display:inline-block;width:12px;height:12px;border-radius:50%;background:${color};border:3px solid #fff'></span>

# 6. Inline status indicator (line ~11102)
<span style='display:inline-block;width:12px;height:12px;border-radius:50%;background:${color};border:3px solid #fff'></span>

# 7. Message status indicator (line ~11282)
<span style='position:absolute;right:-2px;bottom:-2px;display:inline-block;width:12px;height:12px;border-radius:50%;background:${color};border:3px solid #fff'></span>

# ============================================================================
# DISCORD-INSPIRED MOBILE UI REDESIGN - Full responsive design system
# ============================================================================

<style>
/* Full-Screen Responsive Design - Always show all elements */

/* Small phones (up to 480px) - Full screen with scaled elements */
@media (max-width: 480px) {
  .app { 
    display: flex !important; 
    flex-direction: row !important; 
    gap: 2px !important; 
    height: 100vh; 
    overflow: hidden;
  }
  
  /* Scale sidebars to fit */
  #leftbar { 
    width: 25% !important; 
    min-width: 80px !important; 
    max-width: 120px !important;
    padding: 4px !important;
    overflow-y: auto;
    font-size: 11px;
  }
  #rightbar { 
    width: 20% !important; 
    min-width: 60px !important; 
    max-width: 100px !important;
    padding: 4px !important;
    overflow-y: auto;
    font-size: 11px;
  }
  
  /* Main chat area takes remaining space */
  #main { 
    flex: 1 !important; 
    min-width: 0 !important;
    padding: 2px !important;
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
  }
  
  /* Chat area with proper scrolling */
  .chat { 
    flex: 1;
    overflow-y: auto;
    padding: 4px !important;
    font-size: 13px;
    line-height: 1.3;
  }
  
  /* Compact form at bottom */
  .form-row { 
    flex-shrink: 0;
    padding: 4px !important;
    background: var(--bg);
  }
  
  /* Smaller text input but still usable */
  #textInput { 
    font-size: 14px !important; 
    padding: 8px 6px !important; 
    min-height: 36px !important;
    border-radius: 6px;
  }
  
  /* Compact buttons */
  #sendForm button { 
    padding: 8px 10px !important; 
    min-height: 36px !important; 
    font-size: 12px !important;
  }
  
  /* Smaller sidebar buttons */
  #leftbar button, #rightbar button { 
    font-size: 10px !important; 
    padding: 4px 6px !important;
    min-height: 32px !important;
  }
  
  /* Compact messages */
  .message { 
    font-size: 12px !important; 
    line-height: 1.3 !important; 
    padding: 4px !important;
    margin: 2px 0 !important;
  }
  .username { 
    font-size: 11px !important; 
    font-weight: 600;
  }
  
  /* Hide mobile nav - not needed in full screen */
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
  #textInput { min-height: 32px !important; }
  #sendForm button { min-height: 32px !important; }
}
</style>

# ============================================================================
# SUMMARY OF CHANGES
# ============================================================================

# STATUS CIRCLE IMPROVEMENTS:
# - Increased size from 8px × 8px to 12px × 12px
# - Added 3px white borders for better visibility
# - Applied consistently across all status indicators
# - More professional and Discord-like appearance

# MOBILE UI REDESIGN:
# - Discord-inspired responsive design system
# - Full-screen layout that always shows all elements
# - Responsive breakpoints for different screen sizes:
#   * Small phones (≤480px): Compact 3-column layout
#   * Regular phones (481-768px): Better proportioned layout  
#   * Tablets (769-1024px): Standard full screen
#   * Large tablets/laptops (1025-1440px): Optimal spacing
#   * Large screens (1441px+): Maximum full screen
# - Proper overflow handling and scrolling
# - Landscape orientation support
# - No mobile navigation overlay needed
# - Maintains usability across all device sizes

