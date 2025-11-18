#!/usr/bin/env python3
"""
Enhanced Anti-Spam System for Chatter
Comprehensive spam protection with all requested features
"""

import time
import difflib
import zlib
import re
from collections import defaultdict

# Enhanced anti-spam state tracking
spam_public = defaultdict(list)  # username -> [ts,...]
spam_dm = defaultdict(list)      # username -> [ts,...]
spam_gdm = defaultdict(list)     # username -> [ts,...]

# Extended anti-spam state for content-based checks and progressive sanctions
spam_recent_public = defaultdict(list)  # username -> [(ts, norm_text)]
spam_recent_dm = defaultdict(list)
spam_recent_gdm = defaultdict(list)
spam_strikes = defaultdict(lambda: {'count': 0.0, 'ts': 0.0})  # username -> {count, ts}
spam_slow_until = defaultdict(float)   # username -> unix timestamp until slow-mode expires
spam_block_until = defaultdict(float)  # username -> unix timestamp until hard block expires

# Auto-split tracking for rate limiting
spam_split_queue = defaultdict(list)  # username -> [(ts, chunk), ...]

def _spam_auto_split_message(text: str, max_chars: int = 500) -> list[str]:
    """Auto-split large messages into smaller chunks."""
    if not text or len(text) <= max_chars:
        return [text] if text else []
    
    chunks = []
    # Try to split by paragraphs first
    paragraphs = text.split('\n\n')
    current_chunk = ""
    
    for para in paragraphs:
        if len(current_chunk + para) <= max_chars:
            current_chunk += para + '\n\n'
        else:
            if current_chunk:
                chunks.append(current_chunk.rstrip())
                current_chunk = ""
            
            # If single paragraph is too long, split by sentences
            if len(para) > max_chars:
                sentences = para.split('. ')
                for i, sentence in enumerate(sentences):
                    if i < len(sentences) - 1:
                        sentence += '. '
                    
                    if len(current_chunk + sentence) <= max_chars:
                        current_chunk += sentence
                    else:
                        if current_chunk:
                            chunks.append(current_chunk.rstrip())
                        current_chunk = sentence
            else:
                current_chunk = para + '\n\n'
    
    if current_chunk:
        chunks.append(current_chunk.rstrip())
    
    return chunks

def _spam_record_strike(user: str, severity: float = 1.0, get_setting_func=None) -> None:
    """Record a spam strike and apply progressive sanctions."""
    try:
        if not user:
            return
        now = time.time()
        
        # Get settings with fallbacks
        try:
            slow_seconds = float(get_setting_func('SPAM_SLOW_SECONDS','10') if get_setting_func else 10.0)
        except Exception:
            slow_seconds = 10.0
        if slow_seconds < 1.0:
            slow_seconds = 1.0
        elif slow_seconds > 120.0:
            slow_seconds = 120.0
        
        block_short = max(30.0, slow_seconds * 6.0)
        block_long = max(60.0, slow_seconds * 30.0)
        
        st = spam_strikes[user]
        last_ts = float(st.get('ts') or 0.0)
        
        # Decay old strikes after ~5 minutes
        if last_ts and (now - last_ts) > 300.0:
            st['count'] = 0.0
        
        st['count'] = float(st.get('count') or 0.0) + float(severity)
        st['ts'] = now
        c = float(st.get('count') or 0.0)
        
        # Progressive escalation: strikes drive slow-mode and temporary blocks
        if c >= 4.0:
            spam_block_until[user] = max(float(spam_block_until.get(user) or 0.0), now + block_long)
        elif c >= 3.0:
            spam_block_until[user] = max(float(spam_block_until.get(user) or 0.0), now + block_short)
        elif c >= 2.0:
            spam_slow_until[user] = max(float(spam_slow_until.get(user) or 0.0), now + slow_seconds)
    except Exception:
        pass

def _spam_enhanced_content_analysis(text: str) -> tuple[bool, str]:
    """Enhanced content pattern analysis."""
    if not text:
        return True, ""
    
    lower = text.lower()
    
    # HTML/CSS/JS dump detection
    try:
        tag_hits = sum(lower.count(tag) for tag in ('<div', '<script', '<style', '<html', '<body', '<span', '<p>'))
        css_hits = sum(lower.count(prop) for prop in ('margin:', 'padding:', 'background:', 'color:', 'font-'))
        js_hits = sum(lower.count(keyword) for keyword in ('function(', 'var ', 'let ', 'const ', '=>'))
    except Exception:
        tag_hits = css_hits = js_hits = 0
    
    br_hits = lower.count('<br') if '<' in lower else 0
    newline_hits = text.count('\n')
    
    # Excessive whitespace detection
    whitespace_ratio = (text.count(' ') + text.count('\t') + text.count('\n')) / max(len(text), 1)
    
    # Repeated character patterns
    repeated_chars = len(re.findall(r'(.)\1{10,}', text))  # 10+ repeated chars
    
    if tag_hits >= 10 or br_hits >= 20 or newline_hits >= 80:
        return False, "Large HTML/code dumps are not allowed. Please send files or smaller snippets."
    
    if css_hits >= 5 or js_hits >= 5:
        return False, "Large CSS/JavaScript code blocks should be sent as files."
    
    if whitespace_ratio > 0.7 and len(text) > 100:
        return False, "Messages with excessive whitespace are not allowed."
    
    if repeated_chars >= 3:
        return False, "Messages with excessive repeated characters are not allowed."
    
    return True, ""

def _spam_gate_and_update(kind: str, username: str, text: str, *, has_attachment: bool = False, 
                         get_setting_func=None, superadmins=None):
    """
    Comprehensive spam gate with all requested features:
    1. Message Length Limit
    2. Duplicate & Near-Duplicate Detection  
    3. Payload Size Monitoring
    4. Auto-Split with Rate Limiting
    5. Individual Slow Mode
    6. Content Pattern Analysis
    7. Progressive Sanction System
    """
    try:
        if not username:
            return True, None, []
        
        # Superadmins bypass spam gates to avoid accidental lockouts
        try:
            if superadmins and username in superadmins:
                return True, None, []
        except Exception:
            pass

        now = time.time()

        # Load configurable thresholds with safe fallbacks
        try:
            max_chars = int(get_setting_func('SPAM_MAX_CHARS', '1000') if get_setting_func else 1000)
        except Exception:
            max_chars = 1000
        try:
            max_bytes = int(get_setting_func('SPAM_MAX_BYTES', '4000') if get_setting_func else 4000)
        except Exception:
            max_bytes = 4000
        try:
            rate_window = float(get_setting_func('SPAM_WINDOW_SECONDS', '10') if get_setting_func else 10.0)
        except Exception:
            rate_window = 10.0
        try:
            min_gap = float(get_setting_func('SPAM_MIN_GAP_SECONDS', '0.7') if get_setting_func else 0.7)
        except Exception:
            min_gap = 0.7
        try:
            max_per_window = int(get_setting_func('SPAM_MAX_PER_WINDOW', '8') if get_setting_func else 8)
        except Exception:
            max_per_window = 8
        try:
            sensitivity = float(get_setting_func('SPAM_SENSITIVITY', '1.0') if get_setting_func else 1.0)
        except Exception:
            sensitivity = 1.0
        if sensitivity < 0.25:
            sensitivity = 0.25
        elif sensitivity > 3.0:
            sensitivity = 3.0
        
        try:
            auto_split_threshold = int(get_setting_func('SPAM_AUTO_SPLIT_THRESHOLD', '800') if get_setting_func else 800)
        except Exception:
            auto_split_threshold = 800

        # Hard block gate (user fully blocked for a short period)
        try:
            block_until = float(spam_block_until.get(username) or 0.0)
        except Exception:
            block_until = 0.0
        if block_until:
            if now < block_until:
                return False, "You are temporarily blocked from sending messages due to spam-like activity.", []
            # Expired
            spam_block_until.pop(username, None)

        # Slow mode gate (per-user, any channel)
        try:
            slow_until = float(spam_slow_until.get(username) or 0.0)
        except Exception:
            slow_until = 0.0
        if slow_until and now < slow_until:
            return False, "Slow mode is enabled for you. Please wait a few seconds before sending another message.", []
        if slow_until and now >= slow_until:
            spam_slow_until.pop(username, None)

        # Choose per-channel history and recent text buffers
        if kind == 'dm':
            hist = spam_dm[username]
            recent = spam_recent_dm[username]
        elif kind == 'gdm':
            hist = spam_gdm[username]
            recent = spam_recent_gdm[username]
        else:
            hist = spam_public[username]
            recent = spam_recent_public[username]

        # Auto-split large messages
        raw = (text or '').strip()
        message_chunks = []
        
        if raw and len(raw) > auto_split_threshold:
            # Check if message should be auto-split
            if len(raw) <= max_chars * 3:  # Only auto-split reasonably sized messages
                chunks = _spam_auto_split_message(raw, auto_split_threshold)
                if len(chunks) > 1:
                    message_chunks = chunks
                    # For auto-split, we'll process the first chunk normally and queue the rest
                    raw = chunks[0]
                    
                    # Queue remaining chunks with rate limiting
                    split_queue = spam_split_queue[username]
                    split_queue.clear()  # Clear old queue
                    for i, chunk in enumerate(chunks[1:], 1):
                        split_queue.append((now + i * 1.0, chunk))  # 1 second between chunks

        # Baseline rate limit: ~1 msg / min_gap, max ~max_per_window msgs / rate_window
        window = rate_window
        hist[:] = [t for t in hist if now - t <= window]
        if hist and ((now - hist[-1]) < min_gap or len(hist) >= max_per_window):
            base_sev = 1.5 if len(hist) >= max_per_window else 1.0
            _spam_record_strike(username, severity=base_sev * sensitivity, get_setting_func=get_setting_func)
            return False, "You are sending messages too quickly; please slow down.", []
        hist.append(now)

        if raw:
            # Message length / payload size limits (server-side backstop)
            try:
                if len(raw) > max_chars or len(raw.encode('utf-8')) > max_bytes:
                    _spam_record_strike(username, severity=1.0 * sensitivity, get_setting_func=get_setting_func)
                    return False, "This message is too large. Please shorten it.", []
            except Exception:
                if len(raw) > max_chars:
                    _spam_record_strike(username, severity=1.0 * sensitivity, get_setting_func=get_setting_func)
                    return False, "This message is too large. Please shorten it.", []

            # Compression-based payload check: catch large encoded/base64-style blobs
            try:
                if len(raw) > 200:
                    raw_bytes = raw.encode('utf-8', errors='ignore')
                    comp = zlib.compress(raw_bytes, level=3)
                    if len(comp) > max_bytes:
                        _spam_record_strike(username, severity=1.0 * sensitivity, get_setting_func=get_setting_func)
                        return False, "This message looks like a large encoded payload. Please send it as a file instead of pasting it.", []
            except Exception:
                pass

            # Enhanced content pattern analysis
            content_ok, content_msg = _spam_enhanced_content_analysis(raw)
            if not content_ok:
                _spam_record_strike(username, severity=1.0 * sensitivity, get_setting_func=get_setting_func)
                return False, content_msg, []

            # Duplicate / near-duplicate detection in the last 60 seconds
            recent_window = 60.0
            recent[:] = [(ts, txt) for (ts, txt) in recent if now - ts <= recent_window]
            norm = ' '.join(raw.split())  # collapse whitespace
            for ts, prev in recent:
                if not prev:
                    continue
                if norm == prev:
                    _spam_record_strike(username, severity=1.0 * sensitivity, get_setting_func=get_setting_func)
                    return False, "Duplicate message detected. Please avoid sending the same content repeatedly.", []
                try:
                    if len(norm) >= 40 and len(prev) >= 40:
                        ratio = difflib.SequenceMatcher(None, norm, prev).ratio()
                        if ratio > 0.97:
                            _spam_record_strike(username, severity=0.7 * sensitivity, get_setting_func=get_setting_func)
                            return False, "Very similar message detected. Please avoid minor variations of the same content.", []
                except Exception:
                    pass
            recent.append((now, norm))

        # Return success with any auto-split chunks
        return True, None, message_chunks
    except Exception:
        # Fail open on unexpected errors to avoid breaking chat
        return True, None, []

def _spam_process_split_queue(username: str, emit_func=None, room=None):
    """Process queued auto-split message chunks."""
    if not emit_func:
        return
    
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
        
        # Emit ready chunks
        for chunk in ready_chunks:
            try:
                emit_func("system_message", f"[Auto-split continued] {chunk}", room=room)
            except Exception:
                pass
                
    except Exception:
        pass

