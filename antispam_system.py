# Anti-Spam System - Comprehensive behavior-based spam detection
import hashlib
import time
import re
from collections import defaultdict, deque

# Global anti-spam tracking
user_spam_stats = defaultdict(lambda: {
    'violations': 0,
    'last_violation_time': 0,
    'cooldown_until': 0,
    'recent_messages': deque(maxlen=10),  # Store last 10 message texts
    'message_count_window': 0,
    'last_message_time': 0,
    'large_message_count': 0,
    'last_large_message_time': 0
})

def get_message_hash(text):
    """Generate hash for message content"""
    try:
        # Normalize text for hashing (remove extra whitespace, lowercase)
        normalized = re.sub(r'\s+', ' ', text.lower().strip())
        return hashlib.md5(normalized.encode('utf-8')).hexdigest()
    except Exception:
        return None

def check_content_patterns(text):
    """Detect suspicious content patterns"""
    try:
        # Check for excessive whitespace
        if len(re.findall(r'\s', text)) > len(text) * 0.7:  # More than 70% whitespace
            return "excessive_whitespace"
        
        # Check for HTML/CSS dumps
        html_tags = len(re.findall(r'<[^>]+>', text))
        if html_tags > 10:  # More than 10 HTML tags
            return "html_dump"
        
        # Check for excessive line breaks
        if text.count('\n') > 20:  # More than 20 line breaks
            return "excessive_breaks"
        
        # Check for repeated structures
        if len(re.findall(r'<div[^>]*>', text)) > 5:  # More than 5 div tags
            return "repeated_structures"
        
        return None
    except Exception:
        return None

def apply_progressive_sanction(username, violation_type):
    """Apply progressive sanctions based on violation history"""
    try:
        stats = user_spam_stats[username]
        stats['violations'] += 1
        stats['last_violation_time'] = time.time()
        
        if stats['violations'] == 1:
            # First violation: Warning
            return {
                'action': 'warning',
                'message': 'Warning: Please avoid spamming. This message has been blocked.',
                'allowed': False
            }
        elif stats['violations'] == 2:
            # Second violation: Slow mode (10 seconds)
            stats['cooldown_until'] = time.time() + 10
            return {
                'action': 'slowmode',
                'message': 'Slow mode applied: You must wait 10 seconds between messages.',
                'allowed': False
            }
        else:
            # Third+ violation: Temporary restriction (30 seconds)
            stats['cooldown_until'] = time.time() + 30
            return {
                'action': 'restrict',
                'message': 'Temporary restriction: You cannot send messages for 30 seconds.',
                'allowed': False
            }
    except Exception:
        return {'action': 'allow', 'allowed': True}

def check_anti_spam(username, text, attachment=None):
    """
    Comprehensive anti-spam check
    Returns: dict with 'allowed' (bool), 'message' (str), 'action' (str)
    """
    try:
        # Skip anti-spam for admins and superadmins
        try:
            if is_superadmin(username) or _is_adminish(username):
                return {'allowed': True, 'message': '', 'action': 'allow'}
        except Exception:
            pass
        
        stats = user_spam_stats[username]
        current_time = time.time()
        
        # Check if user is in cooldown
        if stats['cooldown_until'] > current_time:
            remaining = int(stats['cooldown_until'] - current_time)
            return {
                'allowed': False,
                'message': f'You are in cooldown. Please wait {remaining} seconds.',
                'action': 'cooldown'
            }
        
        # 1. Message Length Limit (500-1000 characters)
        if len(text) > 1000:
            # Auto-split large messages
            if len(text) > 2000:  # Very large messages get blocked
                return apply_progressive_sanction(username, 'oversized_message')
            else:
                # For moderately large messages, suggest splitting
                return {
                    'allowed': False,
                    'message': 'This message is too large. Please shorten it or split it into multiple messages.',
                    'action': 'length_limit'
                }
        
        # Track large messages for rate limiting
        if len(text) > 500:
            stats['large_message_count'] += 1
            stats['last_large_message_time'] = current_time
            
            # 5. Individual Slow Mode for large messages
            if stats['large_message_count'] > 3 and (current_time - stats['last_large_message_time']) < 30:
                return apply_progressive_sanction(username, 'large_message_spam')
        
        # 2. Duplicate & Near-Duplicate Detection
        message_hash = get_message_hash(text)
        if message_hash:
            # Check exact duplicates
            if message_hash in [get_message_hash(msg) for msg in stats['recent_messages']]:
                return apply_progressive_sanction(username, 'duplicate_message')
            
            # Check near-duplicates (simplified)
            if len(text) > 20 and len(stats['recent_messages']) > 0:
                # Simple check: if message is very similar in length and has similar words
                for recent_text in list(stats['recent_messages'])[-3:]:  # Check last 3 messages
                    if abs(len(text) - len(recent_text)) < 10:  # Similar length
                        common_words = set(text.lower().split()) & set(recent_text.lower().split())
                        if len(common_words) > len(text.split()) * 0.7:  # 70% word overlap
                            return apply_progressive_sanction(username, 'near_duplicate')
            
            # Store message text for comparison
            stats['recent_messages'].append(text.lower().strip())
        
        # 3. Payload Size Monitoring
        total_size = len(text.encode('utf-8'))
        if attachment:
            total_size += len(str(attachment))
        
        if total_size > 50000:  # 50KB limit
            return apply_progressive_sanction(username, 'payload_too_large')
        
        # 4. Rate Limiting (1 message per second for rapid posting)
        if stats['last_message_time'] > 0:
            time_diff = current_time - stats['last_message_time']
            if time_diff < 1.0:  # Less than 1 second
                stats['message_count_window'] += 1
                if stats['message_count_window'] > 3:  # More than 3 rapid messages
                    return apply_progressive_sanction(username, 'rate_limit')
            else:
                stats['message_count_window'] = 0  # Reset counter
        
        stats['last_message_time'] = current_time
        
        # 6. Content Pattern Analysis
        pattern_issue = check_content_patterns(text)
        if pattern_issue:
            return apply_progressive_sanction(username, f'content_pattern_{pattern_issue}')
        
        # Reset violation count if user has been good for 5 minutes
        if stats['violations'] > 0 and (current_time - stats['last_violation_time']) > 300:
            stats['violations'] = max(0, stats['violations'] - 1)
        
        return {'allowed': True, 'message': '', 'action': 'allow'}
        
    except Exception as e:
        # On any error, allow the message (fail-safe)
        return {'allowed': True, 'message': '', 'action': 'allow'}

