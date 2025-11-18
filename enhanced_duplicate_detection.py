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

