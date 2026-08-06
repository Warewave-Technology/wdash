"""
Utility helper functions for WDash
"""

import re
from datetime import datetime
from typing import Optional


def format_timestamp(timestamp: str) -> str:
    """Format ISO timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, AttributeError):
        return timestamp


def escape_html(text: str) -> str:
    """Escape HTML characters in text"""
    if not isinstance(text, str):
        text = str(text)
    
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))


def validate_query(query: str) -> tuple[bool, Optional[str]]:
    """
    Validate Elasticsearch query syntax
    Returns (is_valid, error_message)
    """
    if not query or not query.strip():
        return False, "Query cannot be empty"
    
    # Basic validation - check for dangerous patterns
    dangerous_patterns = [
        r'script\s*:',  # Script queries
        r'delete\s+',   # Delete operations
        r'drop\s+',     # Drop operations
    ]
    
    query_lower = query.lower()
    for pattern in dangerous_patterns:
        if re.search(pattern, query_lower):
            return False, f"Query contains potentially dangerous pattern: {pattern}"
    
    # Check for balanced quotes
    single_quotes = query.count("'")
    double_quotes = query.count('"')
    
    if single_quotes % 2 != 0:
        return False, "Unbalanced single quotes in query"
    
    if double_quotes % 2 != 0:
        return False, "Unbalanced double quotes in query"
    
    return True, None


