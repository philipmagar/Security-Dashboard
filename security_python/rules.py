from collections import defaultdict
from datetime import datetime, timedelta

def detect_brute_force(logs, time_window_minutes=5, max_attempts=5):
    """
    Analyzes a list of logs to detect brute force attempts.
    A brute force is detected if there are more than `max_attempts` 
    failed logins from the same IP within `time_window_minutes`.
    """
    failed_logins = [
        log for log in logs 
        if log.get('event') == 'LOGIN' and log.get('success') is False
    ]
    
    alerts_generated = []
    ip_attempts = defaultdict(list)
    
    for log in failed_logins:
        ip = log.get('ip')
        if not ip or ip == 'unknown':
            continue
            
        timestamp = log.get('timestamp')
        if isinstance(timestamp, str):
            try:
                # Handle ISO format strings
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                timestamp = datetime.now()
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now()
                
        ip_attempts[ip].append(timestamp)
        
        # Remove attempts outside the time window
        window_start = timestamp - timedelta(minutes=time_window_minutes)
        ip_attempts[ip] = [t for t in ip_attempts[ip] if t >= window_start]
        
        # Check if attempts exceed threshold
        if len(ip_attempts[ip]) >= max_attempts:
            alert = {
                'type': 'BRUTE_FORCE_DETECTED',
                'severity': 'HIGH',
                'source': ip,
                'message': f"Brute force detected from IP {ip}. {len(ip_attempts[ip])} failed attempts within {time_window_minutes} minutes.",
                'details': {
                    'ip': ip,
                    'attempts': len(ip_attempts[ip]),
                    'time_window_minutes': time_window_minutes
                }
            }
            
            alerts_generated.append(alert)
            # Clear attempts to prevent duplicate consecutive alerts for the same burst
            ip_attempts[ip] = []
            
    return alerts_generated
