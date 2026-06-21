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

def detect_rapid_registration(logs, time_window_minutes=10, max_registrations=3):
    """
    Detects if an IP is registering an abnormal number of accounts quickly.
    """
    registrations = [log for log in logs if log.get('event') == 'REGISTER']
    
    alerts_generated = []
    ip_attempts = defaultdict(list)
    
    for log in registrations:
        ip = log.get('ip')
        if not ip or ip == 'unknown':
            continue
            
        timestamp = log.get('timestamp')
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                timestamp = datetime.now()
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now()
                
        ip_attempts[ip].append(timestamp)
        window_start = timestamp - timedelta(minutes=time_window_minutes)
        ip_attempts[ip] = [t for t in ip_attempts[ip] if t >= window_start]
        
        if len(ip_attempts[ip]) >= max_registrations:
            alert = {
                'type': 'SUSPICIOUS_ACTIVITY',
                'severity': 'MEDIUM',
                'source': ip,
                'message': f"Rapid registrations detected from IP {ip}. {len(ip_attempts[ip])} accounts created within {time_window_minutes} minutes.",
                'details': {
                    'ip': ip,
                    'registrations': len(ip_attempts[ip]),
                    'time_window_minutes': time_window_minutes
                }
            }
            alerts_generated.append(alert)
            ip_attempts[ip] = []
            
    return alerts_generated

def detect_password_spraying(logs, time_window_minutes=30, max_ips=3):
    """
    Detects password spraying / distributed brute force: 
    Multiple different IPs failing to login to the SAME account.
    """
    failed_logins = [
        log for log in logs 
        if log.get('event') == 'LOGIN' and log.get('success') is False
    ]
    
    alerts_generated = []
    account_attempts = defaultdict(lambda: defaultdict(list))
    
    for log in failed_logins:
        email = log.get('user_email')
        ip = log.get('ip')
        if not email or not ip or ip == 'unknown':
            continue
            
        timestamp = log.get('timestamp')
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                timestamp = datetime.now()
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now()
                
        account_attempts[email][ip].append(timestamp)
        window_start = timestamp - timedelta(minutes=time_window_minutes)
        
        # Clean up old attempts
        for k_ip in list(account_attempts[email].keys()):
            account_attempts[email][k_ip] = [t for t in account_attempts[email][k_ip] if t >= window_start]
            if not account_attempts[email][k_ip]:
                del account_attempts[email][k_ip]
        
        # Count unique IPs that have attempted to log into this email
        unique_ips = list(account_attempts[email].keys())
        if len(unique_ips) >= max_ips:
            alert = {
                'type': 'PASSWORD_SPRAYING',
                'severity': 'CRITICAL',
                'source': 'MULTIPLE_IPS',
                'message': f"Password spraying detected against account {email}. {len(unique_ips)} different IPs attempted access within {time_window_minutes} minutes.",
                'details': {
                    'user_email': email,
                    'unique_ips_count': len(unique_ips),
                    'ips': unique_ips,
                    'time_window_minutes': time_window_minutes
                }
            }
            alerts_generated.append(alert)
            # Clear to prevent duplicate consecutive alerts
            account_attempts[email].clear()
            
    return alerts_generated
