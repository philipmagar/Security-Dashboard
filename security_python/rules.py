from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Union, Dict, Any
from models import SecurityEvent
from event_processor import EventProcessor


def _extract_event_info(log: Union[SecurityEvent, Dict[str, Any]]):
    """Helper to extract normalized fields whether log is a SecurityEvent or dict."""
    if isinstance(log, SecurityEvent):
        return log.event_type, log.username, log.source_ip, log.timestamp, log.is_failure
    
    # Dict fallback
    event_type = (log.get('event_type') or log.get('event') or '').upper()
    username = (log.get('username') or log.get('user_email') or 'unknown').lower()
    ip = EventProcessor.sanitize_ip(log.get('source_ip') or log.get('ip'))
    timestamp = EventProcessor.parse_timestamp(log.get('timestamp'))
    
    success = log.get('success')
    result = log.get('result')
    if result:
        is_failure = result in ('FAILURE', 'BLOCKED', 'DENIED', 'ERROR')
    elif success is not None:
        is_failure = not success
    else:
        is_failure = False
        
    return event_type, username, ip, timestamp, is_failure


def detect_brute_force(logs: List[Union[SecurityEvent, Dict[str, Any]]], time_window_minutes=5, max_attempts=5):
    """
    Analyzes a list of logs/events to detect brute force attempts.
    A brute force is detected if there are more than `max_attempts` 
    failed logins from the same IP within `time_window_minutes`.
    """
    alerts_generated = []
    ip_attempts = defaultdict(list)
    
    for log in logs:
        event_type, username, ip, timestamp, is_failure = _extract_event_info(log)
        
        if event_type != 'LOGIN' or not is_failure:
            continue
            
        if not ip or ip == 'unknown':
            continue
            
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
                    'username': username,
                    'attempts': len(ip_attempts[ip]),
                    'time_window_minutes': time_window_minutes
                }
            }
            
            alerts_generated.append(alert)
            # Clear attempts to prevent duplicate consecutive alerts for the same burst
            ip_attempts[ip] = []
            
    return alerts_generated


def detect_rapid_registration(logs: List[Union[SecurityEvent, Dict[str, Any]]], time_window_minutes=10, max_registrations=3):
    """
    Detects if an IP is registering an abnormal number of accounts quickly.
    """
    alerts_generated = []
    ip_attempts = defaultdict(list)
    
    for log in logs:
        event_type, username, ip, timestamp, _ = _extract_event_info(log)
        
        if event_type != 'REGISTER':
            continue
            
        if not ip or ip == 'unknown':
            continue
            
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


def detect_password_spraying(logs: List[Union[SecurityEvent, Dict[str, Any]]], time_window_minutes=30, max_ips=3):
    """
    Detects password spraying / distributed brute force: 
    Multiple different IPs failing to login to the SAME account.
    """
    alerts_generated = []
    account_attempts = defaultdict(lambda: defaultdict(list))
    
    for log in logs:
        event_type, username, ip, timestamp, is_failure = _extract_event_info(log)
        
        if event_type != 'LOGIN' or not is_failure:
            continue
            
        if not username or username == 'unknown' or not ip or ip == 'unknown':
            continue
            
        account_attempts[username][ip].append(timestamp)
        window_start = timestamp - timedelta(minutes=time_window_minutes)
        
        # Clean up old attempts
        for k_ip in list(account_attempts[username].keys()):
            account_attempts[username][k_ip] = [t for t in account_attempts[username][k_ip] if t >= window_start]
            if not account_attempts[username][k_ip]:
                del account_attempts[username][k_ip]
        
        # Count unique IPs that have attempted to log into this user
        unique_ips = list(account_attempts[username].keys())
        if len(unique_ips) >= max_ips:
            alert = {
                'type': 'PASSWORD_SPRAYING',
                'severity': 'CRITICAL',
                'source': 'MULTIPLE_IPS',
                'message': f"Password spraying detected against account {username}. {len(unique_ips)} different IPs attempted access within {time_window_minutes} minutes.",
                'details': {
                    'username': username,
                    'user_email': username,
                    'unique_ips_count': len(unique_ips),
                    'ips': unique_ips,
                    'time_window_minutes': time_window_minutes
                }
            }
            alerts_generated.append(alert)
            # Clear to prevent duplicate consecutive alerts
            account_attempts[username].clear()
            
    return alerts_generated

