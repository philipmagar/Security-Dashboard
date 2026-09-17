import time
from datetime import datetime, timezone
from db import fetch_recent_logs, save_alert
from event_processor import EventProcessor
from rules import detect_brute_force, detect_rapid_registration, detect_password_spraying

def run_detection_engine(poll_interval=10):
    print(f"Starting Python Detection Engine with Standard Event-Processing Layer.")
    print(f"Polling database every {poll_interval} seconds...")
    last_processed_timestamp = None
    
    while True:
        try:
            # Fetch recent logs from database
            raw_logs = fetch_recent_logs(limit=200)
            
            if not raw_logs:
                time.sleep(poll_interval)
                continue
            
            # Normalize and validate raw logs through standard event-processing layer
            events = EventProcessor.process_raw_logs(raw_logs)
            
            # Filter out already processed events based on timestamp
            if last_processed_timestamp:
                new_events = [
                    event for event in events 
                    if event.timestamp and event.timestamp > last_processed_timestamp
                ]
            else:
                new_events = events
                
            if new_events:
                print(f"[{datetime.now(timezone.utc).isoformat()}] Normalized & Validated {len(new_events)} new security events...")
                
                # Update last_processed_timestamp to the most recent event's timestamp
                valid_timestamps = [event.timestamp for event in new_events if event.timestamp]
                if valid_timestamps:
                    last_processed_timestamp = max(valid_timestamps)
                
                # Apply detection rules over standardized event stream
                alerts = []
                
                # Rule 1: Brute Force Detection
                brute_force_alerts = detect_brute_force(new_events, time_window_minutes=5, max_attempts=5)
                alerts.extend(brute_force_alerts)
                
                # Rule 2: Rapid Registration Spike
                rapid_reg_alerts = detect_rapid_registration(new_events, time_window_minutes=10, max_registrations=3)
                alerts.extend(rapid_reg_alerts)
                
                # Rule 3: Password Spraying (Distributed Brute Force)
                password_spraying_alerts = detect_password_spraying(new_events, time_window_minutes=30, max_ips=3)
                alerts.extend(password_spraying_alerts)
                
                # Save generated alerts to database
                for alert in alerts:
                    print(f"*** ALERT GENERATED: [{alert['severity']}] {alert['type']} - {alert['message']} ***")
                    success = save_alert(
                        alert_type=alert['type'],
                        severity=alert['severity'],
                        source=alert['source'],
                        message=alert['message'],
                        details=alert['details']
                    )
                    if success:
                        print("Alert successfully saved to database.")
            
            time.sleep(poll_interval)
            
        except Exception as e:
            print(f"Error in detection engine loop: {e}")
            time.sleep(poll_interval)

if __name__ == "__main__":
    run_detection_engine()
