import time
from datetime import datetime
from db import fetch_recent_logs, save_alert
from rules import detect_brute_force

def run_detection_engine(poll_interval=10):
    print(f"Starting Python Detection Engine. Polling every {poll_interval} seconds...")
    last_processed_timestamp = None
    
    while True:
        try:
            # Fetch recent logs from database
            logs = fetch_recent_logs(limit=200)
            
            if not logs:
                time.sleep(poll_interval)
                continue
            
            # Filter out already processed logs based on timestamp
            if last_processed_timestamp:
                new_logs = [log for log in logs if log['timestamp'] and log['timestamp'] > last_processed_timestamp]
            else:
                new_logs = logs
                
            if new_logs:
                print(f"[{datetime.now().isoformat()}] Processing {len(new_logs)} new logs...")
                
                # Update last_processed_timestamp to the most recent log's timestamp
                valid_timestamps = [log['timestamp'] for log in new_logs if log['timestamp']]
                if valid_timestamps:
                    last_processed_timestamp = max(valid_timestamps)
                
                # Apply detection rules
                alerts = []
                
                # Rule 1: Brute Force Detection
                brute_force_alerts = detect_brute_force(new_logs, time_window_minutes=5, max_attempts=5)
                alerts.extend(brute_force_alerts)
                
                # Save generated alerts to database
                for alert in alerts:
                    print(f"*** ALERT GENERATED: {alert['type']} - {alert['message']} ***")
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
