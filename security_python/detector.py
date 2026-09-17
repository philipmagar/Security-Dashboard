import time
from datetime import datetime, timezone
from db import fetch_recent_logs, save_alert
from event_processor import EventProcessor
from rules import RuleEngine

def run_detection_engine(poll_interval=10):
    print("=" * 70)
    print("Starting Modular Rule-Based Python Detection Engine.")
    rule_engine = RuleEngine()
    active_rules = rule_engine.list_rules()
    print(f"Loaded {len(active_rules)} security rules:")
    for r in active_rules:
        print(f"  • [{r['rule_id']}] {r['name']} (Severity: {r['severity']}, Risk Score: {r['risk_score']})")
    print(f"Polling database every {poll_interval} seconds...")
    print("=" * 70)

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
                print(f"[{datetime.now(timezone.utc).isoformat()}] Normalized {len(new_events)} security events. Evaluating rules...")
                
                # Update last_processed_timestamp to the most recent event's timestamp
                valid_timestamps = [event.timestamp for event in new_events if event.timestamp]
                if valid_timestamps:
                    last_processed_timestamp = max(valid_timestamps)
                
                # Execute all registered modular detection rules
                alerts = rule_engine.evaluate_all(new_events)
                
                # Save generated alerts to database
                for alert in alerts:
                    print(
                        f"*** ALERT GENERATED: [{alert.severity}] [{alert.rule_id}] "
                        f"{alert.attack_type} (Risk: {alert.risk_score}) - {alert.message} ***"
                    )
                    success = save_alert(alert)
                    if success:
                        print(f"Alert {alert.rule_id} successfully saved to database.")
            
            time.sleep(poll_interval)
            
        except Exception as e:
            print(f"Error in detection engine loop: {e}")
            time.sleep(poll_interval)

if __name__ == "__main__":
    run_detection_engine()
