import psycopg2
from psycopg2.extras import RealDictCursor
import os
import json
import uuid
import time

# Connection string matching the one in docker-compose.yml / .env
DB_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/minisiem")

def get_connection():
    """Establish a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print(f"Error connecting to the database: {e}")
        return None

def setup_tables():
    """Create logs and alerts tables if they do not exist, for the python engine."""
    conn = get_connection()
    if not conn: return
    
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event VARCHAR(50),
                    user_email VARCHAR(100),
                    success BOOLEAN,
                    ip VARCHAR(50),
                    endpoint VARCHAR(255),
                    result VARCHAR(50),
                    details TEXT
                );
                ALTER TABLE logs ADD COLUMN IF NOT EXISTS endpoint VARCHAR(255);
                ALTER TABLE logs ADD COLUMN IF NOT EXISTS result VARCHAR(50);
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id VARCHAR(100) PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    type VARCHAR(50),
                    severity VARCHAR(20),
                    source VARCHAR(50),
                    message TEXT,
                    details TEXT,
                    rule_id VARCHAR(50),
                    attack_type VARCHAR(50),
                    risk_score INT,
                    recommended_response TEXT,
                    acknowledged BOOLEAN DEFAULT FALSE
                );
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_id VARCHAR(50);
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS attack_type VARCHAR(50);
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score INT;
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS recommended_response TEXT;
            """)
            conn.commit()
            print("Database tables ensured.")
    except Exception as e:
        print(f"Error setting up tables: {e}")
    finally:
        conn.close()

def fetch_recent_logs(limit=100):
    """Fetch the most recent logs from the database."""
    conn = get_connection()
    if not conn: return []
    
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT %s;", (limit,))
            return cur.fetchall()
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return []
    finally:
        conn.close()

def save_alert(alert_type, severity=None, source=None, message=None, details=None, rule_id=None, risk_score=None, attack_type=None, recommended_response=None):
    """Save a generated alert into the database."""
    conn = get_connection()
    if not conn: return False
    
    try:
        # Support passing a DetectionAlert object or dict as first parameter
        if hasattr(alert_type, 'rule_id'): # DetectionAlert instance
            rule_id = alert_type.rule_id
            attack_type = alert_type.attack_type
            risk_score = alert_type.risk_score
            severity = alert_type.severity
            source = alert_type.source
            message = alert_type.message
            details = alert_type.details
            recommended_response = getattr(alert_type, 'recommended_response', '')
            alert_type_val = alert_type.rule_id
        elif isinstance(alert_type, dict) and ('rule_id' in alert_type or 'type' in alert_type):
            rule_id = alert_type.get('rule_id', alert_type.get('type'))
            attack_type = alert_type.get('attack_type', alert_type.get('type'))
            risk_score = alert_type.get('risk_score', 50)
            severity = alert_type.get('severity', 'MEDIUM')
            source = alert_type.get('source', alert_type.get('source_ip', 'unknown'))
            message = alert_type.get('message', '')
            details = alert_type.get('details', alert_type.get('evidence', {}))
            recommended_response = alert_type.get('recommended_response', alert_type.get('response', ''))
            alert_type_val = alert_type.get('type', rule_id)
        else:
            alert_type_val = alert_type
            if rule_id is None and isinstance(details, dict):
                rule_id = details.get('rule_id')
                attack_type = details.get('attack_type')
                risk_score = details.get('risk_score')
                recommended_response = details.get('recommended_response')

        serialized_details = json.dumps(details) if isinstance(details, (dict, list)) else str(details or "")

        alert_id = f"alert_py_{int(time.time()*1000)}_{uuid.uuid4().hex[:5]}"
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (id, type, severity, source, message, details, rule_id, attack_type, risk_score, recommended_response, acknowledged)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, False)
            """, (alert_id, alert_type_val, severity, source, message, serialized_details, rule_id, attack_type, risk_score, recommended_response))
            conn.commit()
            return True
    except Exception as e:
        print(f"Error saving alert: {e}")
        return False
    finally:
        conn.close()

# Initialize tables when module is imported
setup_tables()
