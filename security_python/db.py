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
                    details TEXT
                );
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
                    acknowledged BOOLEAN DEFAULT FALSE
                );
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

def save_alert(alert_type, severity, source, message, details):
    """Save a generated alert into the database."""
    conn = get_connection()
    if not conn: return False
    
    try:
        alert_id = f"alert_py_{int(time.time()*1000)}_{uuid.uuid4().hex[:5]}"
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (id, type, severity, source, message, details, acknowledged)
                VALUES (%s, %s, %s, %s, %s, %s, False)
            """, (alert_id, alert_type, severity, source, message, json.dumps(details)))
            conn.commit()
            return True
    except Exception as e:
        print(f"Error saving alert: {e}")
        return False
    finally:
        conn.close()

# Initialize tables when module is imported
setup_tables()
