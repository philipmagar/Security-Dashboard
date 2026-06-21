const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5433/minisiem',
});

// Test the connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Error connecting to PostgreSQL:', err.message);
  } else {
    console.log('Connected to PostgreSQL successfully at', res.rows[0].now);
  }
});

// Setup tables if they don't exist
const setupDb = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
          id VARCHAR(100) PRIMARY KEY,
          email VARCHAR(150) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          name VARCHAR(150),
          role VARCHAR(50) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS logs (
          id SERIAL PRIMARY KEY,
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          event VARCHAR(50),
          user_email VARCHAR(100),
          success BOOLEAN,
          ip VARCHAR(50),
          details TEXT
      );
    `);

    await client.query(`
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
    `);
    console.log('Database tables ensured in Node.js.');
  } catch (error) {
    console.error('Error setting up DB tables:', error);
  } finally {
    client.release();
  }
};

setupDb();

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool
};
