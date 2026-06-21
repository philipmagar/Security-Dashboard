const bcrypt = require('bcrypt');
const db = require('../utils/db');

// Seed a default admin user so the dashboard works immediately on startup.
// Credentials: admin@siem.local / Admin@1234
const seedAdmin = async () => {
  try {
    const res = await db.query('SELECT id FROM users WHERE email = $1', ['admin@siem.local']);
    if (res.rows.length === 0) {
      const hashed = await bcrypt.hash('Admin@1234', 10);
      await db.query(
        'INSERT INTO users (id, email, password, name, role) VALUES ($1, $2, $3, $4, $5)',
        ['1', 'admin@siem.local', hashed, 'Admin', 'admin']
      );
      console.log('Default admin seeded.');
    }
  } catch (err) {
    console.error('Error seeding admin:', err.message);
  }
};

setTimeout(seedAdmin, 2000); // Give the pool time to connect and tables to create

const getUserByEmail = async (email) => {
  const res = await db.query('SELECT * FROM users WHERE email = $1', [email]);
  return res.rows[0];
};

const createUser = async (user) => {
  const { id, email, password, name, role } = user;
  await db.query(
    'INSERT INTO users (id, email, password, name, role) VALUES ($1, $2, $3, $4, $5)',
    [id, email, password, name || '', role]
  );
  return user;
};

module.exports = { getUserByEmail, createUser };
