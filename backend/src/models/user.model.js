const bcrypt = require('bcrypt');

const users = [];

// Seed a default admin user so the dashboard works immediately on startup.
// Credentials: admin@siem.local / Admin@1234
(async () => {
  const hashed = await bcrypt.hash('Admin@1234', 10);
  users.push({
    id: '1',
    email: 'admin@siem.local',
    password: hashed,
    name: 'Admin',
    role: 'admin',
    createdAt: new Date().toISOString(),
  });
})();

module.exports = { users };
