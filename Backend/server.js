require('dotenv').config();
const express = require('express');
const mysql   = require('mysql2/promise');
const cors    = require('cors');

const authRoutes = require('./routes/auth');
const { getDb }  = require('./models/User');

const app  = express();
const PORT = process.env.PORT || 5000;

/* ── Middleware ── */
app.use(cors());
app.use(express.json());

/* ── Routes ── */
app.use('/api/auth', authRoutes);

/* ── Health check ── */
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/* ── Create MySQL pool & start server ── */
async function startServer() {
  try {
    const pool = mysql.createPool({
      host:            process.env.DB_HOST     || 'localhost',
      port:            process.env.DB_PORT     || 3306,
      user:            process.env.DB_USER,
      password:        process.env.DB_PASSWORD,
      database:        process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit:    10,
      queueLimit:         0,
    });

    // Attach pool to app so routes can use it
    app.locals.db = pool;
    getDb.setPool(pool);

    // Verify connection
    const conn = await pool.getConnection();
    await conn.ping();
    conn.release();
    console.log('✅ MySQL connected');

    // Create users table if it does not exist
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        full_name     VARCHAR(100)  NOT NULL,
        email         VARCHAR(255)  NOT NULL UNIQUE,
        password_hash VARCHAR(255)  NOT NULL,
        organization  VARCHAR(255)  DEFAULT '',
        wazuh_ip      VARCHAR(100)  DEFAULT '',
        created_at    DATETIME      DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    console.log('✅ users table ready');

    app.listen(PORT, () => {
      console.log(`🚀 Backend running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('❌ MySQL startup error:', err.message);
    process.exit(1);
  }
}

startServer();
