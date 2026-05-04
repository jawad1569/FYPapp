require('dotenv').config();
const express = require('express');
const mysql   = require('mysql2/promise');
const cors    = require('cors');

const authRoutes     = require('./routes/auth');
const mlRoutes       = require('./routes/ml');
const chatRoutes     = require('./routes/chat');
const alertRoutes    = require('./routes/alerts');
const chatsRoutes    = require('./routes/chats');
const sentinelRoutes = require('./routes/sentinel');
const { getDb }  = require('./models/User');

const app  = express();
const PORT = process.env.PORT || 5000;

/* ── Middleware ── */
app.use(cors());
app.use(express.json());

/* ── Routes ── */
app.use('/api/auth',     authRoutes);
app.use('/api/ml',       mlRoutes);
app.use('/api/chat',     chatRoutes);
app.use('/api/alerts',   alertRoutes);
app.use('/api/chats',    chatsRoutes);
app.use('/api/sentinel', sentinelRoutes);

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
        id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        full_name           VARCHAR(100)  NOT NULL,
        email               VARCHAR(255)  NOT NULL UNIQUE,
        password_hash       VARCHAR(255)  NOT NULL,
        organization        VARCHAR(255)  DEFAULT '',
        wazuh_ip            VARCHAR(100)  DEFAULT '',
        wazuh_user          VARCHAR(100)  DEFAULT '',
        wazuh_password      VARCHAR(512)  DEFAULT '',
        wazuh_api_user      VARCHAR(100)  DEFAULT '',
        wazuh_api_password  VARCHAR(512)  DEFAULT '',
        created_at          DATETIME      DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    // Add columns for existing installs that pre-date this schema
    for (const ddl of [
      `ALTER TABLE users ADD COLUMN wazuh_user         VARCHAR(100) DEFAULT ''`,
      `ALTER TABLE users ADD COLUMN wazuh_password     VARCHAR(512) DEFAULT ''`,
      `ALTER TABLE users ADD COLUMN wazuh_api_user     VARCHAR(100) DEFAULT ''`,
      `ALTER TABLE users ADD COLUMN wazuh_api_password VARCHAR(512) DEFAULT ''`,
      `ALTER TABLE users ADD COLUMN wazuh_indexer_ip   VARCHAR(100) DEFAULT ''`,
    ]) {
      await pool.execute(ddl).catch(() => {});
    }
    console.log('✅ users table ready');

    await pool.execute(`
      CREATE TABLE IF NOT EXISTS conversations (
        id         VARCHAR(50)   NOT NULL PRIMARY KEY,
        user_id    INT UNSIGNED  NOT NULL,
        title      VARCHAR(255)  DEFAULT 'New Chat',
        created_at DATETIME      DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.execute(`
      CREATE TABLE IF NOT EXISTS messages (
        id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        conversation_id VARCHAR(50)              NOT NULL,
        role            ENUM('user','assistant') NOT NULL,
        content         TEXT                     NOT NULL,
        tool_calls      JSON,
        sources         JSON,
        is_error        BOOLEAN  DEFAULT FALSE,
        timestamp       BIGINT,
        created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    console.log('✅ conversations + messages tables ready');

    app.listen(PORT, () => {
      console.log(`🚀 Backend running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('❌ MySQL startup error:', err.message);
    process.exit(1);
  }
}

startServer();
