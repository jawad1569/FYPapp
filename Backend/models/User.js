const bcrypt = require('bcryptjs');

/* ── Get the pool attached by server.js ── */
function getDb(req) {
  // When called from routes, req is the Express request object.
  // We also expose a setter so server.js can push the pool in.
  return getDb._pool;
}
getDb.setPool = (pool) => { getDb._pool = pool; };

/* ── Row mapper: MySQL snake_case → camelCase ── */
function mapRow(row, includePassword = false) {
  const user = {
    _id:          row.id,
    fullName:     row.full_name,
    email:        row.email,
    organization: row.organization || '',
    wazuhIp:      row.wazuh_ip    || '',
    createdAt:    row.created_at,
  };
  if (includePassword) user.passwordHash = row.password_hash;
  return user;
}

/* ── Find user by email ── */
async function findByEmail(email, includePassword = false) {
  const cols = includePassword
    ? 'id, full_name, email, password_hash, organization, wazuh_ip, created_at'
    : 'id, full_name, email, organization, wazuh_ip, created_at';

  const [rows] = await getDb._pool.execute(
    `SELECT ${cols} FROM users WHERE email = ?`,
    [email.toLowerCase()]
  );
  if (rows.length === 0) return null;
  return mapRow(rows[0], includePassword);
}

/* ── Find user by ID ── */
async function findById(id) {
  const [rows] = await getDb._pool.execute(
    `SELECT id, full_name, email, organization, wazuh_ip, created_at
     FROM users WHERE id = ?`,
    [id]
  );
  if (rows.length === 0) return null;
  return mapRow(rows[0]);
}

/* ── Create a new user ── */
async function createUser({ fullName, email, password, organization = '', wazuhIp = '' }) {
  const salt         = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const [result] = await getDb._pool.execute(
    `INSERT INTO users (full_name, email, password_hash, organization, wazuh_ip)
     VALUES (?, ?, ?, ?, ?)`,
    [fullName, email.toLowerCase(), passwordHash, organization, wazuhIp]
  );
  return await findById(result.insertId);
}

/* ── Compare plain password against stored hash ── */
async function comparePassword(plainPassword, passwordHash) {
  return bcrypt.compare(plainPassword, passwordHash);
}

module.exports = { findByEmail, findById, createUser, comparePassword, getDb };
